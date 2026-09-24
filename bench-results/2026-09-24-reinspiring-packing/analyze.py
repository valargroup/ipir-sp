#!/usr/bin/env python3
"""Verify matched fixtures/ciphertexts and summarize completed Intel runs."""
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / 'raw-final'
assert (RAW / 'complete').read_text().strip() == 'complete', 'final run incomplete'

def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]

def rss(path):
    text = path.with_suffix('.time').read_text()
    assert 'Exit status: 0' in text, path
    return int(re.search(r'Maximum resident set size \(kbytes\): (\d+)', text)[1]) * 1024

def distribution(values):
    return {'median': statistics.median(values), 'min': min(values), 'max': max(values), 'values': values}

packing = defaultdict(list)
fixtures = {}
outputs = {}
for path in sorted(RAW.glob('packing-*.jsonl')):
    variant, blocks, ell, threads, concurrency, repeat = re.fullmatch(
        r'packing-(baseline|final)-b(\d+)-e(\d+)-t(\d+)-c(\d+)-r(\d+)\.jsonl', path.name).groups()
    data = rows(path)
    setup = next(r for r in data if r['kind'] == 'batch_setup')
    samples = [r for r in data if r['kind'] == 'online']
    stages = [r for r in data if r['kind'] == 'setup']
    assert len(samples) == 30 and all(r['correct'] for r in samples), path
    assert len(stages) == int(blocks), path
    shape = (blocks, ell)
    digest = setup['fixture_sha256']
    assert fixtures.setdefault(shape, digest) == digest, f'fixture mismatch: {path}'
    for sample in samples:
        key = (*shape, sample['sample'])
        digest = sample['ciphertext_sha256']
        assert outputs.setdefault(key, digest) == digest, f'ciphertext mismatch: {path}'
    entry = {
        'file': path.name,
        'setup_s': setup['seconds'],
        'online_ms': statistics.median(r['ms'] for r in samples),
        'key_ms': statistics.median(r['key_ms'] for r in samples),
        'contribution_ms': statistics.median(r['contribution_ms'] for r in samples),
        'finish_ms': statistics.median(r['finish_ms'] for r in samples),
        'coefficient_bytes': sum(r['coefficient_bytes'] for r in stages),
        'peak_rss_bytes': rss(path),
    }
    packing[f'{variant}-b{blocks}-e{ell}-t{threads}-c{concurrency}'].append(entry)
required={}
for variant in ['baseline','final']:
    for ell in [2,3]:
        for blocks in [1,16]:
            required[f'{variant}-b{blocks}-e{ell}-t8-c{8 if blocks==16 else 1}']=3
            required[f'{variant}-b{blocks}-e{ell}-t1-c1']=1
    required[f'{variant}-b16-e2-t8-c1']=3
assert set(packing)==set(required), 'missing or unexpected benchmark group'
for name,count in required.items():
    assert len(packing[name])==count, f'incomplete group: {name}'
summary = {'packing': {}, 'e2e': {}, 'actual_inspiring': {}, 'exact_fixture_shapes': len(fixtures), 'exact_ciphertext_samples_per_variant': len(outputs)}
for name, runs in packing.items():
    summary['packing'][name] = {'runs': runs, **{field: distribution([r[field] for r in runs]) for field in runs[0] if field != 'file'}}

for variant in ['baseline', 'final']:
    runs = []
    for path in sorted(RAW.glob(f'e2e-{variant}-r*.jsonl')):
        data = rows(path)
        setup = data[0]
        samples = [r for r in data if r['kind'] == 'sample']
        assert len(samples) == 3 and all(r['correct'] for r in samples), path
        runs.append({'file': path.name, 'setup_s': setup['offline_s'], 'coefficient_bytes': setup['coeff_bytes'],
                     'peak_rss_bytes': rss(path), **{field: statistics.median(r[field] for r in samples) for field in ['packing_ms', 'matvec_ms', 'server_ms']}})
    assert len(runs) == 3
    summary['e2e'][variant] = {'runs': runs, **{field: distribution([r[field] for r in runs]) for field in runs[0] if field != 'file'}}
for repeat in [1, 2, 3]:
    before = rows(RAW / f'e2e-baseline-r{repeat}.jsonl')
    after = rows(RAW / f'e2e-final-r{repeat}.jsonl')
    for a, b in zip(before[1:], after[1:], strict=True):
        for field in ['phase_error', 'upload_bytes', 'download_bytes']:
            assert a[field] == b[field], (repeat, field)

for threads in [1, 8]:
    groups = defaultdict(list)
    for repeat in [1, 2, 3]:
        data = rows(RAW / f'compare-t{threads}-r{repeat}.jsonl')
        for name in {r['name'] for r in data if r['kind'] == 'sample'}:
            samples = [r['ms'] for r in data if r.get('name') == name]
            assert len(samples) == 30
            groups[name].append(statistics.median(samples))
    summary['actual_inspiring'][str(threads)] = {name: distribution(vals) for name, vals in groups.items()}
(ROOT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
