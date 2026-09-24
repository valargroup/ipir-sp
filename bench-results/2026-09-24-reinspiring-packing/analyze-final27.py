#!/usr/bin/env python3
"""Validate final 27/28-bit runs against every earlier exact fixture/output."""
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW = ROOT / 'raw-final27'
assert (RAW / 'complete').read_text().strip() == 'complete'
assert json.loads((RAW / 'source-verification.json').read_text())['all_blobs_match']

def rows(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.startswith('{')]

def dist(values):
    return {'median': statistics.median(values), 'min': min(values), 'max': max(values), 'values': values}

def peak(path):
    text = path.with_suffix('.time').read_text()
    assert 'Exit status: 0' in text, path
    return int(re.search(r'Maximum resident set size \(kbytes\): (\d+)', text)[1]) * 1024

fixtures, outputs = {}, {}
def verify(path):
    data = rows(path)
    setup = data[0]
    shape = (setup['blocks'], setup['ell'])
    digest = setup['fixture_sha256']
    assert fixtures.setdefault(shape, digest) == digest, path
    samples = [r for r in data if r['kind'] == 'online']
    assert len(samples) == 30 and all(r['correct'] for r in samples), path
    for sample in samples:
        key = (*shape, sample['sample'])
        digest = sample['ciphertext_sha256']
        assert outputs.setdefault(key, digest) == digest, (path, key)
    return data, samples

# Every final result must match prior-version ciphertexts, including across CPUs
# (worker counts), concurrency settings, and full repeated benchmark runs.
for path in sorted((ROOT / 'raw-final').glob('packing-*.jsonl')):
    verify(path)
packing = defaultdict(list)
def collect(path, name):
    data, samples = verify(path)
    stages = [r for r in data if r['kind'] == 'setup']
    assert len(stages) == data[0]['blocks']
    packing[name].append({'file': str(path.relative_to(ROOT)), 'setup_s': data[0]['seconds'],
        'online_ms': statistics.median(r['ms'] for r in samples),
        'key_ms': statistics.median(r['key_ms'] for r in samples),
        'contribution_ms': statistics.median(r['contribution_ms'] for r in samples),
        'finish_ms': statistics.median(r['finish_ms'] for r in samples),
        'coefficient_bytes': sum(r['coefficient_bytes'] for r in stages), 'peak_rss_bytes': peak(path)})
for path in sorted(RAW.glob('packing-*.jsonl')):
    name = re.fullmatch(r'packing-(.+)-r\d+\.jsonl', path.name)[1]
    collect(path, name)
for path in sorted((ROOT / 'raw-experiments').glob('packed27-trial-packed27-e3-r*.jsonl')):
    collect(path, 'final27-b16-e3-t8-c8')
required = {'baseline-b16-e2-t8-c8': 3, 'final27-b16-e2-t8-c8': 3,
            'final27-b16-e2-t8-c1': 3, 'final27-b16-e3-t8-c8': 3}
for ell in [2, 3]:
    required[f'final27-b1-e{ell}-t8-c1'] = 3
    for blocks in [1, 16]:
        required[f'final27-b{blocks}-e{ell}-t1-c1'] = 1
assert set(required) == set(packing)

def aggregate(runs):
    return {'runs': runs, **{field: dist([r[field] for r in runs]) for field in runs[0] if field != 'file'}}
summary = {'source': 'abb6a96804dbef6f5b14cb4e23f97e6645df5938', 'packing': {}, 'e2e': {}, 'actual_inspiring': {}}
for name, runs in packing.items():
    assert len(runs) == required[name], name
    summary['packing'][name] = aggregate(runs)
for variant in ['baseline', 'final27']:
    runs = []
    for path in sorted(RAW.glob(f'e2e-{variant}-r*.jsonl')):
        data = rows(path)
        setup = data[0]
        samples = data[1:]
        assert len(samples) == 3 and all(r['correct'] for r in samples), path
        runs.append({'file': path.name, 'setup_s': setup['offline_s'], 'coefficient_bytes': setup['coeff_bytes'],
            'peak_rss_bytes': peak(path), **{field: statistics.median(r[field] for r in samples)
            for field in ['packing_ms', 'matvec_ms', 'server_ms']}})
    assert len(runs) == 3
    summary['e2e'][variant] = aggregate(runs)
for repeat in [1, 2, 3]:
    before = rows(RAW / f'e2e-baseline-r{repeat}.jsonl')
    after = rows(RAW / f'e2e-final27-r{repeat}.jsonl')
    for a, b in zip(before[1:], after[1:], strict=True):
        for field in ['phase_error', 'upload_bytes', 'download_bytes']:
            assert a[field] == b[field], (repeat, field)
for threads in [1, 8]:
    groups, offline = defaultdict(list), defaultdict(list)
    for repeat in [1, 2, 3]:
        data = rows(RAW / f'compare-t{threads}-r{repeat}.jsonl')
        for name in {r['name'] for r in data if r['kind'] == 'sample'}:
            values = [r['ms'] for r in data if r.get('name') == name]
            assert len(values) == 30
            groups[name].append(statistics.median(values))
        for row in data:
            if row['kind'] == 'setup':
                if row['backend'] == 'odd':
                    offline['inspiring'].append(row['inspiring_s'])
                else:
                    offline[f"native_l{row['ell']}"] .append(row['offline_s'])
    summary['actual_inspiring'][str(threads)] = {name: dist(values) for name, values in groups.items()}
    summary['actual_inspiring'][str(threads)]['setup_s'] = {name: dist(values) for name, values in offline.items()}
summary['exact_fixture_shapes'] = len(fixtures)
summary['exact_ciphertext_sample_sets'] = len(outputs)
(ROOT / 'summary-final27.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
