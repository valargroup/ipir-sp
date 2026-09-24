#!/usr/bin/env python3
"""Verify tiling trials and final eight-row full-wire/hot packing checks."""
import json
import statistics as st
from pathlib import Path
ROOT = Path(__file__).resolve().parent

def read(path):
    return [json.loads(s) for s in path.read_text().splitlines() if s.startswith('{')]

fixtures, hashes, trials = {}, {}, {}
for path in sorted((ROOT/'raw-experiments').glob('tiles-*.jsonl')):
    data = read(path)
    shape = (data[0]['blocks'], data[0]['ell'])
    assert fixtures.setdefault(shape, data[0]['fixture_sha256']) == data[0]['fixture_sha256']
    samples = [r for r in data if r['kind'] == 'online']
    assert len(samples) == 30 and all(r['correct'] for r in samples)
    for row in samples:
        key = (*shape, row['sample'])
        assert hashes.setdefault(key, row['ciphertext_sha256']) == row['ciphertext_sha256']
    trials[path.stem] = st.median(r['ms'] for r in samples)
assert len(trials) == 15
# Also compare the tiling cohort to the original final27 source and fixtures.
for path in (ROOT/'raw-final27').glob('packing-*.jsonl'):
    data = read(path); shape = (data[0]['blocks'], data[0]['ell'])
    if shape not in fixtures:
        continue
    assert fixtures[shape] == data[0]['fixture_sha256']
    for row in data:
        if row['kind'] == 'online':
            assert hashes[(*shape, row['sample'])] == row['ciphertext_sha256']
raw = ROOT/'raw-final8'
assert (raw/'complete').read_text().strip() == 'complete'
assert json.loads((raw/'source-verification.json').read_text())['all_blobs_match']
e2e = []
compare = {}
for rep in [1,2,3]:
    data = read(raw/f'e2e-r{rep}.jsonl')
    baseline = read(ROOT/'raw-final27'/f'e2e-baseline-r{rep}.jsonl')
    assert len(data) == len(baseline) == 4
    for a,b in zip(data[1:], baseline[1:]):
        assert a['correct'] and b['correct']
        for key in ['phase_error', 'upload_bytes', 'download_bytes']:
            assert a[key] == b[key], key
    e2e.append({'setup_s':data[0]['offline_s'], 'coefficient_bytes':data[0]['coeff_bytes'],
        **{key: st.median(r[key] for r in data[1:]) for key in ['packing_ms','matvec_ms','server_ms']}})
    data = read(raw/f'compare-r{rep}.jsonl')
    names = {r['name'] for r in data if r['kind']=='sample'}
    for name in names:
        samples = [r['ms'] for r in data if r['kind']=='sample' and r['name']==name]
        assert len(samples)==30
        compare.setdefault(name,[]).append(st.median(samples))
    for stem in [f'e2e-r{rep}',f'compare-r{rep}']:
        assert 'Exit status: 0' in (raw/(stem+'.time')).read_text()
result={'source':'6c1aabca59ca096a716db2015a78f51ca3efdaac', 'trials_ms':trials,
        'e2e_runs': e2e, 'e2e_medians':{k:st.median(r[k] for r in e2e) for k in e2e[0]},
        'compare_runs_ms':compare, 'compare_medians_ms':{k:st.median(v) for k,v in compare.items()},
        'exact_trial_files':len(trials),'exact_ciphertext_sample_sets':len(hashes)}
(ROOT/'summary-final8.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
