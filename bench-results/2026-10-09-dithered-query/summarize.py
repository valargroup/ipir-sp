"""Certify every retained noise report and aggregate every retained e2e sample."""
import json
import statistics
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[1] / 'reinspiring/tools/security'))
from certify_native import evaluate  # noqa: E402

certificates = {}
for path in sorted(root.glob('noise-*.json')):
    result = evaluate(json.loads(path.read_text()))
    out = root / path.name.replace('noise-', 'certificate-')
    out.write_text(json.dumps(result, indent=2) + '\n')
    certificates[path.stem] = {k: result['actual_profile'][k] for k in (
        'query_bits', 'query_rounding', 'query_bytes', 'certified_failure_bits', 'meets_128')}
    certificates[path.stem]['smallest_screened_query_bits_128'] = result['smallest_screened_query_bits_128']

runs = {}
for path in sorted(root.glob('e2e-*.jsonl')):
    records = [json.loads(line) for line in path.read_text().splitlines()]
    setup = next(r for r in records if r['kind'] == 'setup')
    rows = [r for r in records if r['kind'] == 'sample']
    assert rows and all(r['correct'] for r in rows)
    runs[path.stem] = {
        'samples': len(rows), 'threads': setup['threads'], 'query_bits': setup['query_bits'],
        'dithered_query': setup['dithered_query'], 'published_bytes': setup['published_bytes'],
        'upload_bytes': rows[0]['upload_bytes'], 'download_bytes': rows[0]['download_bytes'],
        'median_ms': {k: statistics.median(r[k] for r in rows)
                      for k in ('client_ms', 'server_ms', 'parse_ms', 'decode_ms')},
        'max_phase_error': max(r['phase_error'] for r in rows),
    }

# Interleaved n49/d43 rounds on the same host: compare only within a round.
paired = {}
for tag in ('n49', 'd43'):
    rounds = []
    for path in sorted(root.glob(f'paired-one-mask-{tag}-*.jsonl')):
        rows = [r for r in map(json.loads, path.read_text().splitlines()) if r['kind'] == 'sample']
        assert rows and all(r['correct'] for r in rows)
        rounds.append({k: statistics.median(r[k] for r in rows)
                       for k in ('client_ms', 'server_ms', 'matvec_ms', 'packing_ms', 'parse_ms')})
    paired[tag] = rounds
if paired['n49']:
    paired['server_ratio_per_round'] = [b['server_ms'] / a['server_ms'] for a, b in zip(paired['n49'], paired['d43'])]
    paired['client_ratio_per_round'] = [b['client_ms'] / a['client_ms'] for a, b in zip(paired['n49'], paired['d43'])]

(root / 'aggregate.json').write_text(json.dumps(
    {'certificates': certificates, 'e2e': runs, 'paired_one_mask': paired}, indent=2) + '\n')
for name, item in {**certificates, **runs, **paired}.items():
    print(name, item)
