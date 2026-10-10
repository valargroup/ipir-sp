"""Summarize the p = 2^8 native evidence into aggregate.json and tables.md.

Reads certificates and noise reports from raw-mac/, timing/memory runs from
raw-xeon/ (and raw-mac/ e2e runs if present). Medians use all recorded samples;
nothing is filtered by timing.
"""
import json
import re
import statistics as st
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
PROD_UPLOAD, PROD_DOWNLOAD, PROD_TOTAL = 236_544, 81_920, 318_464
NATIVE_UPLOAD, NATIVE_DOWNLOAD, NATIVE_PUBLISHED = 203_300, 90_180, 237_604


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * (len(xs) - 1) + 0.5))]


def time_file(path):
    text = path.read_text() if path.exists() else ''
    rss = re.search(r'Maximum resident set size \(kbytes\): (\d+)', text)
    mac = re.search(r'(\d+)\s+maximum resident set size', text)
    status = re.search(r'Exit status: (\d+)', text)
    return {
        'max_rss_bytes': int(rss.group(1)) * 1024 if rss else (int(mac.group(1)) if mac else None),
        'exit_status': int(status.group(1)) if status else None,
    }


def e2e(path):
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    setup = next(r for r in rows if r['kind'] == 'setup')
    samples = [r for r in rows if r['kind'] == 'sample']
    assert all(r['correct'] for r in samples), path
    by_threads = {}
    for r in samples:
        by_threads.setdefault(r['threads'], []).append(r)
    stages = ('server_ms', 'matvec_ms', 'packing_ms', 'parse_ms', 'serialize_ms', 'client_ms',
              'generate_ms', 'prepare_ms', 'decode_ms', 'cold_decode_ms')
    timing = {}
    for threads, rs in sorted(by_threads.items()):
        timing[threads] = {'samples': len(rs)}
        for k in stages:
            xs = [r[k] for r in rs if r.get(k) is not None]
            if xs:
                timing[threads][k] = {'median': st.median(xs), 'p10': pct(xs, .1), 'p90': pct(xs, .9)}
    memory = {r['threads']: r for r in rows if r['kind'] == 'memory'}
    first = samples[0] if samples else {}
    return {
        'setup': setup, 'timing': timing, 'memory': memory,
        'upload_bytes': first.get('upload_bytes'), 'download_bytes': first.get('download_bytes'),
        'max_phase_error': max((r['phase_error'] for r in samples), default=None),
        'time': time_file(path.with_suffix('.time')),
    }


def dot(path):
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    setup = next(r for r in rows if r['kind'] == 'setup')
    out = {'setup': setup}
    for r in rows:
        if r['kind'] == 'sample':
            out.setdefault(f"{r['name']}-t{r['threads']}", []).append(r['ms'])
    return {k: (st.median(v) if isinstance(v, list) else v) for k, v in out.items()}


def certificates():
    out = {}
    for path in sorted((root / 'raw-mac').glob('certificate-*.json')):
        c = json.loads(path.read_text())['actual_profile']
        out[path.stem.removeprefix('certificate-')] = c
    return out


def regression():
    ours = root / 'raw-mac/noise-p16-regression-two-mask29-n49.json'
    recorded = root.parent / '2026-10-09-dithered-query/noise-two-mask29-n49.json'
    if not ours.exists():
        return None
    a, b = json.loads(ours.read_text()), json.loads(recorded.read_text())
    added = {'ell', 'gadget_bits', 'dropped_bits'}
    return {'identical_apart_from_added_keys': {k: v for k, v in a.items() if k not in added} == b,
            'added_keys': sorted(set(a) - set(b))}


def main():
    agg = {'certificates': certificates(), 'p16_regression': regression(), 'runs': {}, 'dot': {}}
    for d in ('raw-xeon', 'raw-mac'):
        for path in sorted((root / d).glob('*.jsonl')):
            if path.name.startswith('dot-'):
                agg['dot'][f'{d}/{path.stem}'] = dot(path)
            else:
                agg['runs'][f'{d}/{path.stem}'] = e2e(path)
    (root / 'aggregate.json').write_text(json.dumps(agg, indent=2, default=str) + '\n')
    lines = ['| Run | Upload | Download | Published | Server 8w ms (scan/pack) | Server 1w ms | '
             'Offline s | DB bytes | Packing bytes | H′ storage | Peak RSS |', '|' + '---|' * 11]
    for name, r in agg['runs'].items():
        s, t = r['setup'], r['timing']
        def med(threads, k):
            v = t.get(threads, {}).get(k)
            return f"{v['median']:.1f}" if v else '—'
        lines.append(
            f"| {name} | {r['upload_bytes']:,} | {r['download_bytes']:,} | {s['published_bytes']:,} | "
            f"{med(8, 'server_ms')} ({med(8, 'matvec_ms')}/{med(8, 'packing_ms')}) | {med(1, 'server_ms')} | "
            f"{s['offline_s']:.1f} | {s.get('database_bytes', 0):,} | {s['coeff_bytes']:,} | "
            f"{s.get('matrix_storage')} | {r['time']['max_rss_bytes'] or 0:,} |")
    lines += ['', '| Certificate | Request | Response | Published | Certified bits |', '|---|---|---|---|---|']
    for name, c in agg['certificates'].items():
        request = 36 + c['key_bytes'] + c['query_bytes']
        lines.append(f"| {name} | {request:,} | {c.get('response_bytes', '—')} | {c.get('published_bytes', '—')} | "
                     f"{c['certified_failure_bits']} |")
    (root / 'tables.md').write_text('\n'.join(lines) + '\n')
    print('\n'.join(lines))


if __name__ == '__main__':
    sys.exit(main())
