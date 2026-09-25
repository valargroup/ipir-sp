"""Summarize complete benchmark JSONL files; bootstrap describes these samples only."""
import collections
import json
import pathlib
import random
import statistics

ROOT = pathlib.Path(__file__).resolve().parent


def stats(values):
    ordered = sorted(values)
    rng = random.Random(2417)
    boots = sorted(statistics.median(rng.choices(values, k=len(values))) for _ in range(2000))
    return dict(n=len(values), median=statistics.median(values), mean=statistics.mean(values),
                sd=statistics.stdev(values) if len(values)>1 else 0,
                p95=ordered[min(len(ordered)-1, int(.95*len(ordered)))],
                median_ci95=[boots[50], boots[1949]])


def summarize():
    result = {}
    for path in sorted((ROOT/'raw').glob('*.jsonl')):
        if path.name == 'security-estimates.jsonl':
            continue
        records = [json.loads(line) for line in path.read_text().splitlines()]
        assert records, ('empty benchmark file', path)
        groups = collections.defaultdict(list)
        for record in records:
            if record['kind']=='sample':
                if 'server_ms' in record:
                    record['local_roundtrip_ms']=record['client_ms']+record['server_ms']+record['decode_ms']
                key = record.get('name','e2e') + '/t' + str(record.get('threads',8))
                groups[key].append(record)
        output = dict(setup=[x for x in records if x['kind']=='setup'], groups={})
        for name, rows in groups.items():
            assert len(rows)==30, (path, name, len(rows))
            assert sorted(x['sample'] for x in rows)==list(range(30))
            if 'correct' in rows[0]:
                assert all(x['correct'] for x in rows)
            fields = {k:stats([x[k] for x in rows]) for k in rows[0] if k=='ms' or k.endswith('_ms')}
            for key in ['upload_bytes','download_bytes']:
                if key in rows[0]:
                    assert len({r[key] for r in rows})==1
                    fields[key]=rows[0][key]
            if 'phase_error' in rows[0]:
                fields['max_phase_error']=max(r['phase_error'] for r in rows)
            output['groups'][name]=fields
        time_file=path.with_suffix('.time')
        if time_file.exists():
            for line in time_file.read_text().splitlines():
                if 'Maximum resident set size' in line:
                    output['max_rss_kib']=int(line.rsplit(':',1)[1])
                if 'Exit status:' in line:
                    assert int(line.rsplit(':',1)[1])==0, path
        result[path.name]=output
    (ROOT/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    result=summarize()
    for name, run in result.items():
        for group, values in run['groups'].items():
            timing=values.get('server_ms', values.get('ms'))
            print(name,group,round(timing['median'],3),timing['median_ci95'])
