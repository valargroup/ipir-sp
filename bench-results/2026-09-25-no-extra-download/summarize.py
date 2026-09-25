"""Aggregate every retained comparison; no selection by timing outcome."""
import json,statistics
from pathlib import Path
root=Path(__file__).resolve().parent
result={}
for bits in (29,32):
    paths=[root/f'paired-{bits}.jsonl']+sorted(root.glob(f'quiet-{bits}-[123].jsonl'))
    records=[json.loads(line) for path in paths for line in path.read_text().splitlines()]
    item={'files':[p.name for p in paths]}
    for mode in (False,True):
        rows=[r for r in records if r['kind']=='sample' and r['two_mask']==mode]
        assert len(rows)==120 and all(r['correct'] for r in rows)
        item['two_mask' if mode else 'baseline']={'samples':len(rows),'median_ms':{k:statistics.median(r[k] for r in rows) for k in ('client_ms','server_ms','decode_ms','packing_ms')},'mean_server_ms':statistics.mean(r['server_ms'] for r in rows),'max_phase_error':max(r['phase_error'] for r in rows)}
    a,b=item['baseline'],item['two_mask']
    item['ratios']={'client_generation':b['median_ms']['client_ms']/a['median_ms']['client_ms'],'client_decode':b['median_ms']['decode_ms']/a['median_ms']['decode_ms'],'server_throughput':a['mean_server_ms']/b['mean_server_ms']}
    item['online_monitoring']=[json.loads(p.read_text()) for p in sorted(root.glob(f'quiet-{bits}-*-environment.json'))]
    item['performance_gate']='unverified: unrelated activity detected in every controlled-repeat attempt'
    result[bits]=item
(root/'aggregate.json').write_text(json.dumps(result,indent=2)+'\n')
for bits,item in result.items(): print(bits,{k:v for k,v in item.items() if k!='online_monitoring'})
