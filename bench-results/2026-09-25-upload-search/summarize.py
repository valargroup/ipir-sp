"""Summarize paired measurements without treating shared-host timings as proof."""
import json
import math
from pathlib import Path
from statistics import mean, median

root=Path(__file__).resolve().parent
result={}
for mode in (False,True):
    samples=[]
    for run in (1,2):
        samples += [r for r in map(json.loads,(root/f'paired-{run}.jsonl').read_text().splitlines()) if r.get('kind')=='sample' and r['two_mask']==mode]
    if len(samples)!=60: raise ValueError('expected 60 measurements per mode')
    result['two_mask' if mode else 'one_mask']={
        'samples':len(samples),
        'median_ms':{k:median(r[k] for r in samples) for k in ('client_ms','server_ms','decode_ms','packing_ms')},
        'mean_server_ms':mean(r['server_ms'] for r in samples),
        'p95_ms':{k:sorted(r[k] for r in samples)[math.ceil(.95*len(samples))-1] for k in ('client_ms','server_ms','decode_ms')},
        'upload_bytes':samples[0]['upload_bytes'],
        'response_bytes':samples[0]['download_bytes'],
        'max_phase_error':max(r['phase_error'] for r in samples),
    }
a,b=result['one_mask'],result['two_mask']
result['observed_ratios']={
    'client_generation':b['median_ms']['client_ms']/a['median_ms']['client_ms'],
    'client_decode':b['median_ms']['decode_ms']/a['median_ms']['decode_ms'],
    'server_throughput':a['mean_server_ms']/b['mean_server_ms'],
}
result['environment']=[json.loads((root/f'paired-{i}-environment.json').read_text()) for i in (1,2)]
result['performance_gate']='unverified: shared host, unrelated builds/tests overlapped; observed ratios are exploratory'
(root/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
