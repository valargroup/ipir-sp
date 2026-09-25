"""Conservative offline screen; NEVER a certificate for an executable profile.

Combine secret residue families using triangle inequalities, not independence.
Find minimum deterministic transport error for a fixed TOTAL bit allocation by
integer dynamic programming. A rejected screen is not an impossibility proof.
"""
import argparse
import itertools
import json
import math
from certify_native import sampler_bounds, certified_bits

Q = 1 << 54

def norm(values):
    values = list(values)
    return dict(l1=sum(abs(x) for x in values), l2_squared=sum(x*x for x in values), max=max(map(abs, values), default=0))

def parsed(n):
    return {k:int(v) for k,v in n.items()}

def independent(*ns):
    return dict(l1=sum(n['l1'] for n in ns), l2_squared=sum(n['l2_squared'] for n in ns), max=max(n['max'] for n in ns))

def correlated(a,b):
    cross = math.isqrt(a['l2_squared']*b['l2_squared'])
    if cross*cross < a['l2_squared']*b['l2_squared']: cross += 1
    l1,maximum = a['l1']+b['l1'], a['max']+b['max']
    return dict(l1=l1, l2_squared=min(a['l2_squared']+b['l2_squared']+2*cross,l1*maximum), max=maximum)

def digits(mask,widths):
    dropped = 54-sum(widths)
    out = [[] for _ in widths]
    residue = []
    for value in mask:
        x = (value+(1<<(dropped-1)))>>dropped if dropped else value
        reconstructed = 0
        shift = dropped
        for j,width in enumerate(widths):
            z = 1<<width
            t = (x+z//2)%z-z//2
            out[j].append(t)
            reconstructed += t<<shift
            shift += width
            x = (x-t)//z
        residue.append((reconstructed-value+Q//2)%Q-Q//2)
    return out,residue

def allocations(amplifications,limit):
    # For each exact number of transmitted bits, retain the lowest error.
    states = {0:(0,[])}
    for amp in amplifications:
        nxt = {}
        for used,(error,widths) in states.items():
            for bits in range(1,min(54,limit-used)+1):
                cost = error + amp*(0 if bits==54 else 1<<(53-bits))
                if used+bits not in nxt or cost<nxt[used+bits][0]:
                    nxt[used+bits] = (cost,widths+[bits])
        states = nxt
    return states

def evaluate(header,report):
    mean,bounds = sampler_bounds(header['sampler_counts'])
    support = max(abs(int(x)) for x,n in header['sampler_counts'] if int(n))
    kg = [parsed(n) for n in report['kg_limbs']]
    query = parsed(report['query'])
    secret = parsed(report['collapse_secret'])
    fixed = support*2048**2+query['l1']*16+(1<<31)
    # 172 bits total gives 44,032 bytes (20.37% saving).
    kg_dp = allocations([n['l1'] for n in kg],108)
    best = None
    candidates = [[b] for b in range(25,30)] + list(itertools.product(range(12,28),repeat=2))
    baseline = None
    for widths in candidates:
        ds,rs = digits(report['final_mask'],widths)
        hn = [norm(x) for x in ds]
        weights = independent(*kg,query,correlated(secret,norm(rs)),*hn)
        hd = allocations([n['l1'] for n in hn], min(108,54*len(widths)))
        choices = [(ge+he,gw+hw) for gb,(ge,gw) in kg_dp.items() for hb,(he,hw) in hd.items() if gb+hb<=172]
        error,allocation = min(choices,key=lambda x:x[0])
        score = certified_bits(weights,1<<37,fixed+error,header['cols'],mean,bounds)
        row = dict(kh_widths=widths,wire_bits=allocation,key_bytes=256*sum(allocation),compression_bound=str(error),certified_failure_bits=score)
        if best is None or (score if score is not None else -1)> (best['certified_failure_bits'] if best['certified_failure_bits'] is not None else -1): best=row
        if list(widths)==[19,19]: baseline=row
    return dict(kg_widths=report['kg_widths'],screened_final_gadgets=len(candidates),best_at_target=best,equal_final_at_target=baseline,meets_128=best['certified_failure_bits'] is not None and best['certified_failure_bits']>=128)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report')
    args=parser.parse_args()
    with open(args.report) as f:
        header=json.loads(next(f))
        if header['format']!='native-gadget-screen-v1': raise ValueError('wrong format')
        print(json.dumps(dict(format='native-upload-screen-v1',source=header,scope='single-block counterfactual screen, not full-response certificate')),flush=True)
        for line in f:
            print(json.dumps(evaluate(header,json.loads(line))),flush=True)
if __name__=='__main__': main()
