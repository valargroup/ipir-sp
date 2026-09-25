"""Counterfactual one-mask precision screen on a native-noise(-rounded)-v1 report.

Mirrors certify_native.evaluate's deterministic budget for the one-mask route
(D.1 + query rounding + response rounding, full-precision K_h), but substitutes
each exported public_mask_screen's weights. 54 = lossless (actual weights).
"""
import json, sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[2] / 'reinspiring/tools/security'))
from certify_native import sampler_bounds, certified_bits, validate_native_sampler

report = json.load(open(sys.argv[1]))
validate_native_sampler(report)
d, qb, pb = (int(report[k]) for k in ('d', 'q_bits', 'p_bits'))
cols = int(report['cols'])
mean, bounds = sampler_bounds(report['sampler_counts'])
support = max(abs(int(x)) for x, n in report['sampler_counts'] if int(n))
radius = 1 << (qb - pb - 1)

def score(pick):
    scores = []
    for block in report['blocks']:
        deterministic = support*d*d + int(block['query_l1'])*16 + (1 << 31)
        scores.append(certified_bits(pick(block), radius, deterministic, cols, mean, bounds))
    return None if any(s is None for s in scores) else min(scores)

rows = [(64, 36 + cols*8, score(lambda b: b['weights'])),
        (54, 36 + (cols*54+7)//8, score(lambda b: b['weights']))]
for bits in range(32, 23, -1):
    rows.append((bits, 36 + (cols*bits+7)//8,
                 score(lambda b, bits=bits: next(v['weights'] for v in b['public_mask_screens'] if v['bits'] == bits))))
print(f"{'mask bits':>9} | {'snapshot bytes':>14} | {'certified bits':>14} | >=128")
for bits, nbytes, s in rows:
    print(f"{bits:>9} | {nbytes:>14,} | {str(s):>14} | {'yes' if s is not None and s >= 128 else 'no'}")
