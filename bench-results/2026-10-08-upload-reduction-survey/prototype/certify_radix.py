"""Radix-sample certificate (research only). Run from reinspiring/tools/security of the
prototype worktree:  python3 certify_radix.py noise-radix-l1-m20.json

The noise export uses profile p = 2^12 with uniform 12-bit entries, an upper bound on merged
entries c = D0 + 256*D1 <= 3855. Decoding is at effective p = 2^4, so the radius is q/32.
The lower digit D0 lands at scale q/4096 when the upper digit is selected: a deterministic
offset <= 15*q/4096, charged without centering.
"""
import json, math, sys
import certify_native as c

r = json.load(open(sys.argv[1]))
d, qb = 2048, 54
bq, br = int(r['query_bits']), int(r['response_bits'])
mean, bounds = c.sampler_bounds(r['sampler_counts'])
support = max(abs(int(x)) for x, n in r['sampler_counts'] if int(n))
radius = 1 << (qb - 4 - 1)
garbage = 15 * (1 << (qb - 12))
for bits in (19, 20, 21):
    scores, mx = [], 0
    for b in r['blocks']:
        w = next(v['weights'] for v in b['public_mask_screens'] if v['bits'] == bits)
        det = support * d * d + int(b['query_l1']) * (1 << (qb - bq - 1)) + (1 << (qb - br - 1)) + garbage
        mx = max(mx, det)
        scores.append(c.certified_bits(w, radius, det, int(r['cols']), mean, bounds))
    print('mask bits', bits, 'certified bits', None if None in scores else min(scores),
          'max deterministic log2', round(math.log2(mx), 2))
