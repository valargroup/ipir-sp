"""Independent integer/schoolbook D.1 + sequential key-switch oracle.

JSON on stdin contains explicit public masks, key masks/bodies and LWE bodies.
No Rust FFT, Compile, CRT, or native matrix implementation is reused.
"""
import json
import sys


def rotate(a, k):
    d = len(a)
    out = [0] * d
    for i, x in enumerate(a):
        out[(i + k) % d] += x * (-1 if ((i + k) // d) % 2 else 1)
    return out


def tau(a, g):
    out = [0] * len(a)
    for i, x in enumerate(a):
        e = i * g % (2 * len(a))
        out[e % len(a)] += x * (-1 if e >= len(a) else 1)
    return out


def mul(a, b, q):
    out = [0] * len(a)
    for j, y in enumerate(b):
        for i, x in enumerate(rotate(a, j)):
            out[i] += x * y
    return [x % q for x in out]


def run(v):
    d, q, bits, ell, dropped = (v[k] for k in ['d', 'q', 'bits', 'ell', 'dropped'])
    exps = [pow(5, i, 2*d) for i in range(d//2)]
    exps += [(-g) % (2*d) for g in exps]
    slots = []
    for g in exps:
        total = [0]*d
        for j, row in enumerate(v['masks']):
            embedded = [row[0]] + [-row[d-k] for k in range(1, d)]
            for i, x in enumerate(rotate(tau(embedded, g), j)):
                total[i] += x
        slots.append([(x//d) % q for x in total])
    body = v['b'][:]

    def switch(a, b, mask, key):
        z = 1 << bits
        digits = [[0]*d for _ in range(ell)]
        for i, x in enumerate(b):
            if dropped:
                x = (x + (1 << (dropped-1))) >> dropped
            for j in range(ell):
                digit = (x + z//2) % z - z//2
                digits[j][i] = digit
                x = (x-digit)//z
        for j in range(ell):
            da, db = mul(mask[j], digits[j], q), mul(key[j], digits[j], q)
            for i in range(d):
                a[i] = (a[i] + da[i]) % q
                body[i] = (body[i] + db[i]) % q
        return a

    for start in [0, d//2]:
        for i in range(d//2-1, 0, -1):
            g = exps[start+i-1]
            slots[start+i-1] = switch(slots[start+i-1], slots[start+i],
                                     [tau(w, g) for w in v['w']], [tau(y, g) for y in v['kg']])
    a = switch(slots[0], slots[d//2], v['v'], v['kh'])
    return dict(a=a, b=body)


if __name__ == '__main__':
    json.dump(run(json.load(sys.stdin)), sys.stdout)
