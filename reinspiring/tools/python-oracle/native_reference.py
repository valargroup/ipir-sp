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
    kg_weights = [[0]*(ell*d) for _ in range(d)]
    secret_weights = [[0]*d for _ in range(d)]
    final_before = None

    def add_product(matrix, poly, exponent, offset=0):
        for c in range(d):
            basis = [int(i == c) for i in range(d)]
            product = mul(poly, tau(basis, exponent), q)
            for row, x in zip(matrix, product):
                row[offset+c] = (row[offset+c]+x) % q

    def residue(mask, digits, b, r):
        return [(sum(limb[i]*(1 << (r+j*b)) for j, limb in enumerate(digits))-x) % q
                for i,x in enumerate(mask)]

    def norms(xs):
        xs = [min(x % q, (-x) % q) for x in xs]
        return [sum(xs),sum(x*x for x in xs),max(xs,default=0)]

    def envelope(secret, digits):
        result = [0]*3
        for gw,sw in zip(kg_weights,secret):
            n = norms(gw+sw+[x for limb in digits for x in limb])
            result = [max(a,b) for a,b in zip(result,n)]
        return result

    def switch(a, b, mask, key, exponent, final=False):
        nonlocal final_before
        z = 1 << bits
        digits = [[0]*d for _ in range(ell)]
        for i, x in enumerate(b):
            if dropped:
                x = (x + (1 << (dropped-1))) >> dropped
            for j in range(ell):
                digit = (x + z//2) % z - z//2
                digits[j][i] = digit
                x = (x-digit)//z
        if final:
            final_before = (b[:], [row[:] for row in secret_weights], digits)
        else:
            for j, digit in enumerate(digits):
                add_product(kg_weights, digit, exponent, j*d)
        add_product(secret_weights, residue(b,digits,bits,dropped), (2*d-1) if final else (5*exponent)%(2*d))
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
                                     [tau(w, g) for w in v['w']], [tau(y, g) for y in v['kg']], g)
    if v.get('two_mask'):
        result = dict(a=slots[0], a_other=slots[d//2], b=body,
                      noise=envelope(secret_weights, []), one_limb=[], kh_l1=0)
        result['public_mask_screens'] = []
        for precision in range(27,min(32,q.bit_length()-1)+1):
            step = q >> precision
            combined = [row[:] for row in secret_weights]
            for mask,exponent in [(slots[0],1),(slots[d//2],2*d-1)]:
                delta = [(((x+step//2)//step*step)-x)%q for x in mask]
                add_product(combined,delta,exponent)
            result['public_mask_screens'].append(dict(bits=precision,noise=envelope(combined,[])))
        if v.get('include_weights'):
            result.update(secret_weights=secret_weights, kg_weights=kg_weights)
        return result
    a = switch(slots[0], slots[d//2], v['v'], v['kh'], 1, True)
    mask, before, final_digits = final_before
    baseline = envelope(secret_weights,final_digits)
    candidates = []
    for b in range(max(1,(q.bit_length()-1)//2-2),min(q.bit_length()-2,(q.bit_length()-1)//2+2)+1):
        r = q.bit_length()-1-b
        z = 1 << b
        digits = [[(((x+(1 << (r-1))) >> r)+z//2)%z-z//2 for x in mask]]
        secret = [row[:] for row in before]
        add_product(secret,residue(mask,digits,b,r),2*d-1)
        candidates.append(dict(bits=b,weights=envelope(secret,digits)))
    result = dict(a=a, b=body,noise=baseline,one_limb=candidates,
                  kh_l1=norms([x for limb in final_digits for x in limb])[0])
    result['public_mask_screens'] = []
    for precision in range(24, min(32, q.bit_length()-1)+1):
        step = q >> precision
        rounded = [((x+step//2)//step*step) % q for x in a]
        delta = [(y-x) % q for x,y in zip(a,rounded)]
        combined = [row[:] for row in secret_weights]
        add_product(combined, delta, 1)
        screen = dict(bits=precision, noise=envelope(combined,final_digits))
        if 'secret' in v:
            # Explicit ties and wraparound complement the actual packing mask.
            boundary = [0, step//2-1, step//2, step//2+1,
                        q-step//2-1, q-step//2, q-step//2+1, q-1]
            screen['phase_cases'] = []
            for mask in [a, [boundary[i % len(boundary)] for i in range(d)]]:
                rounded = [((x+step//2)//step*step) % q for x in mask]
                delta = [(y-x) % q for x,y in zip(mask,rounded)]
                screen['phase_cases'].append(dict(mask=mask, rounded=rounded,
                                                  delta=mul(delta,v['secret'],q)))
        result['public_mask_screens'].append(screen)
    if v.get('include_weights'):
        result.update(secret_weights=secret_weights,kg_weights=kg_weights,final_digits=final_digits)
    return result


if __name__ == '__main__':
    json.dump(run(json.load(sys.stdin)), sys.stdout)
