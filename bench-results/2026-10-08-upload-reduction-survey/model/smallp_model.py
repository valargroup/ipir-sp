"""Small-plaintext-modulus reshaping model for native IPIR+SP (q = 2^54, d = 2048).

ESTIMATES. Noise constants are calibrated against repo evidence:
  * 2-limb K_g (base 2^19, 16 dropped bits): certified 2^-228 with 1.2e11 of random budget
    (bench-results/2026-09-25-no-extra-download/certificate-29.json) -> sigma_rand ~ 2^32.65.
    First-principles estimate for the same config is 2^32.25, so FUDGE = 2^0.4 is applied to
    every first-principles key/residue sigma below.
  * Deterministic budget mirrors certify_native.py: 65*d^2 + L1(query)*q/2^(bq+1) + q/2^(br+1)
    + published-mask rounding.
Server-time constants (8 workers):
  * packing: 12.25 ms / 16 blocks on Xeon Gold 6548N, scaled x1.35 to Xeon 8358 (ratio of the
    InspiRING packing stage on the two hosts after PR #15) -> ~1.03 ms/block.
  * scan: native VNNI scan 34 ms for 0.94e9 u16 entries x 7 query digits on 6548N; memory floor
    1.75 GiB read in 24.8 ms.  Small entries stored one per byte.
  * offline: 36.69 s for 16 blocks (2.29 s/block) on 6548N; retained 513.25 MiB / 16 blocks.
"""
import math

D, LOGQ = 2048, 54
Q = 2.0**LOGQ
N_NULL = 49_925_853
TAIL = math.sqrt(2 * (128 + 15) * math.log(2))
FUDGE = 2**0.4
SIG_S = 6.4
BS = 65                     # finite sampler support
BASE_UP, BASE_DOWN, BASE_TOTAL = 236_544, 81_920, 318_464


def sig_keys(limbs, base_bits):
    dropped = max(0, LOGQ - limbs * base_bits)
    key = math.sqrt(limbs) * D * (2**base_bits) * SIG_S / 2
    resid = 0 if dropped == 0 else math.sqrt(D * (D - 1)) * 2 ** (dropped - 1) * SIG_S / math.sqrt(3)
    return FUDGE * math.sqrt(key**2 + resid**2)


KEYCFG = {
    "2 limbs x 2^19 (shipped two-mask)": (2, 19, 27_648),
    "1 limb x 2^27 (approx, 27 dropped)": (1, 27, 13_824),
}


def rows_for(cols, L):
    return math.ceil(N_NULL / ((cols * L) // 256))


def ok(L, R, bq, br, ba, sig_k, randomized):
    p = 2**L
    radius = Q / (2 * p)
    w = Q / 2**bq
    det = BS * D * D + Q / 2 ** (br + 1)
    # two published masks, each rounded to ba bits: |(a~-a)*s| <= d*BS*w_a/2 deterministic per mask
    # two published masks rounded to ba bits: public weights on s, random over s (as the repo's screens)
    sig_m = FUDGE * math.sqrt(2 * D) * (Q / 2**ba) / math.sqrt(12) * SIG_S
    if randomized:   # client-side randomized rounding -> independent bounded terms (Hoeffding)
        sig = math.sqrt(sig_k**2 + sig_m**2 + R * (p**2 / 3) * w**2 / 4)
    else:
        sig = math.sqrt(sig_k**2 + sig_m**2)
        det += R * (p - 1) / 2 * w / 2
    return TAIL * sig + det < radius


def best_config(L, blocks, keyname, randomized, ba=None):
    limbs, base, kbytes = KEYCFG[keyname]
    sk = sig_keys(limbs, base)
    C = D * blocks
    R = rows_for(C, L)
    best = None
    for br in range(L + 1, L + 9):
        for bab in ([ba] if ba else range(10, 55)):
            for bq in range(8, 55):
                if ok(L, R, bq, br, bab, sk, randomized):
                    up = math.ceil(R * bq / 8) + kbytes
                    down = math.ceil(C * br / 8)
                    pub = 2 * C * bab // 8
                    cand = (up, down, pub, bq, br, bab)
                    if best is None or (up + down, pub) < (best[0] + best[1], best[2]):
                        best = cand
                    break
    return R, C, best


def server_ms(L, R, C, bq, blocks):
    entries = R * C
    digits = math.ceil(bq / 8)
    planes = 2 if L > 8 else 1
    compute = 34.0 * (entries * planes * digits) / (0.94e9 * 2 * 7)
    memory = 24.8 * (entries * planes) / (1.75 * 2**30)
    scan = max(compute, memory) * 1.35
    pack = 1.03 * blocks
    return scan, pack


if __name__ == "__main__":
    print(f"sigma 2-limb {math.log2(sig_keys(2,19)):.2f}  1-limb(27) {math.log2(sig_keys(1,27)):.2f}")
    for cap in (81_920, 102_400):
        print(f"\n### download cap {cap:,} B")
        print("keys | rnd | L | blocks | rows | bq | br | ba | upload | xUp | down | total | xTot | pub masks | scan ms | pack ms | offline s | retained GiB")
        for keyname in KEYCFG:
            limbs = KEYCFG[keyname][0]
            for randomized in (False, True):
                for L in (3, 4, 5, 6, 8, 16):
                    bestrow = None
                    for blocks in range(8, 200):
                        R, C, b = best_config(L, blocks, keyname, randomized)
                        if b is None or b[1] > cap:
                            continue
                        if bestrow is None or b[0] < bestrow[3][0]:
                            bestrow = (blocks, R, C, b)
                    if not bestrow:
                        continue
                    blocks, R, C, (up, down, pub, bq, br, ba) = bestrow
                    scan, pack = server_ms(L, R, C, bq, blocks)
                    print(f"{limbs}L | {'Y' if randomized else 'N'} | {L:2d} | {blocks:3d} | {R:6d} | {bq:2d} | {br:2d} | {ba:2d} | "
                          f"{up:7,} | {BASE_UP/up:4.2f} | {down:7,} | {up+down:7,} | {BASE_TOTAL/(up+down):4.2f} | "
                          f"{pub:9,} | {scan:5.0f} | {pack:5.0f} | {2.29*blocks*1.0:5.0f} | {513.25/16*blocks/1024:4.2f}")
