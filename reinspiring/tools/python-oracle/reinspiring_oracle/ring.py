"""Ring helpers: schoolbook mul in R_q and Galois automorphisms."""

from __future__ import annotations

G = 5


def h(d: int) -> int:
    return 2 * d - 1


def tau_g_pow(j: int, d: int) -> int:
    """5^j mod 2d."""
    return pow(G, j, 2 * d)


def mul(a: list[int], b: list[int], q: int) -> list[int]:
    d = len(a)
    if len(b) != d:
        raise ValueError("length mismatch")
    raw = [0] * (2 * d)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            raw[i + j] += ai * bj
    return [(raw[k] - raw[k + d]) % q for k in range(d)]


def add(a: list[int], b: list[int], q: int) -> list[int]:
    return [(x + y) % q for x, y in zip(a, b, strict=True)]


def tau(p: list[int], g: int, q: int) -> list[int]:
    """tau_g(p)(X) = p(X^g)."""
    d = len(p)
    two_d = 2 * d
    out = [0] * d
    for i, c in enumerate(p):
        if c == 0:
            continue
        e = (i * g) % two_d
        if e < d:
            out[e] = (out[e] + c) % q
        else:
            out[e - d] = (out[e - d] - c) % q
    return out


def collapse_exponents(d: int) -> list[int]:
    """Automorphism exponents matching inspiring's digits_ntt K_g schedule.

    Left half (reverse of tau_g^i for i in 0..d/2-2), then right half
    (reverse of tau_g^i o tau_h).
    """
    half = d // 2 - 1
    h_d = h(d)
    two_d = 2 * d
    left = [tau_g_pow(i, d) for i in range(half)]
    right = [(tau_g_pow(i, d) * h_d) % two_d for i in range(half)]
    return list(reversed(left)) + list(reversed(right))
