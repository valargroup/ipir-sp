"""Compile (ReinsPIRe Algorithm 1 / Lemma 2)."""

from __future__ import annotations

from reinspiring_oracle.ring import tau


def negacyclic_matrix(t: list[int], q: int) -> list[list[int]]:
    """Neg(t): d x d Toeplitz matrix for negacyclic multiplication.

    Row r, column c is t[(r-c) mod d] with a sign flip when the index wraps
    (c > r), matching SPEC.md section 3.
    """
    d = len(t)
    m = [[0] * d for _ in range(d)]
    for r in range(d):
        for c in range(d):
            idx = r - c
            if idx >= 0:
                m[r][c] = t[idx] % q
            else:
                m[r][c] = (-t[idx + d]) % q
    return m


def signed_perm_apply(vec: list[int], g: int, q: int) -> list[int]:
    """Apply P_tau to a coefficient vector: vec(tau_g(y))."""
    return tau(vec, g, q)


def _matmul(a: list[list[int]], b: list[list[int]], q: int) -> list[list[int]]:
    n = len(a)
    m = len(b[0])
    k = len(b)
    out = [[0] * m for _ in range(n)]
    for i in range(n):
        for kk in range(k):
            aik = a[i][kk]
            if aik == 0:
                continue
            row_b = b[kk]
            out_row = out[i]
            for j in range(m):
                out_row[j] = (out_row[j] + aik * row_b[j]) % q
    return out


def _mat_add(a: list[list[int]], b: list[list[int]], q: int) -> list[list[int]]:
    return [
        [(x + y) % q for x, y in zip(ra, rb, strict=True)]
        for ra, rb in zip(a, b, strict=True)
    ]


def signed_perm_matrix(d: int, g: int, q: int) -> list[list[int]]:
    """Explicit P_tau matrix (for tests). Column c is e_c sent through tau."""
    p = [[0] * d for _ in range(d)]
    for c in range(d):
        basis = [0] * d
        basis[c] = 1
        imaged = tau(basis, g, q)
        for r in range(d):
            p[r][c] = imaged[r] % q
    return p


def compile_naive(ts: list[list[int]], exponents: list[int], q: int) -> list[list[int]]:
    """M = sum_i Neg(t_i) P_{tau_i} (SPEC.md section 4)."""
    if len(ts) != len(exponents):
        raise ValueError("ts and exponents length mismatch")
    d = len(ts[0])
    m = [[0] * d for _ in range(d)]
    for t, g in zip(ts, exponents, strict=True):
        if len(t) != d:
            raise ValueError("polynomial degree mismatch")
        neg = negacyclic_matrix(t, q)
        perm = signed_perm_matrix(d, g, q)
        m = _mat_add(m, _matmul(neg, perm, q), q)
    return m


def matvec(m: list[list[int]], v: list[int], q: int) -> list[int]:
    return [sum(m[r][c] * v[c] for c in range(len(v))) % q for r in range(len(m))]
