"""ReinspiRING Preprocess + Pack (Algorithm 2) at tiny parameters."""

from __future__ import annotations

from dataclasses import dataclass

from reinspiring_oracle.compile import compile_naive, matvec
from reinspiring_oracle.params import ReinspiringParams
from reinspiring_oracle.ring import add, collapse_exponents, mul


@dataclass
class ReinspiringPreprocessed:
    params: ReinspiringParams
    a_tilde: list[int]
    """Final c1 coefficients (ã)."""
    h_prime: list[list[int]]
    """H' as d x (ell*d) row-major nested lists."""
    t_double_prime: list[list[int]]
    """ell polynomials t''_j."""


def preprocess(
    params: ReinspiringParams,
    a_tilde: list[int],
    t_left_right: list[list[list[int]]],
    t_double_prime: list[list[int]],
) -> ReinspiringPreprocessed:
    """Build H' from K_g digit limbs.

    ``t_left_right[step][limb]`` is the coefficient poly for collapse step
    ``step`` in inspiring's K_g schedule order (length ``d-2``), limb ``limb``.
    ``t_double_prime[limb]`` is the final K_h digit limb.
    """
    d = params.d
    ell = params.ell
    exponents = collapse_exponents(d)
    if len(t_left_right) != d - 2:
        raise ValueError(f"expected {d - 2} K_g digit steps, got {len(t_left_right)}")
    if len(exponents) != d - 2:
        raise ValueError("internal exponent schedule length mismatch")
    if len(t_double_prime) != ell:
        raise ValueError("t_double_prime limb count mismatch")

    h_blocks: list[list[list[int]]] = []
    for limb in range(ell):
        ts = [t_left_right[step][limb] for step in range(d - 2)]
        h_blocks.append(compile_naive(ts, exponents, params.q))

    # Horizontal stack: d x (ell*d)
    h_prime = [sum((block[r] for block in h_blocks), []) for r in range(d)]
    return ReinspiringPreprocessed(
        params=params,
        a_tilde=list(a_tilde),
        h_prime=h_prime,
        t_double_prime=[list(p) for p in t_double_prime],
    )


def pack(
    pre: ReinspiringPreprocessed,
    b_scalars: list[int],
    y_limbs: list[list[int]],
    y_prime_limbs: list[list[int]],
) -> tuple[list[int], list[int]]:
    """Return (c1, c2) coefficient polynomials."""
    params = pre.params
    d = params.d
    ell = params.ell
    q = params.q
    if len(b_scalars) != d:
        raise ValueError("b_scalars length")
    if len(y_limbs) != ell or len(y_prime_limbs) != ell:
        raise ValueError("limb count")

    y = []
    for limb in y_limbs:
        if len(limb) != d:
            raise ValueError("y limb degree")
        y.extend(v % q for v in limb)

    c2 = matvec(pre.h_prime, y, q)

    z = [0] * d
    for tpp, yp in zip(pre.t_double_prime, y_prime_limbs, strict=True):
        z = add(z, mul(tpp, yp, q), q)

    b_tilde = [b % q for b in b_scalars]
    c2 = add(add(c2, z, q), b_tilde, q)
    return list(pre.a_tilde), c2


def inspiring_style_sum(
    params: ReinspiringParams,
    b_scalars: list[int],
    y_limbs: list[list[int]],
    y_prime_limbs: list[list[int]],
    t_left_right: list[list[list[int]]],
    t_double_prime: list[list[int]],
) -> list[int]:
    """Direct Eq. 2 evaluation (oracle for Compile equivalence)."""
    from reinspiring_oracle.ring import tau

    d = params.d
    q = params.q
    exponents = collapse_exponents(d)
    c2 = [b % q for b in b_scalars]
    for step, g in enumerate(exponents):
        for limb, y in enumerate(y_limbs):
            t = t_left_right[step][limb]
            c2 = add(c2, mul(t, tau(y, g, q), q), q)
    for tpp, yp in zip(t_double_prime, y_prime_limbs, strict=True):
        c2 = add(c2, mul(tpp, yp, q), q)
    return c2
