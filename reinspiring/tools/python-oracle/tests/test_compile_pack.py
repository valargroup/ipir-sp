"""Unit tests for Compile and Pack oracles."""

from __future__ import annotations

import random

from reinspiring_oracle.compile import (
    compile_naive,
    matvec,
    negacyclic_matrix,
    signed_perm_apply,
)
from reinspiring_oracle.pack import inspiring_style_sum, pack, preprocess
from reinspiring_oracle.params import ORACLE_EVEN_TINY, ORACLE_TINY
from reinspiring_oracle.ring import collapse_exponents, mul, tau


def test_negacyclic_matches_schoolbook():
    rng = random.Random(0)
    params = ORACLE_TINY
    for _ in range(20):
        a = [rng.randrange(params.q) for _ in range(params.d)]
        b = [rng.randrange(params.q) for _ in range(params.d)]
        neg = negacyclic_matrix(a, params.q)
        via_mat = matvec(neg, b, params.q)
        via_mul = mul(a, b, params.q)
        assert via_mat == via_mul


def test_signed_perm_is_tau():
    params = ORACLE_TINY
    rng = random.Random(1)
    y = [rng.randrange(params.q) for _ in range(params.d)]
    for g in collapse_exponents(params.d):
        assert signed_perm_apply(y, g, params.q) == tau(y, g, params.q)


def test_compile_matches_sum_of_products():
    params = ORACLE_TINY
    rng = random.Random(2)
    d = params.d
    exponents = collapse_exponents(d)
    k = len(exponents)
    ts = [[rng.randrange(params.z) for _ in range(d)] for _ in range(k)]
    y = [rng.randrange(params.q) for _ in range(d)]
    m = compile_naive(ts, exponents, params.q)
    via_compile = matvec(m, y, params.q)
    via_sum = [0] * d
    for t, g in zip(ts, exponents, strict=True):
        prod = mul(t, tau(y, g, params.q), params.q)
        via_sum = [(a + b) % params.q for a, b in zip(via_sum, prod)]
    assert via_compile == via_sum


def _random_digits(params, rng):
    d, ell, z = params.d, params.ell, params.z
    t_lr = [
        [[rng.randrange(z) for _ in range(d)] for _ in range(ell)]
        for _ in range(d - 2)
    ]
    t_pp = [[rng.randrange(z) for _ in range(d)] for _ in range(ell)]
    return t_lr, t_pp


def test_pack_matches_inspiring_style_sum_odd_q():
    params = ORACLE_TINY
    rng = random.Random(3)
    t_lr, t_pp = _random_digits(params, rng)
    a_tilde = [rng.randrange(params.q) for _ in range(params.d)]
    pre = preprocess(params, a_tilde, t_lr, t_pp)
    b = [rng.randrange(params.q) for _ in range(params.d)]
    y = [[rng.randrange(params.q) for _ in range(params.d)] for _ in range(params.ell)]
    yp = [[rng.randrange(params.q) for _ in range(params.d)] for _ in range(params.ell)]
    c1, c2 = pack(pre, b, y, yp)
    assert c1 == a_tilde
    expected = inspiring_style_sum(params, b, y, yp, t_lr, t_pp)
    assert c2 == expected


def test_pack_even_q_compile_path():
    """Compile/Pack algebra works for power-of-two q (D.1 is separate noise)."""
    params = ORACLE_EVEN_TINY
    rng = random.Random(4)
    t_lr, t_pp = _random_digits(params, rng)
    a_tilde = [rng.randrange(params.q) for _ in range(params.d)]
    pre = preprocess(params, a_tilde, t_lr, t_pp)
    b = [rng.randrange(params.q) for _ in range(params.d)]
    y = [[rng.randrange(params.q) for _ in range(params.d)] for _ in range(params.ell)]
    yp = [[rng.randrange(params.q) for _ in range(params.d)] for _ in range(params.ell)]
    _, c2 = pack(pre, b, y, yp)
    expected = inspiring_style_sum(params, b, y, yp, t_lr, t_pp)
    assert c2 == expected
