"""RLWE encryption under ``s_tilde`` (SPEC.md section 1).

The "ring version" of LWE: same sign convention, same plaintext encoding,
but ``a`` becomes a polynomial ``c_1 in R_q`` and the message becomes a
**polynomial** ``m_bar in (Z_p[X] / (X^d + 1))`` instead of a scalar.

Why this module exists in InspiRING:

* The output of ``pack`` (Stage 13) is an honest two-element RLWE
  ciphertext under ``s_tilde``. We need ``decrypt`` to verify that
  ``pack(LWE(m_0), ..., LWE(m_{d-1}))`` recovers ``Sum m_k * X^k``
  (Stage 13's headline test).
* Stage 7 (KS.Setup) builds key-switching matrices whose entries are
  RLWE encryptions of ``s_in * z^i`` under ``s_out``. Both ``encrypt``
  and the noise-extraction helpers here are reused there.
* Stages 12 and 14 read the noise polynomial out of intermediate RLWE
  ciphertexts to validate Theorem 2 empirically.

Sign convention -- per SPEC.md section 1, identical to LWE just lifted
to the ring::

    c_2 = -c_1 * s_tilde + e + Delta * m_bar  (mod q)

Where ``e in R_q`` is a noise polynomial with each coefficient sampled
from ``chi`` independently.

Two superficially similar polynomial constructions live in this codebase
and **must not be confused**:

* ``s_tilde = Sum s[i] * X^i``         (this module, **positive exponent**)
* ``a_tilde = Sum a[i] * X^{-i}``      (Stage 8's TRANSFORM, **negative exponent**)

The negative exponent on ``a_tilde`` is what makes ``(a_tilde * s_tilde)|_{X^0}
= <a, s>`` -- the constant coefficient of the ring product equals the LWE
inner product. ``s_tilde`` itself has no special structural role; it's
just the polynomial form of ``s``. ``test_rlwe.py``'s
``TestStructuralDistinction`` group pins this distinction down.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from inspiring_oracle.lwe import keygen as _lwe_keygen
from inspiring_oracle.lwe import sample_noise
from inspiring_oracle.params import RlweParams
from inspiring_oracle.ring import add, mul, neg


@dataclass(frozen=True)
class RlweCiphertext:
    """An RLWE ciphertext ``(c_1, c_2) in R_q x R_q``.

    Both ``c_1`` and ``c_2`` are length-``d`` lists of integers in ``[0, q)``.
    The relation ``c_2 = -c_1 * s_tilde + e + Delta * m_bar`` holds modulo
    ``q``, where ``e in R_q`` is the noise polynomial.
    """

    c1: list[int]
    c2: list[int]


# --------------------------------------------------------------------------
# Secret-key construction
# --------------------------------------------------------------------------


def s_tilde_from_s(s: list[int], params: RlweParams) -> list[int]:
    """Embed an LWE secret ``s in Z^d`` as an RLWE secret ``s_tilde in R_q``.

    Per SPEC.md section 1: ``s_tilde[i] = s[i] mod q``. The exponent on
    ``X`` is **positive** -- index ``i`` of the input maps to coefficient
    ``i`` of the polynomial, with no sign flip and no permutation.

    For ternary ``s in {-1, 0, 1}^d``, the output values are in
    ``{0, 1, q-1}`` (since ``-1 mod q = q-1``). This is the "canonical
    R_q form": all coefficients in ``[0, q)``.
    """
    if len(s) != params.d:
        raise ValueError(f"len(s) = {len(s)} != d = {params.d}")
    return [si % params.q for si in s]


def keygen(params: RlweParams, rng: random.Random) -> list[int]:
    """Generate a fresh RLWE secret. Equivalent to ``s_tilde_from_s(lwe.keygen(...))``.

    For Algorithm 1 we usually want to **pair** the LWE and RLWE secrets
    (``s_tilde[i] = s[i]``), so the typical idiom is::

        s = lwe.keygen(params, rng)
        s_tilde = rlwe.s_tilde_from_s(s, params)

    This convenience function is for tests that only need the RLWE side.
    """
    return s_tilde_from_s(_lwe_keygen(params, rng), params)


# --------------------------------------------------------------------------
# Noise sampling
# --------------------------------------------------------------------------


def sample_noise_poly(params: RlweParams, rng: random.Random) -> list[int]:
    """Sample a noise polynomial ``e in R_q`` with each coefficient drawn from chi.

    Returns a length-``d`` list of **signed** ints (centered at 0). Caller
    is responsible for modular reduction at the appropriate point. Reused
    by Stage 7's KS.Setup which also needs fresh per-row noise.
    """
    return [sample_noise(params, rng) for _ in range(params.d)]


# --------------------------------------------------------------------------
# Encrypt / Decrypt
# --------------------------------------------------------------------------


def _scale_message(m_bar: list[int], params: RlweParams) -> list[int]:
    """Compute ``Delta * m_bar mod q`` coefficient-wise; validate ``m_bar in [0, p)^d``."""
    if len(m_bar) != params.d:
        raise ValueError(f"len(m_bar) = {len(m_bar)} != d = {params.d}")
    if not all(0 <= x < params.p for x in m_bar):
        raise ValueError(
            f"every coefficient of m_bar must be in [0, p={params.p}); "
            f"got {m_bar}"
        )
    return [(params.delta * x) % params.q for x in m_bar]


def encrypt(
    s_tilde: list[int],
    m_bar: list[int],
    params: RlweParams,
    rng: random.Random,
) -> RlweCiphertext:
    """RLWE encryption of message polynomial ``m_bar in [0, p)^d``.

    Per SPEC.md section 1::

        c_1   <- uniform R_q
        e     <- chi^d   (sample_noise_poly)
        c_2   := -c_1 * s_tilde + e + Delta * m_bar   (mod q)
        ct    := (c_1, c_2)
    """
    d, q = params.d, params.q
    c1 = [rng.randrange(q) for _ in range(d)]
    e = sample_noise_poly(params, rng)
    delta_m = _scale_message(m_bar, params)

    c1_s = mul(c1, s_tilde, q)
    e_modq = [ei % q for ei in e]
    c2 = add(add(neg(c1_s, q), e_modq, q), delta_m, q)
    return RlweCiphertext(c1=c1, c2=c2)


def decrypt(
    s_tilde: list[int], ct: RlweCiphertext, params: RlweParams
) -> list[int]:
    """RLWE decryption: recover ``m_bar in [0, p)^d``.

    Computes ``raw = c_2 + c_1 * s_tilde mod q``, which equals
    ``Delta * m_bar + e`` modulo ``q`` (where ``e`` is the noise
    polynomial). Each coefficient of ``raw`` is rounded to the nearest
    multiple of ``Delta`` and reduced mod ``p``.

    Correctness condition (per SPEC.md section 7): every coefficient of
    ``e`` must satisfy ``|e_k| < Delta / 2``. Holds with overwhelming
    probability when ``params.correctness_ok()`` is True.
    """
    q, p, delta = params.q, params.p, params.delta
    raw = add(ct.c2, mul(ct.c1, s_tilde, q), q)
    return [((c + delta // 2) // delta) % p for c in raw]


def extract_noise(
    s_tilde: list[int],
    ct: RlweCiphertext,
    m_bar: list[int],
    params: RlweParams,
) -> list[int]:
    """Recover the noise polynomial ``e`` from a known-plaintext ciphertext.

    Each output coefficient is in centered representation ``(-q/2, q/2]``.
    By construction, equals the ``e`` sampled inside ``encrypt`` whenever
    every actual noise coefficient satisfies ``|e_k| < q / 2``.
    """
    q, delta = params.q, params.delta
    raw = add(ct.c2, mul(ct.c1, s_tilde, q), q)
    delta_m = _scale_message(m_bar, params)
    e_modq = [(r - dm) % q for r, dm in zip(raw, delta_m, strict=True)]
    return [c if c <= q // 2 else c - q for c in e_modq]
