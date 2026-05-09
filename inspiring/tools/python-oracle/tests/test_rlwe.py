"""Stage 5: tests for RLWE encryption under ``s_tilde`` (SPEC.md section 1).

RLWE is structurally LWE in the polynomial ring ``R_q``. Most properties
mirror Stage 4's LWE tests, just upgraded from scalars to length-``d`` lists:

* Sign convention: same negative-inner-product (here ``-c_1 * s_tilde``).
* Plaintext encoding: ``Delta * m_bar`` per coefficient.
* Noise budget: per-coefficient ``|e_k| < Delta / 2``.

Test groups (eight in total):

1. ``TestSTildeFromS`` -- the structural conversion ``s -> s_tilde`` is
   plain coefficient embedding with positive exponent. **No sign flip,
   no permutation** -- this is the firewall against confusing it with
   Stage 8's ``a_tilde`` construction.

2. ``TestStructuralDistinction`` -- explicit pinning that ``s_tilde``
   does **not** behave like Stage 8's ``a_tilde``. Reads as a
   self-documenting "what NOT to do" reference for when Stage 8 lands.

3. ``TestKeygen`` -- the convenience wrapper produces ternary-derived
   secrets in canonical R_q form (``{0, 1, q-1}``).

4. ``TestSampleNoisePoly`` -- per-coefficient chi statistics.

5. ``TestEncryptDecryptRoundtrip`` -- the headline contract: encrypt
   then decrypt recovers ``m_bar`` for every valid input.

6. ``TestSignConventionKAT`` -- manually constructed ciphertexts with
   known noise; the firewall for the ``-c_1 * s_tilde`` formula.

7. ``TestNoiseBudget`` -- extracted noise statistics + sub-Gaussian tail
   + per-coefficient decryption budget.

8. ``TestDeterminism`` and ``TestInputValidation`` -- as in Stage 4.
"""

from __future__ import annotations

import random
import statistics

import pytest

from inspiring_oracle.lwe import keygen as lwe_keygen
from inspiring_oracle.params import ORACLE_SMALL, ORACLE_TINY
from inspiring_oracle.ring import mul
from inspiring_oracle.rlwe import (
    RlweCiphertext,
    decrypt,
    encrypt,
    extract_noise,
    keygen,
    sample_noise_poly,
    s_tilde_from_s,
)


@pytest.fixture
def rng() -> random.Random:
    return random.Random(0xCABBA6E)


def rand_message(rng: random.Random, params) -> list[int]:
    return [rng.randrange(params.p) for _ in range(params.d)]


# --------------------------------------------------------------------------
# 1. s_tilde_from_s: the structural conversion
# --------------------------------------------------------------------------


class TestSTildeFromS:
    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_length_equals_d(self, params, rng) -> None:
        s = lwe_keygen(params, rng)
        assert len(s_tilde_from_s(s, params)) == params.d

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_positive_values_passed_through(self, params) -> None:
        """Positive ``s[i]`` (within ``[0, q)``) is left as-is."""
        s = [3, 7, 0, 11, 0, 5, 1, 0] + [0] * (params.d - 8)
        s = s[: params.d]
        assert s_tilde_from_s(s, params) == [v % params.q for v in s]

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_negative_one_maps_to_q_minus_one(self, params) -> None:
        """``-1`` becomes ``q - 1`` (canonical R_q form)."""
        s = [-1] * params.d
        assert s_tilde_from_s(s, params) == [params.q - 1] * params.d

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_zero_stays_zero(self, params) -> None:
        s = [0] * params.d
        assert s_tilde_from_s(s, params) == [0] * params.d

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_ternary_secret_canonical_form(self, params, rng) -> None:
        """For ternary ``s in {-1, 0, 1}^d``, ``s_tilde[i] in {0, 1, q-1}``."""
        s = lwe_keygen(params, rng)
        s_tilde = s_tilde_from_s(s, params)
        for i, (si, ti) in enumerate(zip(s, s_tilde)):
            expected = si % params.q
            assert ti == expected, (
                f"s_tilde[{i}] = {ti}, expected {expected} from s[{i}] = {si}"
            )

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_wrong_length_raises(self, params) -> None:
        with pytest.raises(ValueError, match=r"len\(s\) ="):
            s_tilde_from_s([0] * (params.d + 1), params)


# --------------------------------------------------------------------------
# 2. Structural distinction from Stage 8's a_tilde
# --------------------------------------------------------------------------


class TestStructuralDistinction:
    """Pin down that ``s_tilde`` is **not** the same construction as Stage 8's
    ``a_tilde``. They look superficially similar (both embed a length-``d``
    integer vector into ``R_q``) but differ in:

    1. Sign: ``s_tilde`` has no sign flip; ``a_tilde`` flips signs.
    2. Exponent direction: ``s_tilde`` uses ``X^i``; ``a_tilde`` uses ``X^{-i}``.

    These tests document the difference so anyone refactoring later can
    grep for "structural distinction" and find the contract.
    """

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_e_i_basis_vector_passes_through_unchanged(self, params) -> None:
        """``s = e_i`` (the i-th unit vector) goes to a polynomial with a
        single ``1`` at position ``i``. Stage 8's ``a_tilde`` would put
        ``-1`` at position ``d - i`` instead (for ``i > 0``).
        """
        for i in range(params.d):
            s = [0] * params.d
            s[i] = 1
            result = s_tilde_from_s(s, params)
            expected = [0] * params.d
            expected[i] = 1
            assert result == expected, (
                f"unit vector e_{i} should map to position {i}, not flipped"
            )

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_no_negation_on_indices_above_zero(self, params) -> None:
        """``s_tilde[i] = +s[i]`` for **every** ``i``. Stage 8's ``a_tilde``
        does ``a_tilde[d-i] = -a[i]`` for ``i > 0`` -- a completely
        different mapping.
        """
        s = list(range(1, params.d + 1))
        s_tilde = s_tilde_from_s(s, params)
        for i in range(params.d):
            assert s_tilde[i] == (i + 1) % params.q, (
                f"s_tilde[{i}] should equal s[{i}] = {i+1}"
            )


# --------------------------------------------------------------------------
# 3. keygen
# --------------------------------------------------------------------------


class TestKeygen:
    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_length_equals_d(self, params, rng) -> None:
        assert len(keygen(params, rng)) == params.d

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_coefficients_in_canonical_ternary_image(
        self, params, rng
    ) -> None:
        """Every coefficient is in ``{0, 1, q-1}`` (ternary mod q)."""
        for _ in range(50):
            s_tilde = keygen(params, rng)
            assert all(
                v in (0, 1, params.q - 1) for v in s_tilde
            ), s_tilde


# --------------------------------------------------------------------------
# 4. sample_noise_poly
# --------------------------------------------------------------------------


class TestSampleNoisePoly:
    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_length_equals_d(self, params, rng) -> None:
        e = sample_noise_poly(params, rng)
        assert len(e) == params.d

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_coefficient_statistics_match_chi(self, params, rng) -> None:
        """Aggregate over many noise polynomials -- mean ~ 0, std ~ sigma."""
        n = 10_000 // params.d
        coefs: list[int] = []
        for _ in range(n):
            coefs.extend(sample_noise_poly(params, rng))
        mean = statistics.fmean(coefs)
        std = statistics.stdev(coefs)
        assert abs(mean) < 0.1 * params.sigma
        assert 0.9 * params.sigma < std < 1.1 * params.sigma


# --------------------------------------------------------------------------
# 5. Encrypt / Decrypt roundtrip
# --------------------------------------------------------------------------


class TestEncryptDecryptRoundtrip:
    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_random_messages_roundtrip(self, params, rng) -> None:
        """500 random ``(s_tilde, m_bar)`` pairs -- decrypt(encrypt) recovers m_bar."""
        for _ in range(500):
            s_tilde = keygen(params, rng)
            m_bar = rand_message(rng, params)
            ct = encrypt(s_tilde, m_bar, params, rng)
            assert decrypt(s_tilde, ct, params) == m_bar

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_zero_message_roundtrips(self, params, rng) -> None:
        s_tilde = keygen(params, rng)
        zero = [0] * params.d
        for _ in range(50):
            ct = encrypt(s_tilde, zero, params, rng)
            assert decrypt(s_tilde, ct, params) == zero

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_max_message_roundtrips(self, params, rng) -> None:
        s_tilde = keygen(params, rng)
        max_m = [params.p - 1] * params.d
        for _ in range(50):
            ct = encrypt(s_tilde, max_m, params, rng)
            assert decrypt(s_tilde, ct, params) == max_m

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_single_nonzero_coefficient_roundtrips(self, params, rng) -> None:
        """Each plaintext slot is independently decryptable -- a polynomial
        with a single nonzero coefficient at position ``k`` decrypts to
        exactly that, with zeros elsewhere.
        """
        s_tilde = keygen(params, rng)
        for k in range(params.d):
            m_bar = [0] * params.d
            m_bar[k] = params.p - 1
            ct = encrypt(s_tilde, m_bar, params, rng)
            assert decrypt(s_tilde, ct, params) == m_bar


# --------------------------------------------------------------------------
# 6. Sign convention KAT
# --------------------------------------------------------------------------


class TestSignConventionKAT:
    """Construct ciphertexts manually (no RNG, no noise) to pin down the
    encryption formula's sign convention. SPEC.md section 1 specifies::

        c_2 = -c_1 * s_tilde + e + Delta * m_bar  (mod q)

    The negative-product is the firewall this group enforces.
    """

    def test_manual_zero_noise_zero_message_at_d8(self) -> None:
        """``e = 0, m_bar = 0``: ``c_2 = -c_1 * s_tilde``, decrypts to 0^d."""
        params = ORACLE_TINY
        s_tilde = [1, params.q - 1, 0, 1, 0, params.q - 1, 1, 0]
        c1 = [11, 22, 33, 44, 55, 66, 77, 88]
        c1_s = mul(c1, s_tilde, params.q)
        c2 = [(-x) % params.q for x in c1_s]
        ct = RlweCiphertext(c1=c1, c2=c2)
        assert decrypt(s_tilde, ct, params) == [0] * params.d

    def test_manual_zero_noise_nonzero_message_at_d8(self) -> None:
        """``e = 0, m_bar = [1, 2, 3, ...]``: decrypts to that exact polynomial."""
        params = ORACLE_TINY
        s_tilde = [1, params.q - 1, 0, 1, 0, params.q - 1, 1, 0]
        c1 = [101, 202, 303, 404, 505, 606, 707, 808]
        m_bar = [0, 1, 2, 3, 0, 1, 2, 3]
        c1_s = mul(c1, s_tilde, params.q)
        delta_m = [(params.delta * mi) % params.q for mi in m_bar]
        c2 = [
            ((-c1s) + dm) % params.q
            for c1s, dm in zip(c1_s, delta_m, strict=True)
        ]
        ct = RlweCiphertext(c1=c1, c2=c2)
        assert decrypt(s_tilde, ct, params) == m_bar

    def test_manual_with_small_noise_decrypts_correctly(self) -> None:
        """``|e_k| << Delta/2`` per coefficient: noise doesn't push rounding off."""
        params = ORACLE_TINY
        s_tilde = [params.q - 1, 1, 1, 0, params.q - 1, 0, 1, params.q - 1]
        c1 = [1234, 5678, 9012, 3456, 7890, 1357, 2468, 9876]
        m_bar = [3, 0, 2, 1, 3, 2, 0, 1]
        e = [5, -7, 0, 11, -3, 8, -12, 1]
        c1_s = mul(c1, s_tilde, params.q)
        delta_m = [(params.delta * mi) % params.q for mi in m_bar]
        c2 = [
            ((-c1s) + ei + dm) % params.q
            for c1s, ei, dm in zip(c1_s, e, delta_m, strict=True)
        ]
        ct = RlweCiphertext(c1=c1, c2=c2)
        assert decrypt(s_tilde, ct, params) == m_bar

    def test_extract_noise_recovers_known_noise_polynomial(self) -> None:
        """Manually construct a ciphertext with known ``e``; ``extract_noise``
        returns exactly that polynomial (centered representation).
        """
        params = ORACLE_TINY
        s_tilde = [params.q - 1, 1, 0, 1, 0, params.q - 1, 1, 0]
        c1 = [11, 22, 33, 44, 55, 66, 77, 88]
        m_bar = [1, 2, 3, 0, 1, 2, 3, 0]
        e = [4, -6, 0, 9, -2, 7, -11, 1]
        c1_s = mul(c1, s_tilde, params.q)
        delta_m = [(params.delta * mi) % params.q for mi in m_bar]
        c2 = [
            ((-c1s) + ei + dm) % params.q
            for c1s, ei, dm in zip(c1_s, e, delta_m, strict=True)
        ]
        ct = RlweCiphertext(c1=c1, c2=c2)
        assert extract_noise(s_tilde, ct, m_bar, params) == e


# --------------------------------------------------------------------------
# 7. Noise budget (extracted noise statistics + sub-Gaussian tail)
# --------------------------------------------------------------------------


class TestNoiseBudget:
    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_extracted_noise_statistics(self, params, rng) -> None:
        """Aggregate noise coefficients across many encryptions: mean ~ 0,
        std ~ sigma. Verifies the encrypt/extract_noise round-trip pair.
        """
        s_tilde = keygen(params, rng)
        coefs: list[int] = []
        n_cts = 2000 // params.d
        for _ in range(n_cts):
            m_bar = rand_message(rng, params)
            ct = encrypt(s_tilde, m_bar, params, rng)
            coefs.extend(extract_noise(s_tilde, ct, m_bar, params))
        mean = statistics.fmean(coefs)
        std = statistics.stdev(coefs)
        assert abs(mean) < 0.15 * params.sigma
        assert 0.9 * params.sigma < std < 1.1 * params.sigma

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_per_coefficient_within_decryption_budget(
        self, params, rng
    ) -> None:
        """Every per-coefficient noise stays within ``Delta/2``."""
        s_tilde = keygen(params, rng)
        max_abs = 0
        for _ in range(200):
            m_bar = rand_message(rng, params)
            ct = encrypt(s_tilde, m_bar, params, rng)
            coefs = extract_noise(s_tilde, ct, m_bar, params)
            max_abs = max(max_abs, max(abs(c) for c in coefs))
        assert max_abs < params.delta // 2


# --------------------------------------------------------------------------
# 8. Determinism and input validation
# --------------------------------------------------------------------------


class TestDeterminism:
    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_same_seed_same_ciphertext(self, params) -> None:
        seed = 0xFEEDFACE
        s_tilde = keygen(params, random.Random(seed))
        m_bar = [1] * params.d

        rng1 = random.Random(seed + 1)
        rng2 = random.Random(seed + 1)
        ct1 = encrypt(s_tilde, m_bar, params, rng1)
        ct2 = encrypt(s_tilde, m_bar, params, rng2)
        assert ct1.c1 == ct2.c1
        assert ct1.c2 == ct2.c2


class TestInputValidation:
    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_message_wrong_length_raises(self, params, rng) -> None:
        s_tilde = keygen(params, rng)
        with pytest.raises(ValueError, match=r"len\(m_bar\) ="):
            encrypt(s_tilde, [0] * (params.d + 1), params, rng)

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_message_coefficient_out_of_range_raises(
        self, params, rng
    ) -> None:
        s_tilde = keygen(params, rng)
        bad = [0] * params.d
        bad[0] = params.p
        with pytest.raises(ValueError, match=r"in \[0, p="):
            encrypt(s_tilde, bad, params, rng)

    @pytest.mark.parametrize("params", [ORACLE_TINY, ORACLE_SMALL])
    def test_negative_message_coefficient_raises(self, params, rng) -> None:
        s_tilde = keygen(params, rng)
        bad = [0] * params.d
        bad[3] = -1
        with pytest.raises(ValueError, match=r"in \[0, p="):
            encrypt(s_tilde, bad, params, rng)
