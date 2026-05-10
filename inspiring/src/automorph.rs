//! Galois automorphisms `τ_g`, `τ_h`, and iterated `τ_g^j`.
//!
//! See SPEC.md §2 (Galois group) and §3 (Lemma 1, the trace operator).
//!
//! - `τ_g(p)(X) = p(X^5)` generates the `Z_{d/2}` factor of `Gal(R)`.
//! - `τ_h(p)(X) = p(X^{2d-1})` generates the `Z_2` factor.
//!
//! Both are realised by [`spiral_rs::poly::automorph_alloc`] which is
//! generic in the exponent. We add helpers for the iterated `τ_g^j`
//! (we cache the precomputed exponents `5^j mod 2d`) and a
//! NTT-form wrapper that round-trips through coefficient form (Phase 11
//! will replace it with an in-place NTT-slot permutation).

use spiral_rs::poly::{
    automorph_alloc, from_ntt_alloc, to_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw,
};

/// The fixed generator of the `Z_{d/2}` factor of `Gal(R)`, per SPEC.md §2.
pub const G: u64 = 5;

/// `h = 2d − 1`, the generator of the `Z_2` factor of `Gal(R)`,
/// per SPEC.md §2.
#[must_use]
pub const fn h(d: usize) -> u64 {
    (2 * d as u64) - 1
}

/// `5^j mod 2d`, the exponent passed to `spiral_rs::poly::automorph` to
/// realise `τ_g^j`. SPEC.md §2.
///
#[must_use]
pub fn tau_g_pow(j: usize, d: usize) -> u64 {
    let modulus = 2 * d as u64;
    let mut acc = 1_u64;
    let mut base = G % modulus;
    let mut exp = j;

    while exp > 0 {
        if exp & 1 == 1 {
            acc = (u128::from(acc) * u128::from(base) % u128::from(modulus)) as u64;
        }
        base = (u128::from(base) * u128::from(base) % u128::from(modulus)) as u64;
        exp >>= 1;
    }

    acc
}

/// In-place application of `τ_t` to a coefficient-form polynomial matrix.
/// Trivial passthrough to [`spiral_rs::poly::automorph`]; declared here so
/// callers don't need to import spiral-rs directly.
///
pub fn tau_raw<'a>(a: &PolyMatrixRaw<'a>, t: u64) -> PolyMatrixRaw<'a> {
    automorph_alloc(a, t as usize)
}

/// `τ_t` for an NTT-form polynomial matrix. Phase 5 implements this as a
/// round-trip through coefficient form (see `docs/spiral-rs-mapping.md`
/// §3). Phase 11 hardening replaces the body with an in-place NTT-slot
/// permutation; the public signature is stable.
///
pub fn tau_ntt<'a>(a: &PolyMatrixNTT<'a>, t: u64) -> PolyMatrixNTT<'a> {
    to_ntt_alloc(&tau_raw(&from_ntt_alloc(a), t))
}

/// Lemma 1's trace `Tr(p) = Σ_{j=0}^{d/2-1} τ_g^j(p) + τ_h ∘ τ_g^j(p)`
/// (SPEC.md §3). Used by `tests/lemma1_trace.rs`.
///
pub fn trace<'a>(p: &PolyMatrixRaw<'a>) -> PolyMatrixRaw<'a> {
    let d = p.params.poly_len;
    let two_d = 2 * d as u64;
    let h_d = h(d);
    let mut out = PolyMatrixRaw::zero(p.params, p.rows, p.cols);

    for j in 0..(d / 2) {
        let gj = tau_g_pow(j, d);
        let left = tau_raw(p, gj);
        let right = tau_raw(p, (gj * h_d) % two_d);
        add_assign_raw_mod(&mut out, &left);
        add_assign_raw_mod(&mut out, &right);
    }

    out
}

fn add_assign_raw_mod(out: &mut PolyMatrixRaw<'_>, rhs: &PolyMatrixRaw<'_>) {
    debug_assert_eq!(out.rows, rhs.rows);
    debug_assert_eq!(out.cols, rhs.cols);

    let q = out.params.modulus;
    for row in 0..out.rows {
        for col in 0..out.cols {
            let out_poly = out.get_poly_mut(row, col);
            let rhs_poly = rhs.get_poly(row, col);
            for (out_coeff, rhs_coeff) in out_poly.iter_mut().zip(rhs_poly) {
                *out_coeff = (*out_coeff + *rhs_coeff) % q;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{GadgetParams, RlweParams};

    fn params() -> RlweParams {
        RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 3,
                ell: 5,
            },
        )
        .expect("valid params")
    }

    fn raw_from_coeffs<'a>(params: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixRaw<'a> {
        let mut poly = PolyMatrixRaw::zero(&params.spiral, 1, 1);
        poly.get_poly_mut(0, 0).copy_from_slice(coeffs);
        poly
    }

    fn coeffs(poly: &PolyMatrixRaw<'_>) -> Vec<u64> {
        poly.get_poly(0, 0).to_vec()
    }

    fn ntt_coeffs(poly: &PolyMatrixNTT<'_>) -> Vec<u64> {
        coeffs(&from_ntt_alloc(poly))
    }

    #[test]
    fn h_returns_negation_exponent() {
        assert_eq!(h(8), 15);
        assert_eq!(h(16), 31);
    }

    #[test]
    fn tau_g_pow_returns_powers_mod_2d() {
        assert_eq!(tau_g_pow(0, 8), 1);
        assert_eq!(tau_g_pow(1, 8), 5);
        assert_eq!(tau_g_pow(2, 8), 9);
        assert_eq!(tau_g_pow(3, 8), 13);
        assert_eq!(tau_g_pow(4, 8), 1);
    }

    #[test]
    fn tau_raw_applies_negacyclic_automorphism() {
        let params = params();
        let poly = raw_from_coeffs(&params, &[1, 2, 3, 4, 5, 6, 7, 8]);

        assert_eq!(
            coeffs(&tau_raw(&poly, h(params.d))),
            vec![1, 12281, 12282, 12283, 12284, 12285, 12286, 12287]
        );
    }

    #[test]
    fn tau_ntt_matches_tau_raw_after_round_trip() {
        let params = params();
        let poly = raw_from_coeffs(&params, &[9, 8, 7, 6, 5, 4, 3, 2]);
        let exponent = tau_g_pow(2, params.d);

        assert_eq!(
            ntt_coeffs(&tau_ntt(&to_ntt_alloc(&poly), exponent)),
            coeffs(&tau_raw(&poly, exponent))
        );
    }

    #[test]
    fn trace_keeps_only_d_times_constant_coefficient() {
        let params = params();
        let poly = raw_from_coeffs(&params, &[42, 1, 9, 2, 6, 5, 3, 8]);

        assert_eq!(
            coeffs(&trace(&poly)),
            vec![(params.d as u64 * 42) % params.q, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
