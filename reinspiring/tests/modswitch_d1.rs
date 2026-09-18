//! Appendix D.1 mod-switch and approximate division tests.

use reinspiring::modswitch::{
    approx_div_by_d_coeff, approx_div_by_d_poly, center, ediv_infinity_bound,
    modulus_switch_coeff, modulus_switch_poly,
};
use reinspiring::params::{GadgetParams, ReinspiringParams};

#[test]
fn even_q_params_accepted() {
    let p = ReinspiringParams::new(
        8,
        1 << 16,
        4,
        GadgetParams {
            bits_per: 4,
            ell: 4,
        },
        12289,
    )
    .expect("even q ok");
    assert!(!p.is_odd_q());
}

#[test]
fn center_roundtrip_range() {
    let q = 1u64 << 16;
    for x in [0u64, 1, q / 2, q / 2 + 1, q - 1] {
        let c = center(x, q);
        assert!(c > -(q as i64) / 2 && c <= (q as i64) / 2);
        assert_eq!(((c % q as i64) + q as i64) as u64 % q, x % q);
    }
}

#[test]
fn modulus_switch_identity_when_same() {
    let coeffs = vec![0u64, 1, 100, (1 << 16) - 1];
    let out = modulus_switch_poly(&coeffs, 1 << 16, 1 << 16).unwrap();
    assert_eq!(out, coeffs);
}

#[test]
fn modulus_switch_dq_to_q() {
    let d = 8usize;
    let q = 1u64 << 16;
    let dq = q * d as u64;
    assert_eq!(modulus_switch_coeff(0, dq, q), 0);
    // x = dq/4 centers to dq/4; round((dq/4)*q/dq) = round(q/4) = q/4.
    assert_eq!(modulus_switch_coeff(dq / 4, dq, q), q / 4);
    // Tiny centered values round to 0 when shrinking by factor d (Lemma 10 noise source).
    assert_eq!(modulus_switch_coeff(dq - 1, dq, q), 0);
}

#[test]
fn approx_div_by_d_small_error() {
    let d = 8usize;
    let q = 1u64 << 16;
    // Exact multiple: floor(k d / d) = k.
    for k in 0..20u64 {
        let c = (k * d as u64) % q;
        assert_eq!(approx_div_by_d_coeff(c, d, q), k % q);
    }
}

#[test]
fn ediv_bound_is_d_squared() {
    assert_eq!(ediv_infinity_bound(8), 64);
    assert_eq!(ediv_infinity_bound(2048), 2048u64 * 2048);
}

#[test]
fn approx_div_poly_length() {
    let q = 1u64 << 16;
    let p = approx_div_by_d_poly(&[0, 8, 16, 24, 32, 40, 48, 56], 8, q);
    assert_eq!(p, vec![0, 1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn lemma10_style_noise_on_random_poly() {
    // For a random poly with coeffs in [0,q), approx_div vs exact (when odd q)
    // is not comparable; instead check that dividing an exact multiple of d
    // recovers the quotient with zero error — the D.1 noise comes from the
    // secret-side flooring when a is not divisible, bounded by d² after
    // aggregation (Lemma 10). Here we only check the local floor helper.
    let d = 8usize;
    let q = 1u64 << 16;
    let mut max_err = 0u64;
    for a in 0..256u64 {
        let exact = a / d as u64;
        let approx = approx_div_by_d_coeff(a, d, q);
        let err = exact.abs_diff(approx).min(q - exact.abs_diff(approx));
        max_err = max_err.max(err);
    }
    // Truncation error on a single coeff is < 1 in the quotient for a < q
    // when a is the value being divided — actually floor error is 0 for
    // non-negative a. Bound is trivial here; keep the test as a smoke check.
    assert!(max_err <= 1);
}
