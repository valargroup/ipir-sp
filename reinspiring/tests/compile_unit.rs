#![allow(clippy::needless_range_loop)]
//! Compile unit tests (Neg, fused vs naive matrix form).

use reinspiring::compile::{
    collapse_kg_exponents, compile_fast, compile_naive, compile_naive_fused, negacyclic_matrix,
    schoolbook_negacyclic, tau_coeffs,
};
use reinspiring::matrix::PackingMatrix;

#[test]
fn negacyclic_matches_schoolbook() {
    let q = 12289u64;
    let d = 8usize;
    let t: Vec<u64> = (0..d).map(|i| (i as u64 * 3 + 1) % q).collect();
    let y: Vec<u64> = (0..d).map(|i| (i as u64 * 7 + 2) % q).collect();
    let neg = negacyclic_matrix(&t, q);
    let mut via_mat = vec![0u64; d];
    neg.matvec(&y, &mut via_mat).unwrap();
    let via_mul = schoolbook_negacyclic(&t, &y, q);
    assert_eq!(via_mat, via_mul);
}

#[test]
fn collapse_schedule_length() {
    assert_eq!(collapse_kg_exponents(8).len(), 6);
    assert_eq!(collapse_kg_exponents(16).len(), 14);
}

#[test]
fn naive_matrix_matches_fused() {
    let q = 12289u64;
    let d = 8usize;
    let exponents = collapse_kg_exponents(d);
    let ts: Vec<Vec<u64>> = (0..exponents.len())
        .map(|i| (0..d).map(|j| ((i * 11 + j * 3) as u64) % 8).collect())
        .collect();
    let a = compile_naive(&ts, &exponents, q).unwrap();
    let b = compile_naive_fused(&ts, &exponents, q).unwrap();
    assert_eq!(a.data, b.data);
}

#[test]
fn fast_matches_fused_on_collapse_schedule() {
    let q = 12289u64;
    let d = 8usize;
    let exponents = collapse_kg_exponents(d);
    let ts: Vec<Vec<u64>> = (0..exponents.len())
        .map(|i| (0..d).map(|j| ((i * 5 + j) as u64) % 8).collect())
        .collect();
    let a = compile_naive_fused(&ts, &exponents, q).unwrap();
    let b = compile_fast(&ts, &exponents, q).unwrap();
    assert_eq!(a.data, b.data);
}

#[test]
fn tau_identity() {
    let q = 12289u64;
    let p: Vec<u64> = (0..8).map(|i| i as u64 + 1).collect();
    assert_eq!(tau_coeffs(&p, 1, q), p);
}

#[test]
fn hstack_three_limbs() {
    let q = 17u64;
    let d = 4usize;
    let blocks: Vec<_> = (0..3)
        .map(|k| {
            let mut m = PackingMatrix::zero(d, d, q);
            *m.get_mut(0, 0) = k + 1;
            m
        })
        .collect();
    let h = PackingMatrix::hstack(&blocks).unwrap();
    assert_eq!(h.rows, d);
    assert_eq!(h.cols, 3 * d);
    assert_eq!(h.get(0, 0), 1);
    assert_eq!(h.get(0, d), 2);
    assert_eq!(h.get(0, 2 * d), 3);
}

#[test]
fn pow2_matvec_matches_generic_mod() {
    let q = 1u64 << 16;
    let rows = 8usize;
    let cols = 16usize;
    let mut m = PackingMatrix::zero(rows, cols, q);
    for r in 0..rows {
        for c in 0..cols {
            *m.get_mut(r, c) = ((r * 17 + c * 3) as u64) % q;
        }
    }
    let v: Vec<u64> = (0..cols).map(|i| ((i * 11 + 5) as u64) % q).collect();
    let mut out_pow2 = vec![0u64; rows];
    m.matvec(&v, &mut out_pow2).unwrap();

    let mut expected = vec![0u64; rows];
    for r in 0..rows {
        let mut acc = 0u128;
        for c in 0..cols {
            acc += u128::from(m.get(r, c)) * u128::from(v[c]);
        }
        expected[r] = (acc % u128::from(q)) as u64;
    }
    assert_eq!(out_pow2, expected);
}

#[test]
fn paper_params_q254_accepted() {
    use reinspiring::params::{GadgetParams, ReinspiringParams};
    let p = ReinspiringParams::new(
        2048,
        1 << 54,
        1 << 14,
        GadgetParams {
            bits_per: 19,
            ell: 2,
        },
        12289,
    )
    .expect("paper q=2^54");
    assert!(!p.is_odd_q());
    assert_eq!(p.q, 1 << 54);
}

#[test]
fn ring_fft_normalizes_rotations_when_polynomial_count_exceeds_degree() {
    use reinspiring::compile::ring_fft_eval_pow2;
    // This supported helper input has n=8, d=2. At its last butterfly rot=6
    // exceeds 2*d, so rotation must be reduced before unsigned subtraction.
    let input = vec![vec![1, 2]; 8];
    let mut expected = vec![vec![0, 0]; 8];
    expected[0] = vec![8, 0];
    assert_eq!(ring_fft_eval_pow2(&input, 16), expected);
}
