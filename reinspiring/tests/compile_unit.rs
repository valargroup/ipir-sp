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
