//! Compile: `M = Σ_i Neg(t_i) P_{τ_i}` (SPEC.md §3–§4, Lemma 9).

#![allow(clippy::needless_range_loop)]

use inspiring::automorph::{h, tau_g_pow};

use crate::error::ReinspiringError;
use crate::matrix::PackingMatrix;

/// Automorphism exponents for the K_g half of `digits_ntt`, matching
/// [`inspiring::preprocess`] collapse order (left reverse, then right reverse).
#[must_use]
pub fn collapse_kg_exponents(d: usize) -> Vec<u64> {
    let half = d / 2 - 1;
    let h_d = h(d);
    let two_d = 2 * d as u64;
    let left: Vec<u64> = (0..half).map(|i| tau_g_pow(i, d)).collect();
    let right: Vec<u64> = (0..half).map(|i| (tau_g_pow(i, d) * h_d) % two_d).collect();
    left.into_iter()
        .rev()
        .chain(right.into_iter().rev())
        .collect()
}

/// Apply `τ_g` to a coefficient vector (signed permutation).
#[must_use]
pub fn tau_coeffs(p: &[u64], g: u64, q: u64) -> Vec<u64> {
    let d = p.len();
    let two_d = 2 * d as u64;
    let mut out = vec![0u64; d];
    for (i, &c) in p.iter().enumerate() {
        let e = (i as u64 * g) % two_d;
        if e < d as u64 {
            let idx = e as usize;
            out[idx] = (out[idx] + c) % q;
        } else {
            let idx = (e - d as u64) as usize;
            out[idx] = (out[idx] + q - (c % q)) % q;
        }
    }
    out
}

/// Negacyclic Toeplitz matrix `Neg(t)` (SPEC.md §3).
#[must_use]
pub fn negacyclic_matrix(t: &[u64], q: u64) -> PackingMatrix {
    let d = t.len();
    let mut m = PackingMatrix::zero(d, d, q);
    for r in 0..d {
        for c in 0..d {
            let idx = r as isize - c as isize;
            let val = if idx >= 0 {
                t[idx as usize] % q
            } else {
                (q - (t[(idx + d as isize) as usize] % q)) % q
            };
            *m.get_mut(r, c) = val;
        }
    }
    m
}

/// Explicit signed permutation matrix for `τ_g`.
#[must_use]
pub fn signed_perm_matrix(d: usize, g: u64, q: u64) -> PackingMatrix {
    let mut p = PackingMatrix::zero(d, d, q);
    for c in 0..d {
        let mut basis = vec![0u64; d];
        basis[c] = 1;
        let imaged = tau_coeffs(&basis, g, q);
        for r in 0..d {
            *p.get_mut(r, c) = imaged[r] % q;
        }
    }
    p
}

fn matmul_square(a: &PackingMatrix, b: &PackingMatrix) -> PackingMatrix {
    debug_assert_eq!(a.cols, b.rows);
    debug_assert_eq!(a.rows, a.cols);
    let d = a.rows;
    let q = a.q;
    let mut out = PackingMatrix::zero(d, d, q);
    for i in 0..d {
        for k in 0..d {
            let aik = a.get(i, k);
            if aik == 0 {
                continue;
            }
            for j in 0..d {
                let prod = u128::from(aik) * u128::from(b.get(k, j));
                let sum = u128::from(out.get(i, j)) + prod;
                *out.get_mut(i, j) = (sum % u128::from(q)) as u64;
            }
        }
    }
    out
}

fn mat_add_into(dst: &mut PackingMatrix, src: &PackingMatrix) {
    let q = dst.q;
    for (d, s) in dst.data.iter_mut().zip(src.data.iter()) {
        *d = (*d + s) % q;
    }
}

/// Naive Compile: `M = Σ_i Neg(t_i) P_{τ_i}` in `O(k d²)` matmuls (`O(k d³)`).
pub fn compile_naive(
    ts: &[Vec<u64>],
    exponents: &[u64],
    q: u64,
) -> Result<PackingMatrix, ReinspiringError> {
    if ts.len() != exponents.len() {
        return Err(ReinspiringError::PreprocessMismatch(
            "compile_naive: ts/exponents length mismatch".into(),
        ));
    }
    if ts.is_empty() {
        return Err(ReinspiringError::InvalidParams(
            "compile_naive: empty input".into(),
        ));
    }
    let d = ts[0].len();
    let mut m = PackingMatrix::zero(d, d, q);
    for (t, &g) in ts.iter().zip(exponents.iter()) {
        if t.len() != d {
            return Err(ReinspiringError::PreprocessMismatch(
                "compile_naive: polynomial degree mismatch".into(),
            ));
        }
        let neg = negacyclic_matrix(t, q);
        let perm = signed_perm_matrix(d, g, q);
        let prod = matmul_square(&neg, &perm);
        mat_add_into(&mut m, &prod);
    }
    Ok(m)
}

/// Apply `Neg(t) · P_τ` into `m` without materialising `P_τ`.
///
/// Column `c` of the product is `Neg(t) · (P_τ e_c) = Neg(t) · vec(τ(e_c))`,
/// which equals the coefficient vector of `t · τ(X^c)`. Equivalently, for each
/// source basis index `c`, write column `c` as the image of polynomial `t`
/// under the inverse-style placement... We instead loop columns: column `c` of
/// `Neg(t)P` is `Neg(t)` times the `c`-th column of `P`, i.e. `τ` applied to
/// `e_c`, then left-multiplied by `Neg(t)` = coeffs of `t * τ(e_c)`.
fn accumulate_neg_perm(m: &mut PackingMatrix, t: &[u64], g: u64) {
    let d = t.len();
    let q = m.q;
    for c in 0..d {
        let mut basis = vec![0u64; d];
        basis[c] = 1;
        let imaged = tau_coeffs(&basis, g, q);
        // column c ← column c + Neg(t) · imaged  (= coeffs of t * tau(X^c))
        let col = schoolbook_negacyclic(t, &imaged, q);
        for r in 0..d {
            let sum = u128::from(m.get(r, c)) + u128::from(col[r]);
            *m.get_mut(r, c) = (sum % u128::from(q)) as u64;
        }
    }
}

/// Schoolbook negacyclic product in `R_q`.
#[must_use]
pub fn schoolbook_negacyclic(a: &[u64], b: &[u64], q: u64) -> Vec<u64> {
    let d = a.len();
    debug_assert_eq!(b.len(), d);
    let mut raw = vec![0_i128; 2 * d];
    for i in 0..d {
        let ai = a[i] % q;
        if ai == 0 {
            continue;
        }
        for j in 0..d {
            raw[i + j] += i128::from(ai) * i128::from(b[j] % q);
        }
    }
    let q_i = i128::from(q);
    (0..d)
        .map(|k| (raw[k] - raw[k + d]).rem_euclid(q_i) as u64)
        .collect()
}

/// Faster naive Compile: avoid building `P_τ` explicitly (`O(k d²)`).
pub fn compile_naive_fused(
    ts: &[Vec<u64>],
    exponents: &[u64],
    q: u64,
) -> Result<PackingMatrix, ReinspiringError> {
    if ts.len() != exponents.len() {
        return Err(ReinspiringError::PreprocessMismatch(
            "compile: ts/exponents length mismatch".into(),
        ));
    }
    if ts.is_empty() {
        return Err(ReinspiringError::InvalidParams(
            "compile: empty input".into(),
        ));
    }
    let d = ts[0].len();
    let mut m = PackingMatrix::zero(d, d, q);
    for (t, &g) in ts.iter().zip(exponents.iter()) {
        if t.len() != d {
            return Err(ReinspiringError::PreprocessMismatch(
                "compile: polynomial degree mismatch".into(),
            ));
        }
        accumulate_neg_perm(&mut m, t, g);
    }
    Ok(m)
}

/// Fast Compile via ring-FFT at powers of `X²` (Lemma 9 / Appendix C).
///
/// Computes the same matrix as [`compile_naive_fused`] in `O(d² log d)` ring
/// operations when `k = Θ(d)`. Each butterfly only rotates coefficients, so
/// `q` need not be NTT-friendly.
pub fn compile_fast(
    ts: &[Vec<u64>],
    exponents: &[u64],
    q: u64,
) -> Result<PackingMatrix, ReinspiringError> {
    if ts.is_empty() || ts.len() != exponents.len() || !(2..=(1 << 62)).contains(&q) {
        return Err(ReinspiringError::InvalidParams(
            "invalid Compile inputs".into(),
        ));
    }
    let d = ts[0].len();
    if !(2..=4096).contains(&d)
        || !d.is_power_of_two()
        || ts.iter().any(|t| t.len() != d || t.iter().any(|&x| x >= q))
        || exponents.iter().any(|&g| g % 2 == 0 || g >= 2 * d as u64)
    {
        return Err(ReinspiringError::InvalidParams(
            "invalid Compile degree, coefficient or automorphism".into(),
        ));
    }
    // tau_g(X^j) = X^j (X^(2j))^((g-1)/2). Missing exponents
    // have zero coefficients; repeated exponents add in the generating polynomial.
    let mut p_hat = vec![vec![0; d]; d];
    for (t, &g) in ts.iter().zip(exponents) {
        for (dst, &x) in p_hat[((g - 1) / 2) as usize].iter_mut().zip(t) {
            *dst = (*dst + x) % q;
        }
    }
    compile_fast_ring_fft(&p_hat, q)
}

/// Lemma 9 ring-FFT over a dense generating polynomial `P(Z) = Σ p̂_i Z^i`.
///
/// Twiddles are multiplies by powers of `X²` (coefficient rotations), so `q`
/// need not be NTT-friendly. Cost `O(d² log d)`.
pub fn compile_fast_ring_fft(
    p_hat: &[Vec<u64>],
    q: u64,
) -> Result<PackingMatrix, ReinspiringError> {
    let d = p_hat.len();
    if !(2..=4096).contains(&d) || !d.is_power_of_two() || !(2..=(1 << 62)).contains(&q) {
        return Err(ReinspiringError::InvalidParams(
            "compile_fast_ring_fft: d must be a power of two".into(),
        ));
    }
    for p in p_hat {
        if p.len() != d || p.iter().any(|&x| x >= q) {
            return Err(ReinspiringError::PreprocessMismatch(
                "compile_fast_ring_fft: noncanonical coefficient or degree mismatch".into(),
            ));
        }
    }
    let mut a: Vec<Vec<u64>> = p_hat.to_vec();
    ring_fft_inplace(&mut a, q);
    let mut m = PackingMatrix::zero(d, d, q);
    for j in 0..d {
        let shifted = shift_negacyclic(&a[j], j, q);
        for r in 0..d {
            *m.get_mut(r, j) = shifted[r];
        }
    }
    Ok(m)
}

fn shift_negacyclic(p: &[u64], by: usize, q: u64) -> Vec<u64> {
    let d = p.len();
    let mut out = vec![0u64; d];
    for i in 0..d {
        let dst = (i + by) % d;
        let wraps = i + by >= d;
        let mut c = p[i] % q;
        if wraps {
            c = (q - c) % q;
        }
        out[dst] = (out[dst] + c) % q;
    }
    out
}

fn ring_fft_inplace(a: &mut [Vec<u64>], q: u64) {
    let n = a.len();
    debug_assert!(n.is_power_of_two());
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let d = a[0].len();
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let step = n / len;
        for block in (0..n).step_by(len) {
            for k in 0..half {
                let rot = (2 * step * k) % (2 * d);
                let u = a[block + k].clone();
                let v = rotate_by_x_power(&a[block + k + half], rot, q);
                for t in 0..d {
                    let sum = (u[t] + v[t]) % q;
                    let diff = (u[t] + q - v[t]) % q;
                    a[block + k][t] = sum;
                    a[block + k + half][t] = diff;
                }
            }
        }
        len *= 2;
    }
}

fn rotate_by_x_power(p: &[u64], exp_mod_2d: usize, q: u64) -> Vec<u64> {
    let d = p.len();
    let e = exp_mod_2d % (2 * d);
    let (idx, sign_pos) = if e < d { (e, true) } else { (e - d, false) };
    let mut out = vec![0u64; d];
    for i in 0..d {
        let dst = (i + idx) % d;
        let wraps = i + idx >= d;
        let mut c = p[i] % q;
        if wraps {
            c = (q - c) % q;
        }
        if !sign_pos {
            c = (q - c) % q;
        }
        out[dst] = (out[dst] + c) % q;
    }
    out
}

/// Evaluate coefficient polys under the ring FFT at powers of `X²`.
#[must_use]
pub fn ring_fft_eval_pow2(polys: &[Vec<u64>], q: u64) -> Vec<Vec<u64>> {
    let mut a = polys.to_vec();
    if a.is_empty() {
        return a;
    }
    ring_fft_inplace(&mut a, q);
    a
}
