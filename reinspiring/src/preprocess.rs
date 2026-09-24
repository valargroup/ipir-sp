//! `ReinspiRING.Preprocess` — build `H'` from InspiRING digit material.
//!
//! See SPEC.md §5–§6.

use inspiring::{QueryPackPreprocessed, RlweParams};
use rayon::prelude::*;
use spiral_rs::poly::{from_ntt_alloc, PolyMatrix, PolyMatrixNTT};

use crate::compile::{collapse_kg_exponents, compile_fast, compile_naive_fused};
use crate::error::ReinspiringError;
use crate::matrix::PackingMatrix;
use crate::params::ReinspiringParams;

/// Offline packing material: `(ã, H', [t''_j])`.
pub struct ReinspiringPreprocessed<'a> {
    /// ReinspiRING parameters (mirrors inspiring on the odd-`q` path).
    pub(crate) params: ReinspiringParams,
    /// Borrowed inspiring params (for spiral allocators / NTT of outputs).
    pub(crate) inspiring_params: &'a RlweParams,
    /// Final RLWE `c1` (= `ã`) in NTT form, shared with inspiring.
    pub(crate) a_tilde_ntt: PolyMatrixNTT<'a>,
    /// Compiled packing matrix `H' ∈ Z_q^{d × ℓd}`.
    pub(crate) h_prime: PackingMatrix,
    /// Coefficient-form leftover limbs `t''_j` (length `ℓ`).
    pub(crate) t_double_prime: Vec<Vec<u64>>,
    pub(crate) lift: crate::lift_ntt::LiftContext,
}
impl<'a> ReinspiringPreprocessed<'a> {
    /// Validated source profile.
    pub fn inspiring_params(&self) -> &'a RlweParams {
        self.inspiring_params
    }
    /// Compiled matrix, exposed read-only for diagnostics.
    pub fn matrix(&self) -> &PackingMatrix {
        &self.h_prime
    }
    /// Validated ReinspiRING parameter view.
    pub fn params(&self) -> &ReinspiringParams {
        &self.params
    }
}

/// Which Compile algorithm to use during preprocess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompileAlgo {
    /// `O(k d²)` fused naive (correct for any exponent set).
    Naive,
    /// Lemma 9 ring FFT (`O(d² log d)` per gadget limb).
    #[default]
    Fast,
}

/// Extract coefficient limbs from one `digits_ntt` step (`ell × 1` NTT matrix).
fn digit_limbs_coeff(digits: &PolyMatrixNTT<'_>, ell: usize, d: usize) -> Vec<Vec<u64>> {
    assert_eq!(digits.rows, ell);
    assert_eq!(digits.cols, 1);
    let raw = from_ntt_alloc(digits);
    let mut limbs = Vec::with_capacity(ell);
    for j in 0..ell {
        let poly = raw.get_poly(j, 0);
        limbs.push(poly[..d].to_vec());
    }
    limbs
}

/// Build ReinspiRING preprocess from an inspiring query-pack cache.
pub fn preprocess_from_inspiring<'a>(
    pre: &QueryPackPreprocessed<'a>,
    lift_q: u64,
    algo: CompileAlgo,
) -> Result<ReinspiringPreprocessed<'a>, ReinspiringError> {
    let ip = pre.params;
    let rp = ReinspiringParams::from_inspiring(ip, lift_q)?;
    if pre.digits_ntt.len() != ip.d - 1 {
        return Err(ReinspiringError::PreprocessMismatch(format!(
            "expected {} digit blocks, got {}",
            ip.d - 1,
            pre.digits_ntt.len()
        )));
    }

    let ell = ip.gadget.ell;
    let d = ip.d;
    let q = ip.q;
    let exponents = collapse_kg_exponents(d);

    // K_g steps: digits_ntt[0 .. d-2]; K_h: digits_ntt[d-2]
    let mut per_step_limbs: Vec<Vec<Vec<u64>>> = Vec::with_capacity(d - 2);
    for step in 0..(d - 2) {
        per_step_limbs.push(digit_limbs_coeff(&pre.digits_ntt[step], ell, d));
    }
    let t_double_prime = digit_limbs_coeff(&pre.digits_ntt[d - 2], ell, d);

    let blocks: Result<Vec<_>, _> = (0..ell)
        .into_par_iter()
        .map(|limb| {
            let ts: Vec<Vec<u64>> = per_step_limbs
                .iter()
                .map(|step| step[limb].clone())
                .collect();
            match algo {
                CompileAlgo::Naive => compile_naive_fused(&ts, &exponents, q),
                CompileAlgo::Fast => compile_fast(&ts, &exponents, q),
            }
        })
        .collect();
    let h_prime = PackingMatrix::hstack(&blocks?)?;

    Ok(ReinspiringPreprocessed {
        lift: crate::lift_ntt::LiftContext::new(d, q)?,
        params: rp,
        inspiring_params: ip,
        a_tilde_ntt: clone_ntt(&pre.collapse_a_final_ntt),
        h_prime,
        t_double_prime,
    })
}

/// Build from explicit coefficient digits (oracle / tests / even-`q` path).
pub fn preprocess_from_digits<'a>(
    inspiring_params: &'a RlweParams,
    a_tilde_ntt: PolyMatrixNTT<'a>,
    t_kg_steps: &[Vec<Vec<u64>>],
    t_double_prime: Vec<Vec<u64>>,
    lift_q: u64,
    algo: CompileAlgo,
) -> Result<ReinspiringPreprocessed<'a>, ReinspiringError> {
    let rp = ReinspiringParams::from_inspiring(inspiring_params, lift_q)?;
    let d = inspiring_params.d;
    let ell = inspiring_params.gadget.ell;
    let q = inspiring_params.q;
    if t_kg_steps.iter().any(|step| {
        step.len() != ell
            || step
                .iter()
                .any(|p| p.len() != d || p.iter().any(|&x| x >= q))
    }) || t_double_prime
        .iter()
        .any(|p| p.len() != d || p.iter().any(|&x| x >= q))
        || a_tilde_ntt.rows != 1
        || a_tilde_ntt.cols != 1
        || a_tilde_ntt.params != &inspiring_params.spiral
    {
        return Err(ReinspiringError::PreprocessMismatch(
            "invalid explicit digit material".into(),
        ));
    }
    if t_kg_steps.len() != d - 2 {
        return Err(ReinspiringError::PreprocessMismatch(format!(
            "expected {} K_g steps, got {}",
            d - 2,
            t_kg_steps.len()
        )));
    }
    if t_double_prime.len() != ell {
        return Err(ReinspiringError::PreprocessMismatch(
            "t_double_prime limb count".into(),
        ));
    }
    let exponents = collapse_kg_exponents(d);
    let mut blocks = Vec::with_capacity(ell);
    for limb in 0..ell {
        let ts: Vec<Vec<u64>> = t_kg_steps.iter().map(|step| step[limb].clone()).collect();
        let block = match algo {
            CompileAlgo::Naive => compile_naive_fused(&ts, &exponents, q)?,
            CompileAlgo::Fast => compile_fast(&ts, &exponents, q)?,
        };
        blocks.push(block);
    }
    Ok(ReinspiringPreprocessed {
        lift: crate::lift_ntt::LiftContext::new(d, q)?,
        params: rp,
        inspiring_params,
        a_tilde_ntt,
        h_prime: PackingMatrix::hstack(&blocks)?,
        t_double_prime,
    })
}

fn clone_ntt<'a>(src: &PolyMatrixNTT<'a>) -> PolyMatrixNTT<'a> {
    let mut out = PolyMatrixNTT::zero(src.params, src.rows, src.cols);
    for r in 0..src.rows {
        for c in 0..src.cols {
            out.get_poly_mut(r, c).copy_from_slice(src.get_poly(r, c));
        }
    }
    out
}
