//! `PackPreprocessed`: the CRS-model offline cache.
//!
//! See SPEC.md §8 (offline / online split). Every quantity in Algorithm 1
//! that depends only on `(A, K_g, K_h)` (and not on the LWE `b` scalars)
//! is materialised here, in NTT form, so the online [`crate::pack::pack`]
//! call is a pure function of `(b_0, …, b_{d-1}, &PackPreprocessed)`.
//!
//! The deterministic collapse result is cached here as an affine form:
//! online packing only adds `NTT(b̃)` to the precomputed `b` offset and stacks
//! that with the precomputed final `c1`.

use rayon::prelude::*;
use spiral_rs::poly::{from_ntt_alloc, to_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw};

use crate::automorph::{h, tau_g_pow};
use crate::collapse::precompute_collapse_affine;
use crate::error::InspiringError;
use crate::key_switching::{automorphic_image, KeySwitchingMatrix};
use crate::params::RlweParams;

/// Lean online cache for a single CRS `A` and key-switching pair `(K_g, K_h)`.
///
/// **API invariant (SPEC.md §10)**: this struct holds **exactly two**
/// affine collapse outputs. The key-switching matrices and their automorphic
/// images are consumed during [`PackPreprocessed::build`] and are not retained
/// on the online path.
///
pub struct PackPreprocessed<'a> {
    /// Underlying parameter set.
    pub params: &'a RlweParams,

    /// Final RLWE `c1` from collapsing the deterministic `a` trace.
    pub collapse_a_final_ntt: PolyMatrixNTT<'a>,

    /// Deterministic `c2` offset from collapsing with zero online `b`.
    ///
    /// Online packing computes `c2 = NTT(b̃) + collapse_b_offset_ntt`.
    pub collapse_b_offset_ntt: PolyMatrixNTT<'a>,
}

impl<'a> PackPreprocessed<'a> {
    /// Build all CRS-side data from `(A, K_g, K_h)`. Online callers then
    /// call [`crate::pack::pack`] with just the `b_k` scalars.
    ///
    /// API invariant: this signature accepts exactly two key-switching
    /// matrices. Adding a third is a breaking change and a CDKS-drift
    /// red flag (SPEC.md §9.h).
    ///
    pub fn build(
        params: &'a RlweParams,
        crs: &PolyMatrixNTT<'a>,
        kg: KeySwitchingMatrix<'a>,
        kh: KeySwitchingMatrix<'a>,
    ) -> Result<Self, InspiringError> {
        if crs.rows != params.d || crs.cols != 1 {
            return Err(InspiringError::PreprocessMismatch(format!(
                "expected CRS shape {}x1, got {}x{}",
                params.d, crs.rows, crs.cols
            )));
        }
        if kg.mat.rows != 2 || kg.mat.cols != params.gadget.ell {
            return Err(InspiringError::PreprocessMismatch(format!(
                "K_g must have shape 2x{}, got {}x{}",
                params.gadget.ell, kg.mat.rows, kg.mat.cols
            )));
        }
        if kh.mat.rows != 2 || kh.mat.cols != params.gadget.ell {
            return Err(InspiringError::PreprocessMismatch(format!(
                "K_h must have shape 2x{}, got {}x{}",
                params.gadget.ell, kh.mat.rows, kh.mat.cols
            )));
        }

        let crs_raw = from_ntt_alloc(crs);
        let a_tildes: Vec<_> = (0..params.d)
            .map(|row| a_tilde_coeffs(params, crs_raw.get_poly(row, 0)))
            .collect();
        let a_agg = build_a_agg(params, &a_tildes);

        let two_d = 2 * params.d as u64;
        let h_d = h(params.d);
        let kg_images_left: Vec<_> = (0..(params.d / 2 - 1))
            .map(|i| automorphic_image(&kg, tau_g_pow(i, params.d)))
            .collect();
        let kg_images_right: Vec<_> = (0..(params.d / 2 - 1))
            .map(|i| automorphic_image(&kg, (tau_g_pow(i, params.d) * h_d) % two_d))
            .collect();
        let collapse_affine =
            precompute_collapse_affine(params, a_agg, &kg_images_left, &kg_images_right, &kh);

        Ok(Self {
            params,
            collapse_a_final_ntt: collapse_affine.a_final_ntt,
            collapse_b_offset_ntt: collapse_affine.b_offset_ntt,
        })
    }
}

fn build_a_agg<'a>(params: &'a RlweParams, a_tildes: &[Vec<u64>]) -> Vec<PolyMatrixNTT<'a>> {
    (0..params.d)
        .into_par_iter()
        .map(|slot| aggregate_slot(params, a_tildes, slot))
        .collect()
}

fn aggregate_slot<'a>(
    params: &'a RlweParams,
    a_tildes: &[Vec<u64>],
    slot: usize,
) -> PolyMatrixNTT<'a> {
    let mut out = vec![0_u64; params.d];
    let exponent = if slot < params.d / 2 {
        tau_g_pow(slot, params.d)
    } else {
        let two_d = 2 * params.d as u64;
        (tau_g_pow(slot - params.d / 2, params.d) * h(params.d)) % two_d
    };

    for (shift, a_tilde) in a_tildes.iter().enumerate() {
        add_shifted_tau(&mut out, a_tilde, exponent, shift, params.q);
    }

    for coeff in &mut out {
        *coeff = (u128::from(*coeff) * u128::from(params.d_inv) % u128::from(params.q)) as u64;
    }

    let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    raw.get_poly_mut(0, 0).copy_from_slice(&out);
    to_ntt_alloc(&raw)
}

fn a_tilde_coeffs(params: &RlweParams, a: &[u64]) -> Vec<u64> {
    assert_eq!(
        a.len(),
        params.d,
        "preprocess::a_tilde_coeffs expects an LWE vector of length d"
    );

    let mut out = vec![0_u64; params.d];
    out[0] = a[0] % params.q;
    for (i, coeff) in a.iter().enumerate().skip(1) {
        let reduced = coeff % params.q;
        out[params.d - i] = if reduced == 0 { 0 } else { params.q - reduced };
    }
    out
}

fn add_shifted_tau(out: &mut [u64], poly: &[u64], exponent: u64, shift: usize, q: u64) {
    let d = out.len();
    let two_d = 2 * d as u64;

    for (source_idx, coeff) in poly.iter().enumerate() {
        let reduced = *coeff % q;
        if reduced == 0 {
            continue;
        }

        let exp = (source_idx as u64 * exponent) % two_d;
        let mut idx = if exp < d as u64 {
            exp as usize
        } else {
            (exp - d as u64) as usize
        };
        let mut negate = exp >= d as u64;

        idx += shift;
        if idx >= d {
            idx -= d;
            negate = !negate;
        }

        let term = if negate { q - reduced } else { reduced };
        out[idx] = ((u128::from(out[idx]) + u128::from(term)) % u128::from(q)) as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::GadgetParams;
    use spiral_rs::poly::{to_ntt_alloc, PolyMatrixRaw};

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

    fn zero_ks<'a>(params: &'a RlweParams) -> KeySwitchingMatrix<'a> {
        KeySwitchingMatrix {
            mat: PolyMatrixNTT::zero(&params.spiral, 2, params.gadget.ell),
            params,
        }
    }

    fn crs<'a>(params: &'a RlweParams) -> PolyMatrixNTT<'a> {
        let mut raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
        for row in 0..params.d {
            for col in 0..params.d {
                raw.get_poly_mut(row, 0)[col] = (row * params.d + col + 1) as u64;
            }
        }
        to_ntt_alloc(&raw)
    }

    #[test]
    fn build_precomputes_affine_collapse_cache() {
        let params = params();
        let crs = crs(&params);

        let pre = PackPreprocessed::build(&params, &crs, zero_ks(&params), zero_ks(&params))
            .expect("valid preprocessing");

        assert_eq!(pre.collapse_a_final_ntt.rows, 1);
        assert_eq!(pre.collapse_a_final_ntt.cols, 1);
        assert_eq!(pre.collapse_b_offset_ntt.rows, 1);
        assert_eq!(pre.collapse_b_offset_ntt.cols, 1);
    }

    #[test]
    fn build_rejects_wrong_crs_shape() {
        let params = params();
        let wrong = PolyMatrixNTT::zero(&params.spiral, 1, 1);

        assert!(matches!(
            PackPreprocessed::build(&params, &wrong, zero_ks(&params), zero_ks(&params)),
            Err(InspiringError::PreprocessMismatch(_))
        ));
    }
}
