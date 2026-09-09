//! Reuse fixed public mask images during public preprocessing.
//!
//! This specializes `inspiring` 223626f's `precompute_reference_trace`:
//! its reference switching keys are `[fixed mask; zero]`, its initial `b` is
//! zero, and every subsequent `b` is zero. Only the top-row product contributes
//! to the returned c1 and gadget digits. Use the same library decomposition,
//! matrix multiplication and addition, with identical cascade/digit ordering.
//! No query key, secret, randomness, or database-dependent result is shared.
//! Byte equality against the pinned general implementation guards this
//! specialization; dependency changes must keep those tests passing.

use crate::{
    error::InspiringError, key_switching::ks_digits_ntt_from_c1,
    preprocess::PackPublicPreprocessed, QueryPackPreprocessed, RlweParams, TopKeyImages,
};
use spiral_rs::poly::{add_into, multiply, PolyMatrix, PolyMatrixNTT};

/// `top` must be built with these parameters and remain unmodified.
/// The caller retains ownership; this does not add a persistent cache.
pub(super) fn build<'a>(
    params: &'a RlweParams,
    crs: &PolyMatrixNTT<'a>,
    top: &TopKeyImages<'a>,
) -> Result<QueryPackPreprocessed<'a>, InspiringError> {
    top.validate(params)?;
    let mut left = PackPublicPreprocessed::build(params, crs)?.a_agg;
    let mut right = left.split_off(params.d / 2);
    let mut digits_ntt = Vec::with_capacity(params.d - 1);
    collapse_half(params, &mut left, &top.kg_top_left, &mut digits_ntt);
    collapse_half(params, &mut right, &top.kg_top_right, &mut digits_ntt);
    let final_digits = ks_digits_ntt_from_c1(params, &right[0]);
    add_product(params, &mut left[0], &top.kh_top, &final_digits);
    digits_ntt.push(final_digits);
    Ok(QueryPackPreprocessed {
        params,
        collapse_a_final_ntt: left.pop().expect("one collapsed component"),
        digits_ntt,
    })
}

fn collapse_half<'a>(
    params: &'a RlweParams,
    slots: &mut Vec<PolyMatrixNTT<'a>>,
    masks: &[PolyMatrixNTT<'a>],
    digits: &mut Vec<PolyMatrixNTT<'a>>,
) {
    while slots.len() > 1 {
        let index = slots.len() - 2;
        let next = ks_digits_ntt_from_c1(params, &slots[index + 1]);
        add_product(params, &mut slots[index], &masks[index], &next);
        slots.pop();
        digits.push(next);
    }
}

fn add_product<'a>(
    params: &'a RlweParams,
    destination: &mut PolyMatrixNTT<'a>,
    mask: &PolyMatrixNTT<'a>,
    digits: &PolyMatrixNTT<'a>,
) {
    let mut product = PolyMatrixNTT::zero(&params.spiral, 1, 1);
    multiply(&mut product, mask, digits);
    add_into(destination, &product);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::GadgetParams;
    use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};

    fn compare(params: &RlweParams) {
        let top = TopKeyImages::build(params);
        // Zero, modulus boundary, and changing dense CRS values. Reuse the same
        // public images across different inputs to catch accidental CRS reuse.
        for pattern in 0..3 {
            let mut raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
            for (i, value) in raw.as_mut_slice().iter_mut().enumerate() {
                *value = match pattern {
                    0 => 0,
                    1 => params.q - 1,
                    _ => (i as u64 * 7919 + 17) % params.q,
                };
            }
            let crs = to_ntt_alloc(&raw);
            let expected = QueryPackPreprocessed::build(params, &crs).unwrap();
            let actual = build(params, &crs, &top).unwrap();
            if params.d == 8 && params.gadget.ell == 3 && pattern == 2 {
                use sha2::{Digest, Sha256};
                let mut hash = Sha256::new();
                for matrix in
                    std::iter::once(&expected.collapse_a_final_ntt).chain(&expected.digits_ntt)
                {
                    for word in matrix.as_slice() {
                        hash.update(word.to_le_bytes());
                    }
                }
                // Frozen from the unmodified 223626f general builder: SHA-256
                // of c1 then digits in cascade order, each NTT word as LE u64.
                assert_eq!(
                    format!("{:x}", hash.finalize()),
                    "c9dc1391f4557b8b7126005717fbbcde2f8d59b150d21307be647f9a85002b8a"
                );
            }
            assert_eq!(
                actual.collapse_a_final_ntt.as_slice(),
                expected.collapse_a_final_ntt.as_slice()
            );
            assert_eq!(actual.digits_ntt.len(), params.d - 1);
            for (got, want) in actual.digits_ntt.iter().zip(&expected.digits_ntt) {
                assert_eq!(got.as_slice(), want.as_slice());
            }
        }
        let malformed = PolyMatrixNTT::zero(&params.spiral, params.d - 1, 1);
        assert!(build(params, &malformed, &top).is_err());
        let mut invalid_top = TopKeyImages::build(params);
        invalid_top.kg_top_left.clear();
        if params.d > 2 {
            assert!(build(
                params,
                &PolyMatrixNTT::zero(&params.spiral, params.d, 1),
                &invalid_top
            )
            .is_err());
        }
    }

    #[test]
    fn reused_masks_match_reference_for_boundaries_and_gadget_widths() {
        for d in [2, 8, 128] {
            for (bits_per, ell) in [(3, 5), (5, 3)] {
                compare(
                    &RlweParams::new(d, 12289, 4, 3.2, GadgetParams { bits_per, ell }).unwrap(),
                );
            }
        }
    }

    #[test]
    fn reused_masks_match_reference_at_production_parameters() {
        let params = RlweParams::new(
            2048,
            72_057_594_037_641_217,
            1 << 14,
            6.4,
            GadgetParams {
                bits_per: 19,
                ell: 3,
            },
        )
        .unwrap();
        compare(&params);
    }
}
