//! Pack backend selection: InspiRING (NTT) vs ReinspiRING (coefficient `H'`).
//!
//! The default remains [`PackBackend::Inspiring`]. ReinspiRING is an exact
//! rewrite for odd NTT-friendly moduli (byte-equal ciphertexts).

use inspiring::{InspiringError, PackingKeys, QueryPackPreprocessed, RlweCiphertext, TopKeyImages};
use rayon::prelude::*;
use reinspiring::{
    pack as reinspiring_pack, preprocess_from_inspiring, CompileAlgo, ReinspiringError,
    ReinspiringPreprocessed,
};

use crate::server::pack_intermediate_blocks;

/// Which online packing implementation the server uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PackBackend {
    /// NTT-domain InspiRING path (`QueryPackPreprocessed::pack_b`).
    #[default]
    Inspiring,
    /// Coefficient-domain ReinspiRING path (`H' · y + t'' · y'`).
    Reinspiring,
}

/// Convert an inspiring preprocess miss into a crate-local error string.
fn map_reinspiring(err: ReinspiringError) -> InspiringError {
    InspiringError::PreprocessMismatch(err.to_string())
}

/// Build ReinspiRING `H'` caches from inspiring digit material.
///
/// Call once offline after [`crate::server::build_pack_preprocessed_blocks`].
/// The returned blocks borrow only the long-lived [`inspiring::RlweParams`] (and spiral
/// allocations tied to it), not the inspiring preprocess vector itself.
pub fn build_reinspiring_blocks<'a>(
    inspiring_pre: &[QueryPackPreprocessed<'a>],
) -> Result<Vec<ReinspiringPreprocessed<'a>>, InspiringError> {
    let lift_q = inspiring_pre.first().map(|p| p.params.q).unwrap_or(12289);
    inspiring_pre
        .par_iter()
        .map(|pre| {
            preprocess_from_inspiring(pre, lift_q, CompileAlgo::Fast).map_err(map_reinspiring)
        })
        .collect()
}

/// Pack intermediate SimplePIR values using the selected backend.
pub fn pack_intermediate_blocks_with_backend<'a>(
    backend: PackBackend,
    intermediate: &[u64],
    packing_keys: &PackingKeys<'a>,
    top_key_images: &TopKeyImages<'a>,
    inspiring_pre: &'a [QueryPackPreprocessed<'a>],
    reinspiring_pre: Option<&'a [ReinspiringPreprocessed<'a>]>,
) -> Result<Vec<RlweCiphertext<'a>>, InspiringError> {
    match backend {
        PackBackend::Inspiring => {
            pack_intermediate_blocks(intermediate, packing_keys, top_key_images, inspiring_pre)
        }
        PackBackend::Reinspiring => {
            let Some(rpre) = reinspiring_pre else {
                return Err(InspiringError::PreprocessMismatch(
                    "Reinspiring backend requires reinspiring preprocess blocks".into(),
                ));
            };
            pack_intermediate_blocks_reinspiring(intermediate, packing_keys, rpre)
        }
    }
}

/// Pack using ReinspiRING only (no top-key images needed online).
pub fn pack_intermediate_blocks_reinspiring<'a>(
    intermediate: &[u64],
    packing_keys: &PackingKeys<'a>,
    preprocessed: &'a [ReinspiringPreprocessed<'a>],
) -> Result<Vec<RlweCiphertext<'a>>, InspiringError> {
    let Some(first) = preprocessed.first() else {
        return if intermediate.is_empty() {
            Ok(Vec::new())
        } else {
            Err(InspiringError::PreprocessMismatch(
                "non-empty intermediate with no reinspiring blocks".into(),
            ))
        };
    };
    let d = first.inspiring_params().d;
    let q = first.inspiring_params().q;
    if intermediate.len() != preprocessed.len() * d {
        return Err(InspiringError::LweShape(format!(
            "expected {} intermediate values for {} blocks of d={d}, got {}",
            preprocessed.len() * d,
            preprocessed.len(),
            intermediate.len()
        )));
    }
    packing_keys.validate(first.inspiring_params())?;

    intermediate
        .par_chunks_exact(d)
        .zip(preprocessed.par_iter())
        .enumerate()
        .map(|(block_idx, (b_block, pre))| {
            if pre.inspiring_params().d != d || pre.inspiring_params().q != q {
                return Err(InspiringError::PreprocessMismatch(format!(
                    "reinspiring block {block_idx} uses mismatched RLWE parameters"
                )));
            }
            reinspiring_pack(b_block, packing_keys, pre).map_err(map_reinspiring)
        })
        .collect()
}
