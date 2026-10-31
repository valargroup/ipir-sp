//! Crate error type.
//!
//! Every fallible public API in `inspiring` returns `Result<_, InspiringError>`.
//! Variants are stable: adding a variant is a breaking change, removing or
//! renaming one is a breaking change.

use thiserror::Error;

/// All errors produced by the `inspiring` crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InspiringError {
    /// Parameter-set validation failure (see [`crate::params::RlweParams::new`]).
    ///
    /// Examples:
    /// - `d` is not a power of two.
    /// - `q` is even (would make `d^{-1} mod q` non-existent;
    ///   see SPEC.md §1).
    /// - `(z, ℓ)` are inconsistent with `q` (gadget cannot cover the
    ///   modulus, or `bits_per` derived from `(z, ℓ)` does not match
    ///   spiral-rs's `gadget::get_bits_per`; see
    ///   `docs/spiral-rs-mapping.md` §2).
    #[error("invalid parameter set: {0}")]
    InvalidParams(String),

    /// An LWE ciphertext (or batch) does not match the expected dimensions
    /// for the configured [`crate::params::RlweParams`].
    #[error("LWE shape mismatch: {0}")]
    LweShape(String),

    /// A [`crate::preprocess::PackPreprocessed`] was built against a
    /// different parameter set than the [`crate::lwe::LweBatch`] passed to
    /// [`crate::pack::pack`].
    #[error("preprocessing/parameter mismatch: {0}")]
    PreprocessMismatch(String),

    /// Internal invariant violation. Treat as a panic in debug builds; in
    /// release builds we surface it through `Result` so callers can decide.
    /// Always indicates a bug in `inspiring`, not in caller code.
    #[error("internal invariant: {0}")]
    Internal(&'static str),
}

#[cfg(test)]
mod tests {
    use super::InspiringError;
    use std::error::Error;

    fn assert_error_traits<T: Error + Send + Sync + Unpin + 'static>() {}

    #[test]
    fn display_and_source_are_stable() {
        assert_error_traits::<InspiringError>();
        let cases = [
            (
                InspiringError::InvalidParams("ring".into()),
                "invalid parameter set: ring",
            ),
            (
                InspiringError::LweShape("dimension".into()),
                "LWE shape mismatch: dimension",
            ),
            (
                InspiringError::PreprocessMismatch("cache".into()),
                "preprocessing/parameter mismatch: cache",
            ),
            (
                InspiringError::Internal("invariant"),
                "internal invariant: invariant",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
            assert!(error.source().is_none());
        }
    }
}
