//! Error type for `reinspiring`.

use thiserror::Error;

/// Errors from ReinspiRING preprocess / pack.
#[derive(Debug, Error)]
pub enum ReinspiringError {
    /// Parameter validation failed.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    /// Shape mismatch against an `inspiring` preprocess cache.
    #[error("preprocess mismatch: {0}")]
    PreprocessMismatch(String),

    /// Online LWE / key shape error.
    #[error("LWE shape: {0}")]
    LweShape(String),

    /// Wrapped inspiring error.
    #[error(transparent)]
    Inspiring(#[from] inspiring::InspiringError),
}
