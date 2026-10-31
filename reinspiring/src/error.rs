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

#[cfg(test)]
mod tests {
    use super::ReinspiringError;
    use inspiring::InspiringError;
    use std::error::Error;

    fn assert_error_traits<T: Error + Send + Sync + Unpin + 'static>() {}

    #[test]
    fn display_and_source_are_stable() {
        assert_error_traits::<ReinspiringError>();
        let cases = [
            (
                ReinspiringError::InvalidParams("ring".into()),
                "invalid parameters: ring",
            ),
            (
                ReinspiringError::PreprocessMismatch("cache".into()),
                "preprocess mismatch: cache",
            ),
            (
                ReinspiringError::LweShape("dimension".into()),
                "LWE shape: dimension",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn inspiring_conversion_preserves_the_transparent_error() {
        let error = ReinspiringError::from(InspiringError::InvalidParams("ring".into()));
        assert_eq!(error.to_string(), "invalid parameter set: ring");
        // A transparent wrapper delegates to the inner error's source, which
        // is absent for these parameter errors.
        assert!(error.source().is_none());
        assert!(matches!(
            error,
            ReinspiringError::Inspiring(InspiringError::InvalidParams(reason))
                if reason == "ring"
        ));
    }
}
