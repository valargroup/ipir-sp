//! Discrete-Gaussian sampler with a frozen default CDF.
//!
//! The pinned backend builds its CDF table at runtime from `f64::exp`, whose
//! last bits depend on the platform's math library. Secrets are regenerated
//! from seeds, so the table is part of the protocol: a host whose `exp`
//! differs could derive a different secret from the same seed, and a broken
//! `exp` could collapse the error term without any decoding failure.
//!
//! For the default standard deviation 6.4 this module therefore uses the
//! 131 integer thresholds the backend computed on macOS ARM64 and Linux
//! x86_64, frozen in `gaussian_cdf_6_4.txt` and pinned by SHA-256. They are
//! identical to the native table in `reinspiring/src/native_gaussian_cdf.txt`.
//! Other standard deviations are research or test profiles and still use the
//! backend's runtime construction.

use spiral_rs::discrete_gaussian::DiscreteGaussian;
use std::sync::OnceLock;

/// Standard deviation whose CDF table is frozen.
pub const DEFAULT_SIGMA_CHI: f64 = 6.4;

/// Largest absolute sample of the frozen table, `ceil(4 * 6.4 * sqrt(2*pi))`.
const DEFAULT_MAX_VAL: i64 = 65;

/// Frozen CDF thresholds for standard deviation 6.4, indexed from -65 through 65.
///
/// A uniform `u64` draw `x` maps to the first index `i` with `x <= table[i]`;
/// draws above the last threshold map to zero.
pub fn default_cdf_table() -> &'static [u64] {
    static TABLE: OnceLock<Vec<u64>> = OnceLock::new();
    TABLE.get_or_init(|| {
        include_str!("gaussian_cdf_6_4.txt")
            .lines()
            .map(|line| line.parse().expect("invalid frozen Gaussian CDF"))
            .collect()
    })
}

/// Return the constant-time CDF sampler for standard deviation `sigma_chi`.
///
/// For [`DEFAULT_SIGMA_CHI`] the table is the frozen one, so no floating-point
/// transcendental runs. Any other `sigma_chi` falls back to the backend's
/// `DiscreteGaussian::init(sigma_chi * sqrt(2*pi))`. Callers must use the
/// backend's constant-time `sample`, never `fast_sample`.
pub fn discrete_gaussian(sigma_chi: f64) -> DiscreteGaussian {
    if sigma_chi.to_bits() != DEFAULT_SIGMA_CHI.to_bits() {
        return DiscreteGaussian::init(sigma_chi * std::f64::consts::TAU.sqrt());
    }
    let cdf_table = default_cdf_table().to_vec();
    // The backend also stores weights for its variable-time `fast_sample`.
    // Derive them from the frozen thresholds so that method draws from the
    // same distribution as `sample`, again without calling `exp`.
    let weights: Vec<f64> = default_counts().into_iter().map(|c| c as f64).collect();
    DiscreteGaussian {
        weighted_index: rand::distributions::WeightedIndex::new(weights)
            .expect("frozen Gaussian CDF has positive mass"),
        cdf_table,
        max_val: DEFAULT_MAX_VAL,
    }
}

/// Number of the 2^64 uniform draws that `sample` maps to each output index.
fn default_counts() -> Vec<u128> {
    let table = default_cdf_table();
    let mut previous = 0u128;
    let mut counts: Vec<u128> = table
        .iter()
        .map(|&threshold| {
            let end = u128::from(threshold) + 1;
            let count = end - previous;
            previous = end;
            count
        })
        .collect();
    counts[DEFAULT_MAX_VAL as usize] += (1u128 << 64) - previous;
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha256};

    #[test]
    fn frozen_table_identity_and_shape() {
        let table = default_cdf_table();
        assert_eq!(table.len(), 2 * DEFAULT_MAX_VAL as usize + 1);
        assert!(table.windows(2).all(|w| w[0] <= w[1]));
        let bytes: Vec<u8> = table.iter().flat_map(|x| x.to_le_bytes()).collect();
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            "bc68011d7224eb5dcb649a206c70697d4e6bce32af77966f4ebd60c0683cac2e"
        );
    }

    #[test]
    fn frozen_table_matches_backend_runtime_table() {
        // Compatibility evidence: the frozen table equals what the backend
        // computes on this host, so seeds created before freezing decode
        // unchanged. A failure means this platform's libm diverges.
        let runtime = DiscreteGaussian::init(DEFAULT_SIGMA_CHI * std::f64::consts::TAU.sqrt());
        assert_eq!(runtime.max_val, DEFAULT_MAX_VAL);
        assert_eq!(runtime.cdf_table, default_cdf_table());
    }

    #[test]
    fn default_sampler_uses_frozen_table_and_matches_runtime_draws() {
        let frozen = discrete_gaussian(DEFAULT_SIGMA_CHI);
        assert_eq!(frozen.cdf_table, default_cdf_table());
        assert_eq!(frozen.max_val, DEFAULT_MAX_VAL);

        let runtime = DiscreteGaussian::init(DEFAULT_SIGMA_CHI * std::f64::consts::TAU.sqrt());
        let q = 72_057_594_037_641_217;
        let mut a = ChaCha20Rng::from_seed([0x47; 32]);
        let mut b = ChaCha20Rng::from_seed([0x47; 32]);
        for _ in 0..4096 {
            assert_eq!(frozen.sample(q, &mut a), runtime.sample(q, &mut b));
        }
    }

    #[test]
    fn counts_cover_every_draw_and_are_symmetric() {
        let counts = default_counts();
        assert_eq!(counts.iter().sum::<u128>(), 1u128 << 64);
        let zero = DEFAULT_MAX_VAL as usize;
        assert!(counts[zero] > 0);
        assert!(counts[zero] >= counts[zero + 1]);
        // Rounding may perturb the outermost tails, but the bulk is symmetric
        // to within the 2^11 granularity of f64 near 2^64.
        for k in 1..=40 {
            let diff = counts[zero - k].abs_diff(counts[zero + k]);
            assert!(diff <= 1 << 13, "asymmetric at +/-{k}: {diff}");
        }
    }

    #[test]
    fn other_sigmas_use_runtime_table() {
        let dg = discrete_gaussian(3.2);
        let runtime = DiscreteGaussian::init(3.2 * std::f64::consts::TAU.sqrt());
        assert_eq!(dg.cdf_table, runtime.cdf_table);
        assert_eq!(dg.max_val, runtime.max_val);
    }
}
