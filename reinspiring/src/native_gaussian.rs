//! Frozen native sigma-6.4 CDF; sampling uses the pinned backend's fixed scan.
//! The table is the exact integer table used by the recorded native certificates.
//! The wrapper exposes only the fixed scan, never the backend fast sampler.
use spiral_rs::discrete_gaussian::DiscreteGaussian;
use std::sync::OnceLock;

pub(crate) struct NativeGaussian(DiscreteGaussian);

impl NativeGaussian {
    pub(crate) fn cdf_table(&self) -> &[u64] {
        &self.0.cdf_table
    }
    pub(crate) fn max_val(&self) -> i64 {
        self.0.max_val
    }
    pub(crate) fn sample(&self, modulus: u64, rng: &mut rand_chacha::ChaCha20Rng) -> u64 {
        self.0.sample(modulus, rng)
    }
}

pub(crate) fn gaussian() -> &'static NativeGaussian {
    static SAMPLER: OnceLock<NativeGaussian> = OnceLock::new();
    SAMPLER.get_or_init(|| {
        NativeGaussian(DiscreteGaussian {
            // The backend requires this field for its unused variable-time method.
            // It does not participate in the CDF-based sample method.
            weighted_index: rand::distributions::WeightedIndex::new([1.0]).unwrap(),
            cdf_table: include_str!("native_gaussian_cdf.txt")
                .lines()
                .map(|line| line.parse().expect("invalid frozen native CDF"))
                .collect(),
            max_val: 65,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn frozen_cdf_identity_and_shape() {
        let dg = gaussian();
        assert_eq!(dg.cdf_table().len(), 131);
        assert!(dg.cdf_table().windows(2).all(|w| w[0] <= w[1]));
        let bytes: Vec<_> = dg
            .cdf_table()
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            "bc68011d7224eb5dcb649a206c70697d4e6bce32af77966f4ebd60c0683cac2e"
        );
    }
}
