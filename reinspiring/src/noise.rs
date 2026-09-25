//! Offline public coefficient accounting. Bounds describe original independent
//! sampler draws, never independent automorphic copies of the same draw.
use crate::{compile::compile_fast, lift_ntt::centered, matrix::PackingMatrix, ReinspiringError};

/// Exact integer norms of a vector of weights on independent sampler draws.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WeightNorms {
    /// Sum of absolute weights (also bounds amplification of sampler bias).
    pub l1: u128,
    /// Sum of squared weights, not its square root.
    pub l2_squared: u128,
    /// Largest absolute weight.
    pub max: u128,
}
impl WeightNorms {
    /// Measure signed weights exactly.
    /// Panics on u128 overflow; validated native profiles cannot reach this limit.
    pub fn measure(xs: impl IntoIterator<Item = i128>) -> Self {
        let mut out = Self::default();
        for x in xs {
            let x = x.unsigned_abs();
            out.l1 = out.l1.checked_add(x).expect("noise L1 overflow");
            out.l2_squared = out
                .l2_squared
                .checked_add(x.checked_mul(x).expect("noise square overflow"))
                .expect("noise L2 overflow");
            out.max = out.max.max(x);
        }
        out
    }
    /// Concatenate weights belonging to disjoint independent sample families.
    /// Panics on u128 overflow instead of silently underestimating noise.
    pub fn independent(self, other: Self) -> Self {
        Self {
            l1: self.l1.checked_add(other.l1).expect("noise L1 overflow"),
            l2_squared: self
                .l2_squared
                .checked_add(other.l2_squared)
                .expect("noise L2 overflow"),
            max: self.max.max(other.max),
        }
    }
    /// Componentwise upper envelope, valid for every covered output row.
    pub fn envelope(self, other: Self) -> Self {
        Self {
            l1: self.l1.max(other.l1),
            l2_squared: self.l2_squared.max(other.l2_squared),
            max: self.max.max(other.max),
        }
    }
}

/// Counterfactual one-limb final switch on the same pre-final public mask.
/// This is analysis only: it does not enable a new cryptographic profile.
#[derive(Debug)]
pub struct FinalGadgetAnalysis {
    /// Retained digit width; discarded width is log2(q)-bits.
    pub bits: u32,
    /// Envelope of combined original-key and secret weights across the block.
    pub weights: WeightNorms,
}

/// Public, snapshot-specific packing statistics. D.1 division, query errors,
/// query rounding and response rounding must be budgeted by the caller.
#[derive(Debug)]
pub struct NativeNoiseAnalysis {
    /// Envelope for all original key-error and combined secret-residue weights.
    pub weights: WeightNorms,
    /// Sum of final digit L1 norms; multiply by ciphertext rounding radius.
    pub kh_l1: u128,
    /// Per-limb envelopes of compiled original K_g error weights.
    pub kg_limbs: Vec<WeightNorms>,
    /// Combined secret-residue weights before the final switch.
    pub collapse_secret: WeightNorms,
    /// Public mask before the final switch, for offline mixed-radix screening.
    pub final_mask: Vec<u64>,
    /// Two-mask public-transport screens: precision and exactly combined weights.
    pub public_mask_screens: Vec<(u32, WeightNorms)>,
    /// One-limb counterfactuals, with unchanged collapse gadget.
    pub one_limb: Vec<FinalGadgetAnalysis>,
}

fn row_envelope(matrix: &PackingMatrix, start: usize, len: usize) -> WeightNorms {
    (0..matrix.rows)
        .map(|r| {
            WeightNorms::measure(
                matrix.data[r * matrix.cols + start..r * matrix.cols + start + len]
                    .iter()
                    .map(|&x| centered(x, matrix.q)),
            )
        })
        .fold(WeightNorms::default(), WeightNorms::envelope)
}

/// Offline mixed-radix signed digits and the exact reconstruction residue.
/// Widths must cover at most log2(q) bits; remaining low bits round upward at ties.
pub fn mixed_digits(
    a: &[u64],
    widths: &[u32],
    q: u64,
) -> Result<(Vec<Vec<u64>>, Vec<u64>), ReinspiringError> {
    if !q.is_power_of_two()
        || widths.is_empty()
        || widths.len() > 8
        || widths.iter().any(|&b| b == 0 || b > 29)
        || widths.iter().sum::<u32>() > q.trailing_zeros()
        || a.iter().any(|&x| x >= q)
    {
        return Err(ReinspiringError::InvalidParams(
            "invalid research gadget".into(),
        ));
    }
    let dropped = q.trailing_zeros() - widths.iter().sum::<u32>();
    let mut digits = vec![vec![0; a.len()]; widths.len()];
    let mut residues = Vec::with_capacity(a.len());
    for (i, &v) in a.iter().enumerate() {
        let mut x = if dropped == 0 {
            v as i128
        } else {
            (v as i128 + (1i128 << (dropped - 1))) >> dropped
        };
        let mut shift = dropped;
        let mut reconstruction = 0i128;
        for (j, &width) in widths.iter().enumerate() {
            let z = 1i128 << width;
            let digit = (x + z / 2).rem_euclid(z) - z / 2;
            digits[j][i] = digit.rem_euclid(q as i128) as u64;
            reconstruction += digit << shift;
            x = (x - digit) / z;
            shift += width;
        }
        residues.push((reconstruction - v as i128).rem_euclid(q as i128) as u64);
    }
    Ok((digits, residues))
}

pub(crate) fn residual(
    a: &[u64],
    digits: &[Vec<u64>],
    bits: u32,
    dropped: u32,
    q: u64,
) -> Vec<u64> {
    a.iter()
        .enumerate()
        .map(|(i, &x)| {
            let reconstructed = digits.iter().enumerate().fold(0u64, |s, (j, limb)| {
                let shift = dropped + bits * j as u32;
                s.wrapping_add(if shift < q.trailing_zeros() {
                    limb[i].wrapping_shl(shift)
                } else {
                    0
                })
            });
            reconstructed.wrapping_sub(x) & (q - 1)
        })
        .collect()
}

fn envelope(kg: &PackingMatrix, secret: &PackingMatrix, kh: &[Vec<u64>]) -> WeightNorms {
    let q = kg.q;
    let h = WeightNorms::measure(kh.iter().flatten().map(|&x| centered(x, q)));
    (0..kg.rows).fold(WeightNorms::default(), |out, r| {
        let g = WeightNorms::measure(
            kg.data[r * kg.cols..(r + 1) * kg.cols]
                .iter()
                .map(|&x| centered(x, q)),
        );
        let s = WeightNorms::measure(
            secret.data[r * secret.cols..(r + 1) * secret.cols]
                .iter()
                .map(|&x| centered(x, q)),
        );
        out.envelope(g.independent(s).independent(h))
    })
}

pub(crate) fn analyze(
    kg: &PackingMatrix,
    mut residues: Vec<Vec<u64>>,
    kg_exponents: &[u64],
    last_mask: &[u64],
    last_digits: &[Vec<u64>],
    bits: u32,
    dropped: u32,
) -> Result<NativeNoiseAnalysis, ReinspiringError> {
    let d = kg.rows;
    let q = kg.q;
    // K_g encrypts tau_5(s); its automorphism tau_e encrypts tau_(5e)(s).
    let mut exps: Vec<_> = kg_exponents
        .iter()
        .map(|&e| e * 5 % (2 * d) as u64)
        .collect();
    let collapse = if residues.is_empty() {
        PackingMatrix::zero(d, d, q)
    } else {
        compile_fast(&residues, &exps, q)?
    };
    let collapse_secret = row_envelope(&collapse, 0, d);
    let kg_limbs = (0..kg.cols / d)
        .map(|j| row_envelope(kg, j * d, d))
        .collect();
    exps.push((2 * d - 1) as u64);
    residues.push(residual(last_mask, last_digits, bits, dropped, q));
    let secret = compile_fast(&residues, &exps, q)?;
    let weights = envelope(kg, &secret, last_digits);
    let kh_l1 = WeightNorms::measure(last_digits.iter().flatten().map(|&x| centered(x, q))).l1;
    let mut one_limb = Vec::new();
    let mid = q.trailing_zeros() / 2;
    for b in mid.saturating_sub(2).max(1)..=(mid + 2).min(q.trailing_zeros() - 1) {
        let r = q.trailing_zeros() - b;
        let z = 1i128 << b;
        let digit: Vec<_> = last_mask
            .iter()
            .map(|&x| {
                let rounded = (x as i128 + (1i128 << (r - 1))) >> r;
                ((rounded + z / 2).rem_euclid(z) - z / 2).rem_euclid(q as i128) as u64
            })
            .collect();
        let digits = vec![digit];
        *residues.last_mut().unwrap() = residual(last_mask, &digits, b, r, q);
        let secret = compile_fast(&residues, &exps, q)?;
        one_limb.push(FinalGadgetAnalysis {
            bits: b,
            weights: envelope(kg, &secret, &digits),
        });
    }
    Ok(NativeNoiseAnalysis {
        weights,
        kh_l1,
        one_limb,
        kg_limbs,
        collapse_secret,
        final_mask: last_mask.to_vec(),
        public_mask_screens: Vec::new(),
    })
}

/// Original-sample weights before the final K_h switch.
pub(crate) fn analyze_two_mask(
    kg: &PackingMatrix,
    residues: Vec<Vec<u64>>,
    kg_exponents: &[u64],
    masks: [&[u64]; 2],
) -> Result<NativeNoiseAnalysis, ReinspiringError> {
    let d = kg.rows;
    let q = kg.q;
    let exps: Vec<_> = kg_exponents
        .iter()
        .map(|&e| e * 5 % (2 * d) as u64)
        .collect();
    let secret = if residues.is_empty() {
        PackingMatrix::zero(d, d, q)
    } else {
        compile_fast(&residues, &exps, q)?
    };
    let mut public_mask_screens = Vec::new();
    for bits in 27..=32.min(q.trailing_zeros()) {
        let shift = q.trailing_zeros() - bits;
        let step = 1u64 << shift;
        let deltas: Vec<Vec<u64>> = masks
            .iter()
            .map(|mask| {
                mask.iter()
                    .map(|&x| {
                        let rounded = ((x + step / 2) / step * step) & (q - 1);
                        rounded.wrapping_sub(x) & (q - 1)
                    })
                    .collect()
            })
            .collect();
        let correction = compile_fast(&deltas, &[1, (2 * d - 1) as u64], q)?;
        let mut combined = secret.clone();
        for (s, &e) in combined.data.iter_mut().zip(&correction.data) {
            *s = s.wrapping_add(e) & (q - 1);
        }
        public_mask_screens.push((bits, envelope(kg, &combined, &[])));
    }
    Ok(NativeNoiseAnalysis {
        public_mask_screens,
        weights: envelope(kg, &secret, &[]),
        kh_l1: 0,
        one_limb: Vec::new(),
        kg_limbs: (0..kg.cols / d)
            .map(|j| row_envelope(kg, j * d, d))
            .collect(),
        collapse_secret: row_envelope(&secret, 0, d),
        final_mask: Vec::new(),
    })
}

/// Exact sampler output multiplicities over all 2^64 possible uniform draws.
/// Includes inclusive CDF comparisons, duplicate thresholds and fallback to zero.
pub fn gaussian_counts() -> Vec<(i64, u128)> {
    let dg = crate::native_gaussian::gaussian();
    let mut previous = 0u128;
    let mut out = Vec::new();
    for (i, &cdf) in dg.cdf_table().iter().enumerate() {
        let end = cdf as u128 + 1;
        assert!(end >= previous);
        out.push((i as i64 - dg.max_val(), end - previous));
        previous = end;
    }
    out[dg.max_val() as usize].1 += (1u128 << 64) - previous;
    out
}

/// SHA-256 of the frozen native CDF encoded as consecutive little-endian u64s.
/// Certificate acceptance also checks the full multiplicities, not only this ID.
pub fn gaussian_cdf_sha256() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for x in crate::native_gaussian::gaussian().cdf_table() {
        hash.update(x.to_le_bytes());
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sampler_counts_match_inclusive_cdf_boundaries() {
        let dg = crate::native_gaussian::gaussian();
        let counts = gaussian_counts();
        assert_eq!(counts.iter().map(|x| x.1).sum::<u128>(), 1u128 << 64);
        let mut cumulative = 0u128;
        let fallback = (1u128 << 64) - (*dg.cdf_table().last().unwrap() as u128 + 1);
        for (i, &threshold) in dg.cdf_table().iter().enumerate() {
            cumulative += counts[i].1;
            assert_eq!(
                cumulative,
                threshold as u128
                    + 1
                    + if i >= dg.max_val() as usize {
                        fallback
                    } else {
                        0
                    }
            );
        }
        assert!(counts[0].1 > 0); // inclusive comparison assigns even draw zero
    }
    #[test]
    fn one_limb_residues_cover_ties_wraparound_and_signed_endpoints() {
        let q = 1u64 << 54;
        for b in 25..=29 {
            let r = 54 - b;
            let step = 1u64 << r;
            let a = [0, step / 2 - 1, step / 2, q / 2, q - step / 2, q - 1];
            let z = 1i128 << b;
            let digits = vec![a
                .iter()
                .map(|&x| {
                    let rounded = (x as i128 + (1i128 << (r - 1))) >> r;
                    ((rounded + z / 2).rem_euclid(z) - z / 2).rem_euclid(q as i128) as u64
                })
                .collect()];
            let error = residual(&a, &digits, b, r, q);
            assert!(error
                .iter()
                .all(|&x| centered(x, q).abs() <= step as i128 / 2));
            assert_eq!(centered(error[2], q), step as i128 / 2);
            assert_eq!(centered(digits[0][3], q), -z / 2);
        }
    }
}
