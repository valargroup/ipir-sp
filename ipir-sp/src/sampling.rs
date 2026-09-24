//! Explicit uniform sampling for public (CRS) randomness.
//!
//! The offline query polynomials are derived by both peers from a shared seed,
//! so the exact bytes-to-integers mapping is part of the wire protocol. It used
//! to be `rand::Rng::gen_range(0..q)`, whose algorithm is an implementation
//! detail of the `rand` crate and changed between 0.8 and 0.9. This module pins
//! the mapping in-tree so that a `rand` upgrade, or a client written in another
//! language, cannot silently produce a different CRS.
//!
//! The algorithm is Lemire's nearly-divisionless rejection sampler exactly as
//! `rand` 0.8 implemented it for `u64` and `u32` ranges, so the values produced
//! for existing seeds are unchanged. Every draw is `bound / 2^64`-close to
//! uniform after the rejection step, and the output is exactly uniform in
//! `[0, bound)` given a uniform `u64` stream.

use rand_chacha::rand_core::RngCore;

/// Sample a uniform integer in `[0, bound)` from `rng`.
///
/// Bit-compatible with `rand` 0.8's `gen_range(0..bound)` for `u64` on a
/// `ChaCha20Rng`. `bound` must be non-zero.
///
/// This is used for **public** randomness only. Secret and error coefficients
/// go through the discrete-Gaussian sampler, never through this function.
#[must_use]
pub fn uniform_u64_below(rng: &mut impl RngCore, bound: u64) -> u64 {
    assert!(bound > 0, "uniform bound must be non-zero");
    // Reject the top slice of the 64-bit space that would bias the low
    // multiplication word. `- 1` keeps the comparison unbiased.
    let zone = (bound << bound.leading_zeros()).wrapping_sub(1);
    loop {
        let draw = rng.next_u64();
        let product = u128::from(draw) * u128::from(bound);
        let low = product as u64;
        if low <= zone {
            return (product >> 64) as u64;
        }
    }
}

/// Sample a uniform integer in `[0, bound)` from `rng` using 32-bit draws.
///
/// Bit-compatible with `rand` 0.8's `gen_range(0..bound)` for `u32`-sized
/// ranges on a `ChaCha20Rng`. `bound` must be non-zero.
#[must_use]
pub fn uniform_u32_below(rng: &mut impl RngCore, bound: u32) -> u32 {
    assert!(bound > 0, "uniform bound must be non-zero");
    let zone = (bound << bound.leading_zeros()).wrapping_sub(1);
    loop {
        let draw = rng.next_u32();
        let product = u64::from(draw) * u64::from(bound);
        let low = product as u32;
        if low <= zone {
            return (product >> 32) as u32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn matches_rand_0_8_gen_range_for_pinned_seed() {
        // First four coefficients of the first query polynomial derived from
        // the `[7; 32]` pool seed at the production modulus, recorded while
        // the crate still called `rand` 0.8's `gen_range`. See
        // `client::reusable::tests::pool_slots_are_unique_bounded_and_retries_are_immutable`.
        let q = crate::params::SINGLE_CRT_Q;
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        rng.set_stream(u64::from_le_bytes(*b"IPIRpool"));
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let draws: Vec<u64> = (0..4).map(|_| uniform_u64_below(&mut rng, q)).collect();
        assert_eq!(
            draws,
            [
                9_164_527_206_802_959,
                5_084_643_010_587_079,
                51_932_877_172_136_113,
                33_393_100_479_081_743,
            ]
        );
    }

    #[test]
    fn outputs_stay_below_bound_and_cover_small_ranges() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5A4D);
        for bound in [
            1_u64,
            2,
            3,
            7,
            1 << 20,
            crate::params::SINGLE_CRT_Q,
            u64::MAX,
        ] {
            for _ in 0..1_000 {
                assert!(uniform_u64_below(&mut rng, bound) < bound);
            }
        }
        let mut seen = [false; 3];
        for _ in 0..1_000 {
            seen[uniform_u32_below(&mut rng, 3) as usize] = true;
        }
        assert!(seen.iter().all(|hit| *hit));
    }

    #[test]
    fn accepted_draws_map_to_their_top_bits_and_rejections_match_the_zone() {
        // For `bound = 2^20` the zone is `2^63 - 1`, so `rand` 0.8 (and this
        // port) rejects exactly the draws whose bit 43 is set and returns the
        // top 20 bits of the first accepted draw.
        let mut sampler = ChaCha20Rng::seed_from_u64(1);
        let mut reference = ChaCha20Rng::seed_from_u64(1);
        for _ in 0..64 {
            let got = uniform_u64_below(&mut sampler, 1 << 20);
            let want = loop {
                let draw = reference.next_u64();
                if (draw << 20) >> 63 == 0 {
                    break draw >> 44;
                }
            };
            assert_eq!(got, want);
        }
    }
}
