#![allow(clippy::needless_range_loop)]
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use reinspiring::{
    compile::{compile_fast, compile_naive_fused, schoolbook_negacyclic},
    lift_ntt::LiftContext,
    native::*,
};

#[test]
fn crt_matches_schoolbook_signed_and_boundary_inputs() {
    for d in [2, 8, 16, 64] {
        for q in [12289, 1 << 40, 1 << 54] {
            let ctx = LiftContext::new(d, q).unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(923);
            for _ in 0..4 {
                let a: Vec<_> = (0..d).map(|_| rng.next_u64() % q).collect();
                let mut b: Vec<_> = (0..d).map(|_| rng.next_u64() % q).collect();
                b[0] = q - 1;
                assert_eq!(
                    ctx.multiply(&a, &b).unwrap(),
                    schoolbook_negacyclic(&a, &b, q)
                );
            }
            assert!(ctx.multiply(&vec![q; d], &vec![0; d]).is_err());
        }
    }
}
#[test]
fn cached_public_lifts_match_schoolbook_and_generic_at_capacity_boundaries() {
    for d in [2, 16, 64] {
        for q in [12289, 1 << 54, 1 << 56] {
            let ctx = LiftContext::new(d, q).unwrap();
            // Small public digits select two primes; full-width selects three.
            // Include signed endpoints, zero and multi-limb accumulation.
            let threshold = ((4398046568449u128 * 4398046666753u128 - 1)
                / (2 * d as u128 * (q / 2) as u128))
                .min((q / 2 - 1) as u128) as u64;
            for bound in [0, 1, (1 << 18).min(q / 2), threshold, threshold + 1, q / 2] {
                let a: Vec<Vec<_>> = (0..3)
                    .map(|j| {
                        (0..d)
                            .map(|i| {
                                if (i + j) % 2 == 0 {
                                    bound
                                } else {
                                    (q - bound) % q
                                }
                            })
                            .collect()
                    })
                    .collect();
                let b: Vec<Vec<_>> = (0..3)
                    .map(|j| {
                        (0..d)
                            .map(|i| [0, q - 1, q / 2, q / 2 + 1][(i + j) % 4])
                            .collect()
                    })
                    .collect();
                let cached = ctx.prepare_public(&a).unwrap();
                let mut expected = vec![0; d];
                for (a, b) in a.iter().zip(&b) {
                    for (dst, x) in expected.iter_mut().zip(schoolbook_negacyclic(a, b, q)) {
                        *dst = (*dst + x) % q;
                    }
                }
                assert_eq!(ctx.sum_prepared(&cached, &b).unwrap(), expected);
                let right = ctx.prepare_right(&b).unwrap();
                assert_eq!(ctx.sum_cached(&cached, &right).unwrap(), expected);
                assert!(LiftContext::new(d, q - 1)
                    .unwrap()
                    .sum_cached(&cached, &right)
                    .is_err());
                let short = ctx.prepare_right(&b[..2]).unwrap();
                assert!(ctx.sum_cached(&cached, &short).is_err());
                assert_eq!(
                    ctx.sum_prepared(&cached, &b).unwrap(),
                    ctx.sum(&a, &b).unwrap()
                );
                assert!(ctx.sum_prepared(&cached, &b[..2]).is_err());
                assert!(LiftContext::new(d, q - 1)
                    .unwrap()
                    .sum_prepared(&cached, &b)
                    .is_err());
            }
            assert!(ctx.prepare_right(&[]).is_err());
            assert!(ctx.prepare_right(&[vec![q; d]]).is_err());
            assert!(ctx.prepare_public(&[]).is_err());
            assert!(ctx.prepare_public(&[vec![q; d]]).is_err());
        }
    }
}

#[test]
fn cached_leftover_checks_the_sum_before_combining_inverse_transforms() {
    let d = 16;
    let q = 1u64 << 56;
    let ell = 3;
    let ctx = LiftContext::new(d, q).unwrap();
    let limit = ((4398046568449u128 * 4398046666753u128 - 1)
        / (2 * d as u128 * ell as u128 * (q / 2) as u128)) as u64;
    for bound in [limit, limit + 1] {
        for value in [bound, q - bound] {
            let a = vec![vec![value; d]; ell];
            let b = vec![vec![q / 2; d]; ell];
            let left = ctx.prepare_public(&a).unwrap();
            let right = ctx.prepare_right(&b).unwrap();
            assert_eq!(
                ctx.sum_cached(&left, &right).unwrap(),
                ctx.sum(&a, &b).unwrap()
            );
        }
    }
}

#[test]
fn public_dot_matches_independent_products_and_checks_aggregate_capacity() {
    for d in [2, 16, 64] {
        for q in [12289, 1 << 54, 1 << 56] {
            let ctx = LiftContext::new(d, q).unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(0x524e);
            let a: Vec<Vec<_>> = (0..14)
                .map(|_| (0..d).map(|_| rng.next_u64() % q).collect())
                .collect();
            // Bracket the two-prime boundary for the complete sum, not a
            // single product. This also exercises negative reconstruction.
            let maxima: u128 = a
                .iter()
                .map(|poly| poly.iter().map(|&x| x.min(q - x) as u128).max().unwrap())
                .sum();
            let threshold = ((4398046568449u128 * 4398046666753u128 - 1) / (2 * d as u128 * maxima))
                .min((q / 2 - 1) as u128) as u64;
            for bound in [0, 1, 16383.min(q / 2), threshold, threshold + 1, q / 2] {
                let cached = ctx.prepare_public_dot(&a, bound).unwrap();
                let b: Vec<Vec<_>> = (0..a.len())
                    .map(|j| {
                        (0..d)
                            .map(|i| [bound, (q - bound) % q, 0][(i + j) % 3])
                            .collect()
                    })
                    .collect();
                let mut expected = vec![0; d];
                for (a, b) in a.iter().zip(&b) {
                    for (dst, x) in expected.iter_mut().zip(schoolbook_negacyclic(a, b, q)) {
                        *dst = (*dst + x) % q;
                    }
                }
                assert_eq!(ctx.public_dot(&cached, &b).unwrap(), expected);
                assert_eq!(
                    ctx.public_dot(&cached, &b).unwrap(),
                    ctx.sum(&a, &b).unwrap()
                );
                assert!(ctx.public_dot(&cached, &b[..b.len() - 1]).is_err());
                assert!(LiftContext::new(d, q - 1)
                    .unwrap()
                    .public_dot(&cached, &b)
                    .is_err());
                let mut bad = b.clone();
                bad[0][0] = q;
                assert!(ctx.public_dot(&cached, &bad).is_err());
                if bound < q / 2 {
                    bad[0][0] = bound + 1;
                    assert!(ctx.public_dot(&cached, &bad).is_err());
                }
            }
            assert!(ctx.prepare_public_dot(&[], 0).is_err());
            assert!(ctx.prepare_public_dot(&a, q / 2 + 1).is_err());
            assert!(ctx.prepare_public_dot(&[vec![q; d]], 1).is_err());
        }
    }
    // Force an actual coefficient across the two-prime signed range: the
    // coefficient at d-1 has d positive products per operand, with no wrap.
    // A per-product bound would incorrectly select two primes for this sum.
    let d = 16;
    let q = 1u64 << 56;
    let count = 14;
    let a = vec![vec![q / 2; d]; count];
    let threshold = ((4398046568449u128 * 4398046666753u128 - 1)
        / (2 * d as u128 * count as u128 * (q / 2) as u128)) as u64;
    let ctx = LiftContext::new(d, q).unwrap();
    for bound in [threshold, threshold + 1] {
        let cached = ctx.prepare_public_dot(&a, bound).unwrap();
        for value in [bound, q - bound] {
            let b = vec![vec![value; d]; count];
            let actual = ctx.public_dot(&cached, &b).unwrap();
            assert_eq!(actual, ctx.sum(&a, &b).unwrap());
            let signed = if value == bound {
                bound as i128
            } else {
                -(bound as i128)
            };
            assert_eq!(
                actual[d - 1],
                (d as i128 * count as i128 * (q / 2) as i128 * signed).rem_euclid(q as i128) as u64
            );
        }
    }
    // The generic single-product capacity guarantee is not sufficient for
    // an unbounded dot product. Reject rather than silently wrap in CRT.
    let d = 4096;
    let q = 1 << 56;
    assert!(LiftContext::new(d, q)
        .unwrap()
        .prepare_public_dot(&vec![vec![q / 2; d]; 16], q / 2)
        .is_err());
}

#[test]
fn compile_fft_handles_arbitrary_odd_and_repeated_exponents() {
    for q in [12289, 1 << 54] {
        for d in [2, 4, 8, 16, 64] {
            let exps = vec![1, 3, 3, (2 * d - 1) as u64];
            let mut rng = ChaCha20Rng::seed_from_u64(4);
            let ts: Vec<Vec<_>> = (0..exps.len())
                .map(|_| (0..d).map(|_| rng.next_u64() % q).collect())
                .collect();
            assert_eq!(
                compile_fast(&ts, &exps, q).unwrap().data,
                compile_naive_fused(&ts, &exps, q).unwrap().data
            );
        }
    }
    assert!(compile_fast(&[], &[], 12289).is_err());
    assert!(compile_fast(&[vec![0; 8]], &[2], 12289).is_err());
}
#[test]
fn native_encryption_to_decryption_both_samplers_and_limb_counts() {
    for sampler in [
        SecretDistribution::Gaussian,
        SecretDistribution::TernaryResearch,
    ] {
        for d in [2, 4, 8, 16, 64] {
            for ell in [2, 3] {
                roundtrip(d, ell, sampler);
            }
        }
    }
}
#[test]
fn one_key_two_mask_matches_packing_phase_and_split_path() {
    for d in [2, 4, 8, 16, 64] {
        let p = NativeParams::new(d, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
        let setup = NativeSetup::new(p.clone(), [23; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(311 + d as u64);
        let masks: Vec<Vec<_>> = (0..d)
            .map(|_| (0..d).map(|_| rng.next_u64() & (p.q() - 1)).collect())
            .collect();
        let pre = NativePreprocessed::build_two_mask(&setup, &masks).unwrap();
        let secret = NativeSecret::sample(&p, &mut rng);
        let keys = NativeKeys::generate_one_key(&setup, &secret, &mut rng).unwrap();
        let messages: Vec<_> = (0..d).map(|_| rng.next_u64() & (p.p() - 1)).collect();
        let bodies: Vec<_> = masks
            .iter()
            .zip(&messages)
            .map(|(a, &m)| secret.encrypt_lwe(a, m, &mut rng).unwrap())
            .collect();
        let ct = pre.pack_two_mask(&bodies, &keys).unwrap();
        let prepared = pre.prepare_keys(&keys).unwrap();
        let split = pre
            .prepare_pack(&prepared)
            .unwrap()
            .finish_two_mask(&bodies)
            .unwrap();
        assert_eq!(ct.rows(), split.rows());
        assert_eq!(secret.decrypt_two_mask(&ct).unwrap(), messages);
        assert!(secret.phase_error_two_mask(&ct, &messages).unwrap() < p.q() / p.p() / 2);
        assert!(pre.pack(&bodies, &keys).is_err());
        assert!(pre
            .prepare_pack(&prepared)
            .unwrap()
            .finish(&bodies)
            .is_err());
    }
}
fn roundtrip(d: usize, ell: usize, sampler: SecretDistribution) {
    let p = NativeParams::new(d, 54, 14, 19, ell, sampler).unwrap();
    let setup = NativeSetup::new(p.clone(), [1; 32]);
    let mut rng = ChaCha20Rng::seed_from_u64(134);
    let masks: Vec<Vec<_>> = (0..d)
        .map(|_| (0..d).map(|_| rng.next_u64() & (p.q() - 1)).collect())
        .collect();
    let pre = NativePreprocessed::build(&setup, &masks).unwrap();
    for _ in 0..3 {
        let s = NativeSecret::sample(&p, &mut rng);
        let keys = NativeKeys::generate(&setup, &s, &mut rng).unwrap();
        let messages: Vec<_> = (0..d).map(|_| rng.next_u64() & (p.p() - 1)).collect();
        let b: Vec<_> = masks
            .iter()
            .zip(&messages)
            .map(|(a, &m)| s.encrypt_lwe(a, m, &mut rng).unwrap())
            .collect();
        let ct = pre.pack(&b, &keys).unwrap();
        let prepared = pre.prepare_keys(&keys).unwrap();
        let pending = pre.prepare_pack(&prepared).unwrap();
        assert_eq!(pending.finish(&b).unwrap().rows(), ct.rows());
        assert!(pre
            .prepare_pack(&prepared)
            .unwrap()
            .finish(&b[..d - 1])
            .is_err());
        assert!(pre
            .prepare_pack(&prepared)
            .unwrap()
            .finish(&vec![p.q(); d])
            .is_err());
        let error = s.phase_error(&ct, &messages).unwrap();
        assert_eq!(
            s.decrypt(&ct).unwrap(),
            messages,
            "d={d} ell={ell} sampler={sampler:?} error={error}"
        );
        assert!(error < p.q() / p.p() / 2);
        let bad = NativeSetup::new(p.clone(), [2; 32]);
        let other_pre = NativePreprocessed::build(&bad, &masks).unwrap();
        assert!(other_pre.prepare_pack(&prepared).is_err());
        assert!(other_pre.prepare_keys(&keys).is_err());
        assert!(pre
            .pack(&b, &NativeKeys::generate(&bad, &s, &mut rng).unwrap())
            .is_err());
    }
}
#[test]
#[ignore = "degree-2048 cryptographic validation; run explicitly in release"]
fn native_paper_degree_roundtrip() {
    for sampler in [
        SecretDistribution::Gaussian,
        SecretDistribution::TernaryResearch,
    ] {
        for ell in [2, 3] {
            roundtrip(2048, ell, sampler);
        }
    }
}
#[test]
fn decomposition_reconstructs_with_documented_rounding_error() {
    for ell in [2, 3] {
        let p = NativeParams::new(8, 54, 14, 19, ell, SecretDistribution::Gaussian).unwrap();
        let q = p.q();
        let a = vec![0, 1, q - 1, q / 2, q / 2 - 1, 32767, 32768, 32769];
        let digits = decompose(&a, &p).unwrap();
        for i in 0..8 {
            let reconstructed = (0..ell).fold(0u64, |s, j| {
                s.wrapping_add(
                    digits[j][i].wrapping_mul(1u64 << (p.dropped_bits() + 19 * j as u32)),
                )
            }) & (q - 1);
            let diff = reconstructed.wrapping_sub(a[i]) & (q - 1);
            let dist = diff.min(q - diff);
            assert!(
                dist <= if p.dropped_bits() == 0 {
                    0
                } else {
                    1 << (p.dropped_bits() - 1)
                }
            );
        }
    }
}

#[test]
fn compact_matrix_matches_wide_oracle_at_all_storage_and_modulus_boundaries() {
    use reinspiring::{matrix::PackingMatrix, native_matrix::NativeMatrix};
    for q in [12289, (1 << 54), 72_057_594_037_641_217] {
        for cols in [1, 3, 8, 511, 6144] {
            let mut m = PackingMatrix::zero(3, cols, q);
            for (i, x) in m.data.iter_mut().enumerate() {
                *x = match i % 5 {
                    0 => q - 1,
                    1 => 1,
                    2 => (i32::MAX as u64).min(q - 1),
                    3 => q / 2,
                    _ => 0,
                };
            }
            let y: Vec<_> = (0..cols).map(|i| q - 1 - i as u64 % (q - 1)).collect();
            let expected: Vec<_> = (0..3)
                .map(|r| {
                    m.data[r * cols..(r + 1) * cols]
                        .iter()
                        .zip(&y)
                        .fold(0u128, |s, (&a, &b)| (s + a as u128 * b as u128) % q as u128)
                        as u64
                })
                .collect();
            assert_eq!(
                NativeMatrix::from_compiled(m)
                    .unwrap()
                    .multiply(&y)
                    .unwrap(),
                expected
            );
            let mut m = PackingMatrix::zero(2, cols, q);
            for (i, x) in m.data.iter_mut().enumerate() {
                *x = if i % 2 == 0 { q - 123 } else { 17 };
            }
            let mut expected = vec![0; 2];
            m.matvec(&y, &mut expected).unwrap();
            assert_eq!(
                NativeMatrix::from_compiled(m)
                    .unwrap()
                    .multiply(&y)
                    .unwrap(),
                expected
            );
        }
    }
}
