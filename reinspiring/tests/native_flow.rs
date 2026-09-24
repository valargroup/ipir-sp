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
fn compile_fft_handles_arbitrary_odd_and_repeated_exponents() {
    for q in [12289, 1 << 54] {
        for d in [4, 8, 16] {
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
        for d in [4, 8, 16, 64] {
            for ell in [2, 3] {
                roundtrip(d, ell, sampler);
            }
        }
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
        let error = s.phase_error(&ct, &messages).unwrap();
        assert_eq!(
            s.decrypt(&ct).unwrap(),
            messages,
            "d={d} ell={ell} sampler={sampler:?} error={error}"
        );
        assert!(error < p.q() / p.p() / 2);
        let bad = NativeSetup::new(p.clone(), [2; 32]);
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
