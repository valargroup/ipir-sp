//! Paper-eval ReinspiRING hot path at hardware-native `q = 2^54`.
//!
//! ReinsPIRe §5.1 / Table 5: `d=2048`, `q=2^54`, `σ=6.4`, `ℓ=2`, `z=2^19`.
//! Paper reports `H'·y ≈ 1.2 ms` (and full Pack ≈ 13.6 ms) for `ℓ=2`.
//!
//! This microbench measures the coefficient matvec under that modulus (free
//! reduction via bitmask). Full online Pack also needs lifted-NTT leftover
//! (`Q > d q²`); that path is still schoolbook here and is timed separately.
//!
//! InspiRING cannot use even `q` (`d^{-1} mod q`), so this is not a dual-backend
//! byte-equal run — it is the paper's intended ReinspiRING parameter set.
//!
//! ```text
//! cargo bench -p reinspiring --bench paper_q254
//! ```

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use reinspiring::compile::{collapse_kg_exponents, compile_fast};
use reinspiring::lift_ntt::leftover_sum;
use reinspiring::matrix::PackingMatrix;
use reinspiring::params::{GadgetParams, ReinspiringParams};

const D: usize = 2048;
const Q: u64 = 1 << 54;
const ELL: usize = 2;
const BITS_PER: u32 = 19;
/// Paper Table 5 target for `H'·y` at `ℓ=2`.
const PAPER_H_PRIME_Y_MS: f64 = 1.2;

fn paper_params() -> ReinspiringParams {
    // lift_q is unused on the schoolbook leftover path; any odd prime works.
    ReinspiringParams::new(
        D,
        Q,
        1 << 14,
        GadgetParams {
            bits_per: BITS_PER,
            ell: ELL,
        },
        12289,
    )
    .expect("paper q=2^54 params")
}

fn random_digit_limb(seed: u64, d: usize, z: u64) -> Vec<u64> {
    (0..d)
        .map(|i| {
            seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(i as u64 * 0x85EB_CA6B)
                % z
        })
        .collect()
}

fn build_h_prime(params: &ReinspiringParams) -> PackingMatrix {
    use rayon::prelude::*;
    let d = params.d;
    let z = params.gadget.z();
    let exponents = collapse_kg_exponents(d);
    let steps = d - 2;
    let blocks: Vec<_> = (0..params.gadget.ell)
        .into_par_iter()
        .map(|limb| {
            let ts: Vec<Vec<u64>> = (0..steps)
                .map(|step| {
                    random_digit_limb(
                        0x54_u64
                            .wrapping_mul(1_000_003)
                            .wrapping_add(limb as u64 * 17)
                            .wrapping_add(step as u64),
                        d,
                        z,
                    )
                })
                .collect();
            compile_fast(&ts, &exponents, params.q).expect("compile_fast")
        })
        .collect();
    PackingMatrix::hstack(&blocks).expect("hstack")
}

fn bench_paper_q254(c: &mut Criterion) {
    let params = paper_params();
    assert!(params.q.is_power_of_two());
    assert_eq!(params.q, 1 << 54);
    assert_eq!(params.gadget.ell, 2);

    eprintln!(
        "paper params: d={}, q=2^{}, ell={}, z=2^{}",
        params.d,
        params.q.trailing_zeros(),
        params.gadget.ell,
        params.gadget.bits_per
    );
    eprintln!("building H' via Compile (ℓ={} limbs)…", params.gadget.ell);
    let t0 = std::time::Instant::now();
    let h_prime = build_h_prime(&params);
    let compile_s = t0.elapsed().as_secs_f64();
    let h_bits = h_prime.infinity_norm_centered().max(1) as f64;
    eprintln!(
        "Compile done in {:.1}s, H'_inf_bits≈{:.1}, shape {}×{}",
        compile_s,
        h_bits.log2(),
        h_prime.rows,
        h_prime.cols
    );

    let y: Vec<u64> = (0..h_prime.cols)
        .map(|i| (0x54E5_u64.wrapping_mul(11).wrapping_add(i as u64 * 13)) % params.q)
        .collect();
    let mut out = vec![0u64; h_prime.rows];
    h_prime.matvec(&y, &mut out).expect("matvec");

    let t_pp: Vec<Vec<u64>> = (0..ELL)
        .map(|j| random_digit_limb(0x7000 + j as u64, D, params.gadget.z()))
        .collect();
    let y_prime: Vec<Vec<u64>> = (0..ELL)
        .map(|j| {
            (0..D)
                .map(|i| (0x9000_u64 + j as u64 * 1009 + i as u64 * 17) % params.q)
                .collect()
        })
        .collect();
    let _ = leftover_sum(&t_pp, &y_prime, params.q).expect("leftover");

    let mut group = c.benchmark_group("paper_q254");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(8));
    group.warm_up_time(Duration::from_secs(2));

    group.bench_function(BenchmarkId::new("h_prime_matvec", D), |ben| {
        ben.iter(|| {
            let mut out = vec![0u64; h_prime.rows];
            h_prime
                .matvec(black_box(&y), black_box(&mut out))
                .unwrap();
            black_box(out)
        });
    });

    group.bench_function(BenchmarkId::new("leftover_schoolbook", D), |ben| {
        ben.iter(|| {
            black_box(leftover_sum(black_box(&t_pp), black_box(&y_prime), black_box(params.q)).unwrap())
        });
    });

    group.finish();
    eprintln!(
        "paper Table 5 target H'·y ≈ {PAPER_H_PRIME_Y_MS} ms (ℓ=2, z=2^19, q=2^54)"
    );
}

criterion_group!(benches, bench_paper_q254);
criterion_main!(benches);
