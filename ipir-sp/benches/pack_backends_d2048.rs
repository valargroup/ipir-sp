//! Pack-only microbench at paper ring degree `d = 2048` on the **odd**
//! NTT-friendly production modulus (byte-equal dual path).
//!
//! This is **not** the paper's ReinspiRING eval set. Paper §5.1 uses hardware-
//! native `q = 2^54`, `ℓ = 2`, `z = 2^19`. InspiRING rejects even `q`, so the
//! fair paper-params measurement lives in
//! `reinspiring` bench `paper_q254`.
//!
//! ```text
//! cargo bench -p ipir-sp --bench pack_backends_d2048
//! cargo bench -p reinspiring --bench paper_q254
//! ```

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use inspiring::{GadgetParams, PackingKeys, RlweParams, TopKeyImages};
use ipir_sp::params::SINGLE_CRT_Q;
use ipir_sp::server::{build_pack_preprocessed_blocks, pack_intermediate_blocks, CrsBlock};
use ipir_sp::{build_reinspiring_blocks, pack_intermediate_blocks_reinspiring};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};

const D: usize = 2048;
const SEED: u64 = 0x2048_0AE5;

fn paper_degree_params() -> RlweParams {
    // Paper: d=2048, σ=6.4, ℓ=2, z=2^19 with q=2^54.
    // We keep d/σ/z and use production single-CRT odd q + ℓ=3 so both backends run.
    RlweParams::new(
        D,
        SINGLE_CRT_Q,
        1 << 14,
        6.4,
        GadgetParams {
            bits_per: 19,
            ell: 3,
        },
    )
    .expect("d=2048 params")
}

fn build_crs_block(params: &RlweParams) -> CrsBlock {
    let rows = (0..params.d)
        .map(|row| {
            (0..params.d)
                .map(|col| {
                    (SEED
                        .wrapping_mul(1_000_003)
                        .wrapping_add(row as u64 * 65_537)
                        .wrapping_add(col as u64 * 17)
                        .wrapping_add(1))
                        % params.q
                })
                .collect()
        })
        .collect();
    CrsBlock { rows }
}

fn bench_pack_backends_d2048(c: &mut Criterion) {
    let params = Box::leak(Box::new(paper_degree_params()));
    eprintln!(
        "setup d=2048: q={}, ell={}, bits_per={}",
        params.q, params.gadget.ell, params.gadget.bits_per
    );

    let block = build_crs_block(params);
    eprintln!("setup: building InspiRING preprocess (1 block)");
    let t0 = Instant::now();
    let inspiring_pre =
        build_pack_preprocessed_blocks(params, &[block]).expect("inspiring preprocess");
    eprintln!("setup: InspiRING preprocess done in {:.1}s", t0.elapsed().as_secs_f64());

    eprintln!("setup: building ReinspiRING H' (Compile)…");
    let t1 = Instant::now();
    let reinspiring_pre = build_reinspiring_blocks(&inspiring_pre).expect("reinspiring preprocess");
    let compile_s = t1.elapsed().as_secs_f64();
    let h_bits = reinspiring_pre[0]
        .h_prime
        .infinity_norm_centered()
        .max(1) as f64;
    eprintln!(
        "setup: ReinspiRING ready in {:.1}s, H'_inf_bits≈{:.1}, H' entries={}",
        compile_s,
        h_bits.log2(),
        reinspiring_pre[0].h_prime.data.len()
    );

    let mut secret = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    for (i, c) in secret.get_poly_mut(0, 0).iter_mut().enumerate().take(params.d) {
        *c = match i % 3 {
            0 => 0,
            1 => 1,
            _ => params.q - 1,
        };
    }
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);
    let keys = PackingKeys::generate_full(params, &to_ntt_alloc(&secret), &mut rng);
    let top = TopKeyImages::build(params);
    let b: Vec<u64> = (0..params.d)
        .map(|i| (SEED.wrapping_mul(11).wrapping_add(i as u64 * 13)) % params.q)
        .collect();

    // Correctness smoke: one pack each must agree.
    let insp = pack_intermediate_blocks(&b, &keys, &top, &inspiring_pre).expect("inspiring");
    let rein =
        pack_intermediate_blocks_reinspiring(&b, &keys, &reinspiring_pre).expect("reinspiring");
    assert_eq!(
        insp[0].inner.as_slice(),
        rein[0].inner.as_slice(),
        "d=2048 backends must be byte-equal"
    );
    eprintln!("setup: byte-equality check passed");

    let mut group = c.benchmark_group("pack_backends_d2048");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(8));
    group.warm_up_time(Duration::from_secs(2));

    group.bench_function(BenchmarkId::new("online_pack_inspiring", D), |ben| {
        ben.iter(|| {
            black_box(
                pack_intermediate_blocks(
                    black_box(&b),
                    black_box(&keys),
                    black_box(&top),
                    black_box(&inspiring_pre),
                )
                .unwrap(),
            )
        });
    });

    group.bench_function(BenchmarkId::new("online_pack_reinspiring", D), |ben| {
        ben.iter(|| {
            black_box(
                pack_intermediate_blocks_reinspiring(
                    black_box(&b),
                    black_box(&keys),
                    black_box(&reinspiring_pre),
                )
                .unwrap(),
            )
        });
    });

    group.finish();
}

criterion_group!(benches, bench_pack_backends_d2048);
criterion_main!(benches);
