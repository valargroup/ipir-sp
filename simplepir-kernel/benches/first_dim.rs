//! First-dimension kernel benchmark at the production nullifier shape.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p simplepir-kernel --bench first_dim
//! ```
//!
//! This measures the SimplePIR matrix-vector product on its own, without the
//! surrounding PIR fixture, so the kernel can be profiled without paying for
//! offline preprocessing. Set `RAYON_NUM_THREADS=1` to compare against the
//! serial path.
//!
//! `SIMPLEPIR_BENCH_SMALL=1` selects a shape that fits comfortably on a laptop.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use inspiring::{GadgetParams, RlweParams};
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use simplepir_kernel::{ChunkedSplitKernel, FirstDimKernel};

/// Production nullifier shape: 49,925,853 records at 448 per row, 4 instances.
const ROWS: usize = 112_640;
const COLS: usize = 8_192;

const SMALL_ROWS: usize = 28_672;
const SMALL_COLS: usize = 2_048;

fn production_like_rlwe() -> RlweParams {
    RlweParams::new(
        2048,
        72_057_594_037_641_217,
        1 << 14,
        6.4,
        GadgetParams {
            bits_per: 19,
            ell: 3,
        },
    )
    .expect("valid production-like params")
}

fn bench_first_dim(c: &mut Criterion) {
    let (rows, cols) = if std::env::var_os("SIMPLEPIR_BENCH_SMALL").is_some() {
        (SMALL_ROWS, SMALL_COLS)
    } else {
        (ROWS, COLS)
    };

    let rlwe = production_like_rlwe();
    let mut rng = ChaCha20Rng::seed_from_u64(0x5950_4952_5350);

    eprintln!(
        "simplepir-kernel first_dim fixture: {rows}x{cols}, db={:.2} GB, threads={}",
        (rows * cols * 2) as f64 / 1e9,
        rayon::current_num_threads(),
    );

    let db: Vec<u16> = (0..rows * cols)
        .map(|_| rng.gen_range(0..(1 << 14)))
        .collect();
    let query: Vec<u64> = (0..rows).map(|_| rng.gen_range(0..rlwe.q)).collect();
    let mut out = vec![0u64; cols];

    let mut group = c.benchmark_group("first_dim");
    group.sample_size(10);

    let kernel = ChunkedSplitKernel::default();
    group.bench_function(
        BenchmarkId::new("chunked_split", format!("{rows}x{cols}")),
        |b| {
            b.iter(|| {
                kernel.multiply_query(
                    &rlwe,
                    black_box(&db),
                    rows,
                    cols,
                    black_box(&query),
                    black_box(&mut out),
                );
            });
        },
    );

    #[cfg(target_arch = "x86_64")]
    if simplepir_kernel::U16Avx512Kernel::is_supported() {
        let kernel = simplepir_kernel::U16Avx512Kernel::default();
        group.bench_function(
            BenchmarkId::new("avx512_u16", format!("{rows}x{cols}")),
            |b| {
                b.iter(|| {
                    kernel.multiply_query(
                        &rlwe,
                        black_box(&db),
                        rows,
                        cols,
                        black_box(&query),
                        black_box(&mut out),
                    );
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_first_dim);
criterion_main!(benches);
