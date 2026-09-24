//! Criterion benches: ReinspiRING online pack vs inspiring pack_b.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use inspiring::{GadgetParams, PackingKeys, QueryPackPreprocessed, RlweParams, TopKeyImages};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use reinspiring::{pack, preprocess_from_inspiring, CompileAlgo};
use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};
use std::hint::black_box;
use std::time::Duration;

fn tiny_params() -> RlweParams {
    RlweParams::new(
        8,
        12289,
        4,
        3.2,
        GadgetParams {
            bits_per: 3,
            ell: 5,
        },
    )
    .unwrap()
}

fn bench_pack(c: &mut Criterion) {
    let params = Box::leak(Box::new(tiny_params()));
    let mut crs_raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
    for (i, coeff) in crs_raw.as_mut_slice().iter_mut().enumerate() {
        *coeff = (i as u64 * 3 + 1) % params.q;
    }
    let crs = to_ntt_alloc(&crs_raw);
    let pre = QueryPackPreprocessed::build(params, &crs).unwrap();
    let mut secret = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    secret.get_poly_mut(0, 0)[0] = 1;
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let keys = PackingKeys::generate_full(params, &to_ntt_alloc(&secret), &mut rng);
    let top = TopKeyImages::build(params);
    let b: Vec<u64> = (0..params.d).map(|i| i as u64).collect();
    let rp = preprocess_from_inspiring(&pre, 1_000_003, CompileAlgo::Fast).unwrap();

    let mut group = c.benchmark_group("pack_online");
    group.measurement_time(Duration::from_secs(3));
    group.bench_function(BenchmarkId::new("inspiring_pack_b", params.d), |ben| {
        ben.iter(|| {
            black_box(
                pre.pack_b(black_box(&b), black_box(&keys), black_box(&top))
                    .unwrap(),
            )
        });
    });
    group.bench_function(BenchmarkId::new("reinspiring_pack", params.d), |ben| {
        ben.iter(|| black_box(pack(black_box(&b), black_box(&keys), black_box(&rp)).unwrap()));
    });
    group.finish();

    eprintln!(
        "H' infinity-norm (centered) bits ≈ {:.1}",
        (rp.matrix().infinity_norm_centered() as f64).log2()
    );
}

criterion_group!(benches, bench_pack);
criterion_main!(benches);
