//! Phase 10 benchmarks — paper Table 5 reproduction.
//!
//! Run with:
//!
//! ```text
//! cargo bench --bench pack
//! ```
//!
//! The benchmark covers both Table 5 parameter sets and processes 4096 input
//! LWE ciphertexts per iteration by running `ceil(4096 / d)` independent
//! `InspiRING.Pack` chunks. The online benchmark reuses a precomputed CRS cache
//! exactly as the production API expects; the offline benchmark measures cache
//! construction from `(A, K_g, K_h)`.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use inspiring::automorph::{h, tau_g_pow};
use inspiring::key_switching::ks_setup;
use inspiring::{pack, GadgetParams, LweBatch, LweCiphertext, PackPreprocessed, RlweParams};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use spiral_rs::poly::{from_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw};

const TOTAL_LWES: usize = 4096;
const SIGMA_CHI: f64 = 3.2;

#[derive(Clone, Copy)]
struct BenchSpec {
    name: &'static str,
    d: usize,
    q: u64,
    p: u64,
    gadget: GadgetParams,
    seed: u64,
    paper_online_ms: f64,
    paper_key_material_kib: f64,
}

const PARAM_SET_1: BenchSpec = BenchSpec {
    name: "table5_param_set_1_d1024_q28_p6",
    d: 1024,
    q: 268_369_921,
    p: 1 << 6,
    gadget: GadgetParams {
        bits_per: 4,
        ell: 8,
    },
    seed: 0x515E_7001,
    paper_online_ms: 16.0,
    paper_key_material_kib: 60.0,
};

const PARAM_SET_2: BenchSpec = BenchSpec {
    name: "table5_param_set_2_d2048_q56_p15",
    d: 2048,
    q: 36_028_797_018_972_161,
    p: 1 << 15,
    gadget: GadgetParams {
        bits_per: 19,
        ell: 3,
    },
    seed: 0x515E_7002,
    paper_online_ms: 40.0,
    paper_key_material_kib: 84.0,
};

struct OnlineFixture {
    params: &'static RlweParams,
    s_tilde: Vec<u64>,
    chunks: Vec<ChunkFixture<'static>>,
}

struct ChunkFixture<'a> {
    batch: LweBatch,
    messages: Vec<u64>,
    pre: PackPreprocessed<'a>,
}

fn params(spec: BenchSpec) -> RlweParams {
    RlweParams::new(spec.d, spec.q, spec.p, SIGMA_CHI, spec.gadget)
        .expect("paper Table 5 parameters should be valid")
}

fn raw_from_coeffs<'a>(params: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixRaw<'a> {
    let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    raw.get_poly_mut(0, 0).copy_from_slice(coeffs);
    raw
}

fn ntt_from_coeffs<'a>(params: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixNTT<'a> {
    raw_from_coeffs(params, coeffs).ntt()
}

fn tau_coeffs(poly: &[u64], exponent: u64, q: u64) -> Vec<u64> {
    let d = poly.len();
    let mut out = vec![0; d];
    for (i, coeff) in poly.iter().enumerate() {
        let exp = (i as u64 * exponent) % (2 * d as u64);
        let reduced = coeff % q;
        let (idx, value) = if exp < d as u64 {
            (exp as usize, reduced)
        } else {
            (
                (exp - d as u64) as usize,
                if reduced == 0 { 0 } else { q - reduced },
            )
        };
        out[idx] = (out[idx] + value) % q;
    }
    out
}

fn negacyclic_mul(lhs: &[u64], rhs: &[u64], q: u64) -> Vec<u64> {
    let d = lhs.len();
    let mut out = vec![0; d];
    for (i, lhs_coeff) in lhs.iter().enumerate() {
        for (j, rhs_coeff) in rhs.iter().enumerate() {
            let product = (u128::from(*lhs_coeff) * u128::from(*rhs_coeff) % u128::from(q)) as u64;
            let degree = i + j;
            if degree < d {
                out[degree] = (out[degree] + product) % q;
            } else if product != 0 {
                out[degree - d] = (out[degree - d] + q - product) % q;
            }
        }
    }
    out
}

fn add_poly(lhs: &[u64], rhs: &[u64], q: u64) -> Vec<u64> {
    lhs.iter().zip(rhs).map(|(x, y)| (x + y) % q).collect()
}

fn centered_mod(value: u64, q: u64) -> i128 {
    if value > q / 2 {
        i128::from(value) - i128::from(q)
    } else {
        i128::from(value)
    }
}

fn deterministic_secret(params: &RlweParams, seed: u64) -> Vec<u64> {
    (0..params.d)
        .map(|idx| match (idx as u64 + seed) % 3 {
            0 => 0,
            1 => 1,
            _ => params.q - 1,
        })
        .collect()
}

fn lwe_for_message(
    params: &RlweParams,
    a: Vec<u64>,
    s_tilde: &[u64],
    message: u64,
) -> LweCiphertext {
    let inner_product = a.iter().zip(s_tilde).fold(0_u64, |acc, (ai, si)| {
        (acc + (u128::from(*ai) * u128::from(*si) % u128::from(params.q)) as u64) % params.q
    });
    let encoded = (params.delta * message) % params.q;
    let b = (params.q + encoded - inner_product) % params.q;
    LweCiphertext { a, b }
}

fn build_batch(
    params: &RlweParams,
    s_tilde: &[u64],
    spec: BenchSpec,
    chunk_idx: usize,
) -> (LweBatch, Vec<u64>) {
    let messages: Vec<_> = (0..params.d)
        .map(|row| {
            ((spec.seed as usize + chunk_idx * params.d + row * 17) % params.p as usize) as u64
        })
        .collect();
    let inner = messages
        .iter()
        .enumerate()
        .map(|(row, message)| {
            let a = (0..params.d)
                .map(|col| {
                    (spec.seed
                        + chunk_idx as u64 * 1_000_003
                        + row as u64 * 65_537
                        + col as u64 * 257)
                        % params.q
                })
                .collect();
            lwe_for_message(params, a, s_tilde, *message)
        })
        .collect();
    (LweBatch { inner }, messages)
}

fn crs_from_batch<'a>(params: &'a RlweParams, batch: &LweBatch) -> PolyMatrixNTT<'a> {
    let mut crs = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
    for (row, ct) in batch.inner.iter().enumerate() {
        crs.get_poly_mut(row, 0).copy_from_slice(&ct.a);
    }
    crs.ntt()
}

fn build_chunk<'a>(
    params: &'a RlweParams,
    s_tilde: &[u64],
    spec: BenchSpec,
    chunk_idx: usize,
) -> ChunkFixture<'a> {
    let (batch, messages) = build_batch(params, s_tilde, spec, chunk_idx);
    let crs = crs_from_batch(params, &batch);
    let tau_g_s = tau_coeffs(s_tilde, tau_g_pow(1, params.d), params.q);
    let tau_h_s = tau_coeffs(s_tilde, h(params.d), params.q);
    let mut rng = ChaCha20Rng::seed_from_u64(spec.seed + chunk_idx as u64);
    let kg = ks_setup(
        params,
        &ntt_from_coeffs(params, &tau_g_s),
        &ntt_from_coeffs(params, s_tilde),
        &mut rng,
    );
    let kh = ks_setup(
        params,
        &ntt_from_coeffs(params, &tau_h_s),
        &ntt_from_coeffs(params, s_tilde),
        &mut rng,
    );
    let pre = PackPreprocessed::build(params, &crs, &kg, &kh).expect("valid preprocessing");

    ChunkFixture {
        batch,
        messages,
        pre,
    }
}

fn build_online_fixture(spec: BenchSpec) -> OnlineFixture {
    let params = Box::leak(Box::new(params(spec)));
    let s_tilde = deterministic_secret(params, spec.seed);
    let chunk_count = TOTAL_LWES / params.d;
    let chunks = (0..chunk_count)
        .map(|chunk_idx| build_chunk(params, &s_tilde, spec, chunk_idx))
        .collect();
    OnlineFixture {
        params,
        s_tilde,
        chunks,
    }
}

fn preprocess_all_chunks(spec: BenchSpec) -> usize {
    let params = params(spec);
    let s_tilde = deterministic_secret(&params, spec.seed);
    let chunk_count = TOTAL_LWES / params.d;
    let chunks: Vec<_> = (0..chunk_count)
        .map(|chunk_idx| build_chunk(&params, &s_tilde, spec, chunk_idx))
        .collect();
    chunks
        .iter()
        .filter(|chunk| chunk.pre.collapse_a_final_ntt.rows == 1)
        .count()
}

fn noise_inf_norm(fixture: &OnlineFixture) -> i128 {
    let mut max = 0_i128;
    for chunk in &fixture.chunks {
        let packed = pack(&chunk.batch, &chunk.pre).expect("pack succeeds");
        let raw = from_ntt_alloc(&packed.inner);
        let phase = add_poly(
            raw.get_poly(1, 0),
            &negacyclic_mul(raw.get_poly(0, 0), &fixture.s_tilde, fixture.params.q),
            fixture.params.q,
        );
        for (actual, message) in phase.iter().zip(&chunk.messages) {
            let encoded = (fixture.params.delta * message) % fixture.params.q;
            let noise = centered_mod(
                (fixture.params.q + actual - encoded) % fixture.params.q,
                fixture.params.q,
            )
            .abs();
            max = max.max(noise);
        }
    }
    max
}

fn packing_key_bytes(spec: BenchSpec) -> usize {
    // Two base KS matrices, each `[2 x ell]` polynomials of `d` u64 limbs.
    2 * 2 * spec.gadget.ell * spec.d * std::mem::size_of::<u64>()
}

fn packed_ciphertext_bytes(spec: BenchSpec) -> usize {
    2 * spec.d * std::mem::size_of::<u64>()
}

fn bench_spec(c: &mut Criterion, spec: BenchSpec) {
    let fixture = build_online_fixture(spec);
    eprintln!(
        "{}: chunks={}, raw_key={} KiB (paper {} KiB), ct={} KiB, observed ||e||_inf={}, paper_online={} ms",
        spec.name,
        fixture.chunks.len(),
        packing_key_bytes(spec) / 1024,
        spec.paper_key_material_kib,
        packed_ciphertext_bytes(spec) / 1024,
        noise_inf_norm(&fixture),
        spec.paper_online_ms,
    );

    let mut group = c.benchmark_group(spec.name);
    group.sample_size(10);

    group.bench_function(BenchmarkId::new("offline_preprocess", TOTAL_LWES), |b| {
        b.iter_batched(
            || spec,
            |spec| black_box(preprocess_all_chunks(spec)),
            BatchSize::SmallInput,
        );
    });

    group.bench_function(BenchmarkId::new("online_pack", TOTAL_LWES), |b| {
        b.iter(|| {
            for chunk in &fixture.chunks {
                black_box(
                    pack(black_box(&chunk.batch), black_box(&chunk.pre)).expect("pack succeeds"),
                );
            }
        });
    });

    group.finish();
}

fn pack_table5(c: &mut Criterion) {
    bench_spec(c, PARAM_SET_1);
    bench_spec(c, PARAM_SET_2);
}

criterion_group!(benches, pack_table5);
criterion_main!(benches);
