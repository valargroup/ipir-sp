//! Phase 8 benchmark for the IPIR-SP-on-InspiRING integration.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p ipir-sp --bench end_to_end
//! ```
//!
//! By default the fixture uses a smaller `d = 64` shape that runs on ordinary
//! development machines. Set `IPIR_SP_BENCH_MID=1` for a `d = 1024` profile,
//! or `IPIR_SP_BENCH_FULL=1` to attempt the headline YPIR command shape:
//! `cargo run --release -- 32768 131072`.
//!
//! The SimplePIR first-dimension multiply is benchmarked separately from the
//! InspiRING packing boundary so changes to the DB/query kernel are visible.

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use ipir_sp::client::{ClientSecret, IPIRClient, IPIRSimpleQuery};
use ipir_sp::modulus_switch::{serialize_rlwe_response, switched_rlwe_response_len};
use ipir_sp::params::{
    params_for_simplepir, PLAINTEXT_MODULUS, Q_PRIME_1, Q_PRIME_2, SINGLE_CRT_Q,
};
use ipir_sp::serialize::{serialize_packing_keys, serialize_u64s_le, serialized_packing_keys_len};
use ipir_sp::server::{
    build_pack_preprocessed_blocks, offline_precompute_from_hint, pack_intermediate_blocks,
};
use ipir_sp::YpirSchemeParams;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use simplepir_kernel::{ChunkedSplitKernel, FirstDimKernel, ScalarKernel};
use spiral_rs::poly::{from_ntt_alloc, PolyMatrix};

use inspiring::{GadgetParams, PackingKeys, QueryPackPreprocessed, RlweParams, TopKeyImages};

const NUM_ITEMS: u64 = 32_768;
const ITEM_SIZE_BITS: u64 = 131_072;
const SEED: u64 = 0x5950_4952_5350;
const YPIR_CDKS_UPLOAD_KIB: usize = 462;
const YPIR_CDKS_ONLINE_MS: f64 = 55.6;
const INSPIRING_PAPER_NOISE_BITS: f64 = 33.4;

#[derive(Clone, Copy)]
struct BenchSpec {
    name: &'static str,
    rows: usize,
    item_size_bits: u64,
    degree: usize,
    q: u64,
    p: u64,
    sigma: f64,
    gadget: GadgetParams,
    q_prime_1: u64,
    q_prime_2: u64,
}

struct BenchFixture<'a> {
    name: &'static str,
    rlwe: &'a RlweParams,
    ypir: YpirSchemeParams,
    secret: ClientSecret,
    packing_keys: PackingKeys<'a>,
    top_keys: TopKeyImages<'a>,
    intermediate: Vec<u64>,
    first_dim_db: Vec<u16>,
    first_dim_query: Vec<u64>,
    preprocessed: Vec<QueryPackPreprocessed<'a>>,
    noise_bits: u32,
}

struct UploadMeasurements {
    packing_keys_bytes: usize,
    offline_query_polys_bytes: usize,
    online_query_packed_bytes: usize,
}

impl UploadMeasurements {
    fn fresh_query_total_bytes(&self) -> usize {
        self.packing_keys_bytes + self.offline_query_polys_bytes + self.online_query_packed_bytes
    }
}

const SMALL_SPEC: BenchSpec = BenchSpec {
    name: "ipir_sp_smaller_d64_64_128",
    rows: 64,
    item_size_bits: 128,
    degree: 64,
    q: 12_289,
    p: 4,
    sigma: 3.2,
    gadget: GadgetParams {
        bits_per: 3,
        ell: 5,
    },
    q_prime_1: 16,
    q_prime_2: 257,
};

const MID_SPEC: BenchSpec = BenchSpec {
    name: "ipir_sp_mid_d1024_1024_128",
    rows: 1024,
    item_size_bits: 128,
    degree: 1024,
    q: 268_369_921,
    p: 64,
    sigma: 3.2,
    gadget: GadgetParams {
        bits_per: 4,
        ell: 8,
    },
    q_prime_1: 16,
    q_prime_2: 257,
};

fn deterministic_secret(params: &RlweParams) -> ClientSecret {
    let coeffs: Vec<_> = (0..params.d)
        .map(|idx| match (idx + SEED as usize) % 3 {
            0 => 0,
            1 => 1,
            _ => params.q - 1,
        })
        .collect();
    ClientSecret::from_coeffs(params, coeffs)
}

fn deterministic_a(params: &RlweParams, column: usize, coeff: usize) -> u64 {
    (SEED + column as u64 * 1_000_003 + coeff as u64 * 65_537) % params.q
}

fn full_spec() -> BenchSpec {
    BenchSpec {
        name: "ipir_sp_32768_131072",
        rows: NUM_ITEMS as usize,
        item_size_bits: ITEM_SIZE_BITS,
        degree: 2048,
        q: SINGLE_CRT_Q,
        p: PLAINTEXT_MODULUS,
        sigma: 6.4,
        gadget: GadgetParams {
            bits_per: 19,
            ell: 3,
        },
        q_prime_1: Q_PRIME_1,
        q_prime_2: Q_PRIME_2,
    }
}

fn selected_spec() -> BenchSpec {
    if std::env::var_os("IPIR_SP_BENCH_FULL").is_some() {
        full_spec()
    } else if std::env::var_os("IPIR_SP_BENCH_MID").is_some() {
        MID_SPEC
    } else {
        SMALL_SPEC
    }
}

fn seed_from_u64(value: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    seed
}

fn params_for_spec(spec: BenchSpec) -> (RlweParams, YpirSchemeParams) {
    if spec.degree == 2048 && spec.rows as u64 == NUM_ITEMS && spec.item_size_bits == ITEM_SIZE_BITS
    {
        return params_for_simplepir(NUM_ITEMS, ITEM_SIZE_BITS).expect("target params are valid");
    }

    let rlwe = RlweParams::new(spec.degree, spec.q, spec.p, spec.sigma, spec.gadget)
        .expect("benchmark params are valid");
    let instances = (spec.item_size_bits as usize)
        .div_ceil(spec.degree * 2)
        .max(1);
    let ypir = YpirSchemeParams {
        num_items: spec.rows as u64,
        item_size_bits: spec.item_size_bits,
        poly_len: spec.degree,
        db_dim_1: 0,
        db_dim_2: 1,
        instances,
        db_rows: spec.rows,
        db_cols: instances * spec.degree,
        p: spec.p,
        q_prime_1: spec.q_prime_1,
        q_prime_2: spec.q_prime_2,
        q2_bits: (u64::BITS - (spec.q_prime_2 - 1).leading_zeros()) as usize,
        t_exp_left: 3,
        t_exp_right: 2,
    };

    (rlwe, ypir)
}

fn encrypted_fixture_material(
    rlwe: &RlweParams,
    ypir: &YpirSchemeParams,
    secret: &ClientSecret,
) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let mut hint_0 = vec![0_u64; rlwe.d * ypir.db_cols];
    let mut intermediate = vec![0_u64; ypir.db_cols];
    let mut messages = vec![0_u64; ypir.db_cols];

    for column in 0..ypir.db_cols {
        let message = ((SEED as usize + column * 17) % ypir.p as usize) as u64;
        let mut inner_product = 0_u64;

        for coeff in 0..rlwe.d {
            let a = deterministic_a(rlwe, column, coeff);
            hint_0[coeff * ypir.db_cols + column] = a;
            inner_product = ((u128::from(inner_product)
                + u128::from(a) * u128::from(secret.coeffs[coeff]))
                % u128::from(rlwe.q)) as u64;
        }

        messages[column] = message;
        intermediate[column] = (rlwe.q + (rlwe.delta * message) % rlwe.q - inner_product) % rlwe.q;
    }

    (hint_0, intermediate, messages)
}

fn simplepir_multiply_fixture(rlwe: &RlweParams, ypir: &YpirSchemeParams) -> (Vec<u16>, Vec<u64>) {
    let db = (0..ypir.db_cols)
        .flat_map(|col| {
            (0..ypir.db_rows).map(move |row| {
                ((SEED + col as u64 * 1_000_003 + row as u64 * 65_537) % ypir.p) as u16
            })
        })
        .collect();
    let query = (0..ypir.db_rows)
        .map(|row| (SEED + row as u64 * 4_294_967_291) % rlwe.q)
        .collect();

    (db, query)
}

fn build_preprocessed<'a>(
    rlwe: &'a RlweParams,
    ypir: &YpirSchemeParams,
    hint_0: Vec<u64>,
) -> Vec<QueryPackPreprocessed<'a>> {
    eprintln!("setup: extracting CRS blocks from hint");
    let offline = offline_precompute_from_hint(rlwe, ypir, hint_0);
    eprintln!("setup: extracted {} CRS block(s)", offline.crs_blocks.len());
    eprintln!("setup: building pack preprocessing cache");
    let preprocessed = build_pack_preprocessed_blocks(rlwe, &offline.crs_blocks)
        .expect("benchmark preprocessing builds");
    eprintln!("setup: pack preprocessing cache built");

    // `crs_blocks` and `hint_0` are no longer needed after public packing
    // preprocessing has absorbed them. Drop promptly so the online fixture keeps
    // only the long-lived cache and `b` values.
    drop(offline);
    preprocessed
}

fn build_fixture() -> BenchFixture<'static> {
    let spec = selected_spec();
    eprintln!(
        "setup: selected profile={}, rows={}, item_bits={}, d={}",
        spec.name, spec.rows, spec.item_size_bits, spec.degree
    );
    let (rlwe, ypir) = params_for_spec(spec);
    let rlwe = Box::leak(Box::new(rlwe));
    eprintln!(
        "setup: params ready, outputs={}, db_cols={}",
        ypir.db_cols / rlwe.d,
        ypir.db_cols
    );
    let secret = deterministic_secret(rlwe);
    eprintln!("setup: generating deterministic fixture material");
    let (hint_0, intermediate, messages) = encrypted_fixture_material(rlwe, &ypir, &secret);
    eprintln!("setup: deterministic fixture material ready");
    eprintln!("setup: generating SimplePIR multiply fixture");
    let (first_dim_db, first_dim_query) = simplepir_multiply_fixture(rlwe, &ypir);
    eprintln!("setup: SimplePIR multiply fixture ready");
    let preprocessed = build_preprocessed(rlwe, &ypir, hint_0);
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);
    let packing_keys = PackingKeys::generate_full(rlwe, &secret.to_ntt(rlwe), &mut rng);
    let top_keys = TopKeyImages::build(rlwe);
    eprintln!("setup: checking deterministic noise");
    let noise = noise_inf_norm(
        rlwe,
        &secret,
        &intermediate,
        &messages,
        &packing_keys,
        &top_keys,
        &preprocessed,
    );
    eprintln!("setup: deterministic noise checked");
    drop(messages);

    BenchFixture {
        name: spec.name,
        rlwe,
        ypir,
        secret,
        packing_keys,
        top_keys,
        intermediate,
        first_dim_db,
        first_dim_query,
        preprocessed,
        noise_bits: log2_ceil(noise),
    }
}

fn negacyclic_mul(lhs: &[u64], rhs: &[u64], q: u64) -> Vec<u64> {
    let d = lhs.len();
    let mut out = vec![0_u64; d];
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

fn centered_abs(value: u64, q: u64) -> u128 {
    if value > q / 2 {
        u128::from(q - value)
    } else {
        u128::from(value)
    }
}

fn noise_inf_norm(
    rlwe: &RlweParams,
    secret: &ClientSecret,
    intermediate: &[u64],
    messages: &[u64],
    packing_keys: &PackingKeys<'_>,
    top_keys: &TopKeyImages<'_>,
    preprocessed: &[QueryPackPreprocessed<'_>],
) -> u128 {
    let packed = pack_intermediate_blocks(intermediate, packing_keys, top_keys, preprocessed)
        .expect("online pack succeeds");
    let mut max = 0_u128;

    for (block_idx, ct) in packed.iter().enumerate() {
        let raw = from_ntt_alloc(&ct.inner);
        let phase = add_poly(
            raw.get_poly(1, 0),
            &negacyclic_mul(raw.get_poly(0, 0), &secret.coeffs, rlwe.q),
            rlwe.q,
        );

        let message_start = block_idx * rlwe.d;
        for (coeff, message) in phase
            .iter()
            .zip(&messages[message_start..message_start + rlwe.d])
        {
            let expected = (rlwe.delta * *message) % rlwe.q;
            let error = (rlwe.q + *coeff - expected) % rlwe.q;
            max = max.max(centered_abs(error, rlwe.q));
        }
    }

    drop(packed);
    max
}

fn log2_ceil(value: u128) -> u32 {
    if value <= 1 {
        0
    } else {
        u128::BITS - (value - 1).leading_zeros()
    }
}

fn measure_uploads(fixture: &BenchFixture<'_>) -> UploadMeasurements {
    let client = IPIRClient::new(fixture.rlwe, &fixture.ypir);
    let offline_query_polys =
        client.generate_public_query_setup_simplepir_from_seed(seed_from_u64(SEED));
    let packing_keys_bytes = serialize_packing_keys(fixture.rlwe, &fixture.packing_keys)
        .expect("packing keys serialize")
        .len();
    let offline_query_polys_bytes = offline_query_polys
        .iter()
        .map(|poly| serialize_u64s_le(poly).len())
        .sum();
    let online_query = IPIRSimpleQuery::new(fixture.first_dim_query.clone());
    let online_query_packed_bytes = online_query.to_packed_bytes(fixture.rlwe.q).len();

    UploadMeasurements {
        packing_keys_bytes,
        offline_query_polys_bytes,
        online_query_packed_bytes,
    }
}

fn measure_server_breakdown_once(
    fixture: &BenchFixture<'_>,
    packed_query_body: &[u8],
    packed_fixture: &[inspiring::RlweCiphertext<'_>],
) -> (Duration, Duration, Duration, Duration) {
    let deserialize_started = Instant::now();
    let first_dim_query =
        IPIRSimpleQuery::from_packed_bytes(packed_query_body, fixture.ypir.db_rows, fixture.rlwe.q)
            .expect("packed query deserializes")
            .as_slice()
            .to_vec();
    let deserialize_time = deserialize_started.elapsed();

    let multiply_started = Instant::now();
    let kernel = ChunkedSplitKernel::default();
    let mut intermediate = vec![0u64; fixture.ypir.db_cols];
    kernel.multiply_query(
        fixture.rlwe,
        &fixture.first_dim_db,
        fixture.ypir.db_rows,
        fixture.ypir.db_cols,
        &first_dim_query,
        &mut intermediate,
    );
    let multiply_time = multiply_started.elapsed();

    let packing_started = Instant::now();
    let packed = pack_intermediate_blocks(
        &intermediate,
        &fixture.packing_keys,
        &fixture.top_keys,
        &fixture.preprocessed,
    )
    .expect("online pack succeeds");
    black_box(&packed);
    let packing_time = packing_started.elapsed();

    let serialization_started = Instant::now();
    black_box(serialize_rlwe_response(
        packed_fixture,
        fixture.ypir.q_prime_1,
        fixture.ypir.q_prime_2,
    ));
    let serialization_time = serialization_started.elapsed();

    (
        deserialize_time,
        multiply_time,
        packing_time,
        serialization_time,
    )
}

fn bench_end_to_end(c: &mut Criterion) {
    let fixture = build_fixture();
    let output_count = fixture.preprocessed.len();
    let response_bytes = output_count
        * switched_rlwe_response_len(
            fixture.rlwe.d,
            fixture.ypir.q_prime_1,
            fixture.ypir.q_prime_2,
        );
    let packed_fixture = pack_intermediate_blocks(
        &fixture.intermediate,
        &fixture.packing_keys,
        &fixture.top_keys,
        &fixture.preprocessed,
    )
    .expect("fixture online pack succeeds");
    let upload_measurements = measure_uploads(&fixture);
    let packed_query_body =
        IPIRSimpleQuery::new(fixture.first_dim_query.clone()).to_packed_bytes(fixture.rlwe.q);
    let client = IPIRClient::new(fixture.rlwe, &fixture.ypir);
    let client_seed = seed_from_u64(SEED);
    let response_fixture = serialize_rlwe_response(
        &packed_fixture,
        fixture.ypir.q_prime_1,
        fixture.ypir.q_prime_2,
    );
    let (deserialize_once, multiply_once, packing_once, serialization_once) =
        measure_server_breakdown_once(&fixture, &packed_query_body, &packed_fixture);

    eprintln!(
        "ipir-sp target: profile={}, rows={}, item_bits={}, d={}, outputs={}, db_cols={}, serialized_packing_keys={} KiB, measured_packing_keys={} KiB, measured_offline_query_polys={} KiB, measured_online_query_packed={} KiB, measured_fresh_query_upload={} KiB, cdks_upload={} KiB, response={} KiB, ||e_pack||_inf_bits={}, paper_noise_target_bits<={:.1}, cdks_online_target={} ms",
        fixture.name,
        fixture.ypir.db_rows,
        fixture.ypir.item_size_bits,
        fixture.rlwe.d,
        output_count,
        fixture.ypir.db_cols,
        serialized_packing_keys_len(fixture.rlwe) / 1024,
        upload_measurements.packing_keys_bytes / 1024,
        upload_measurements.offline_query_polys_bytes / 1024,
        upload_measurements.online_query_packed_bytes / 1024,
        upload_measurements.fresh_query_total_bytes() / 1024,
        YPIR_CDKS_UPLOAD_KIB,
        response_bytes / 1024,
        fixture.noise_bits,
        INSPIRING_PAPER_NOISE_BITS,
        YPIR_CDKS_ONLINE_MS,
    );
    eprintln!(
        "ipir-sp measured_upload_bytes: packing_keys={} offline_query_polys={} online_query_packed={} fresh_query_total={} current_http_query={}",
        upload_measurements.packing_keys_bytes,
        upload_measurements.offline_query_polys_bytes,
        upload_measurements.online_query_packed_bytes,
        upload_measurements.fresh_query_total_bytes(),
        upload_measurements.online_query_packed_bytes,
    );
    eprintln!(
        "ipir-sp one_shot_server_breakdown_us: deserialize={} matrix_vector={} packing={} serialization={}",
        deserialize_once.as_micros(),
        multiply_once.as_micros(),
        packing_once.as_micros(),
        serialization_once.as_micros(),
    );

    let mut group = c.benchmark_group(fixture.name);
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    group.bench_function(BenchmarkId::new("online_deserialize_query_only", 1), |b| {
        b.iter(|| {
            let query = IPIRSimpleQuery::from_packed_bytes(
                black_box(&packed_query_body),
                fixture.ypir.db_rows,
                fixture.rlwe.q,
            )
            .expect("packed query deserializes");
            black_box(query);
        });
    });

    group.bench_function(
        BenchmarkId::new(
            "multiply_query_only_scalar",
            format!("{}x{}", fixture.ypir.db_rows, fixture.ypir.db_cols),
        ),
        |b| {
            let kernel = ScalarKernel;
            let mut out = vec![0u64; fixture.ypir.db_cols];
            b.iter(|| {
                kernel.multiply_query(
                    fixture.rlwe,
                    black_box(&fixture.first_dim_db),
                    fixture.ypir.db_rows,
                    fixture.ypir.db_cols,
                    black_box(&fixture.first_dim_query),
                    black_box(&mut out),
                );
            });
        },
    );

    group.bench_function(
        BenchmarkId::new(
            "multiply_query_only_chunked_split",
            format!("{}x{}", fixture.ypir.db_rows, fixture.ypir.db_cols),
        ),
        |b| {
            let kernel = ChunkedSplitKernel::default();
            let mut out = vec![0u64; fixture.ypir.db_cols];
            b.iter(|| {
                kernel.multiply_query(
                    fixture.rlwe,
                    black_box(&fixture.first_dim_db),
                    fixture.ypir.db_rows,
                    fixture.ypir.db_cols,
                    black_box(&fixture.first_dim_query),
                    black_box(&mut out),
                );
            });
        },
    );

    if std::env::var_os("IPIR_SP_SKIP_OFFLINE_BENCH").is_none() {
        group.bench_function(
            BenchmarkId::new("offline_crs_extract_and_preprocess", output_count),
            |b| {
                b.iter_batched(
                    || {
                        let (hint_0, _, messages) = encrypted_fixture_material(
                            fixture.rlwe,
                            &fixture.ypir,
                            &fixture.secret,
                        );
                        drop(messages);
                        hint_0
                    },
                    |hint_0| {
                        let offline =
                            offline_precompute_from_hint(fixture.rlwe, &fixture.ypir, hint_0);
                        let preprocessed_len = black_box(
                            build_pack_preprocessed_blocks(fixture.rlwe, &offline.crs_blocks)
                                .expect("benchmark preprocessing builds")
                                .len(),
                        );
                        drop(offline);
                        preprocessed_len
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }

    group.bench_function(BenchmarkId::new("online_pack_only", output_count), |b| {
        b.iter(|| {
            let packed = pack_intermediate_blocks(
                black_box(&fixture.intermediate),
                black_box(&fixture.packing_keys),
                black_box(&fixture.top_keys),
                black_box(&fixture.preprocessed),
            )
            .expect("online pack succeeds");
            black_box(&packed);
            drop(packed);
        });
    });

    group.bench_function(
        BenchmarkId::new("online_serialize_only", output_count),
        |b| {
            b.iter(|| {
                black_box(serialize_rlwe_response(
                    black_box(&packed_fixture),
                    fixture.ypir.q_prime_1,
                    fixture.ypir.q_prime_2,
                ));
            });
        },
    );

    group.bench_function(
        BenchmarkId::new("online_pack_and_serialize", output_count),
        |b| {
            b.iter(|| {
                let packed = pack_intermediate_blocks(
                    black_box(&fixture.intermediate),
                    black_box(&fixture.packing_keys),
                    black_box(&fixture.top_keys),
                    black_box(&fixture.preprocessed),
                )
                .expect("online pack succeeds");
                black_box(serialize_rlwe_response(
                    &packed,
                    fixture.ypir.q_prime_1,
                    fixture.ypir.q_prime_2,
                ));
                drop(packed);
            });
        },
    );

    group.bench_function(BenchmarkId::new("client_decode_only", output_count), |b| {
        b.iter(|| {
            black_box(client.decode_response_simplepir_raw(
                black_box(client_seed),
                black_box(&response_fixture),
            ));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_end_to_end);
criterion_main!(benches);
