//! Client-only decode benchmarks that avoid server preprocessing.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ipir_sp::bits::u64s_to_contiguous_bytes;
use ipir_sp::client::IPIRClient;
use ipir_sp::modulus_switch::modulus_bits;
use ipir_sp::modulus_switch::{rescale, response_body_len};

const NULLIFIER_ITEM_BITS: u64 = 2048 * 14;
const HEADLINE_ITEM_BITS: u64 = 131_072;

fn seed_from_u64(value: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    seed
}

/// `(published c1 rows, response bodies)` for a synthetic answer.
///
/// The response carries only `c2`; `c1` is the snapshot constant the client
/// fetches once from `/public-params`, so the benchmark supplies it separately.
fn synthetic_response(client: &IPIRClient) -> (Vec<Vec<u64>>, Vec<u8>) {
    let rlwe = client.rlwe_params();
    let ypir = client.params();
    let output_count = ypir.db_cols / rlwe.d;
    let mut published_c1 = Vec::with_capacity(output_count);
    let mut response = Vec::with_capacity(output_count * response_body_len(rlwe.d, ypir.q_prime_1));

    for output_idx in 0..output_count {
        published_c1.push(
            (0..rlwe.d)
                .map(|coeff_idx| {
                    (17 + output_idx as u64 * 1_000_003 + coeff_idx as u64 * 65_537) % rlwe.q
                })
                .collect(),
        );
        let row_1: Vec<_> = (0..rlwe.d)
            .map(|coeff_idx| {
                let value =
                    (29 + output_idx as u64 * 4_294_967_291 + coeff_idx as u64 * 131_071) % rlwe.q;
                rescale(value, rlwe.q, ypir.q_prime_1)
            })
            .collect();
        response.extend_from_slice(&u64s_to_contiguous_bytes(
            &row_1,
            modulus_bits(ypir.q_prime_1),
        ));
    }

    (published_c1, response)
}

fn bench_decode(c: &mut Criterion) {
    let cases = [
        ("nullifier_one_output", NULLIFIER_ITEM_BITS),
        ("headline_five_outputs", HEADLINE_ITEM_BITS),
    ];
    let mut group = c.benchmark_group("client_decode");

    for (name, item_bits) in cases {
        let client = IPIRClient::from_db_sz(32_768, item_bits);
        let (published_c1, response) = synthetic_response(&client);
        let client_seed = seed_from_u64(0x4950_4952);
        let output_count = client.params().db_cols / client.rlwe_params().d;

        group.bench_function(BenchmarkId::new(name, output_count), |b| {
            b.iter(|| {
                black_box(client.decode_response_simplepir_raw(
                    black_box(client_seed),
                    black_box(&published_c1),
                    black_box(&response),
                ));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
