//! End-to-end flow at the production RLWE parameter set.
//!
//! The other integration tests use a `d = 8`, `q = 12289` fixture, which is fine
//! for exercising index algebra but says nothing about the noise budget. The
//! transmitted query width is derived from `(q, p, db_rows)`, and the response
//! now omits the snapshot-constant `c1` row, so both need a test at parameters
//! where the noise is real: `d = 2048`, `q ≈ 2^56`, `p = 2^14`.
//!
//! The database is deliberately short (eight row blocks) to keep the test to a
//! few seconds; `db_rows` feeds the width derivation, so the configuration is
//! self-consistent even though it is smaller than the deployed shape.

use inspiring::TopKeyImages;
use ipir_sp::client::IPIRClient;
use ipir_sp::modulus_switch::recover_published_c1;
use ipir_sp::params::params_for_simplepir;
use ipir_sp::server::{build_pack_preprocessed_blocks, published_c1_rows, YServer};

/// The deployed row count, so the derived query width and the rounding term
/// it controls are exactly production's. Only the column count is reduced, and
/// the rounding error does not depend on it.
const ROWS: u64 = 28_672;
const TARGET_ROW: usize = 19_001;
const SETUP_SEED: [u8; 32] = [0x5A; 32];

#[test]
fn production_params_round_trip_recovers_the_target_row() {
    let (rlwe, ypir) = params_for_simplepir(ROWS, 2048 * 14).expect("production params");
    assert_eq!(rlwe.d, 2048);
    assert_eq!(ypir.db_rows, ROWS as usize);
    assert_eq!(ypir.db_cols, 2048);
    assert!(
        ypir.query_bits < 56,
        "the production modulus must leave room to switch the query down"
    );

    // Deterministic plaintext database, every value a valid plaintext.
    let db: Vec<u16> = (0..ypir.db_rows)
        .flat_map(|row| {
            (0..ypir.db_cols).map(move |col| ((row * 31 + col * 17 + 5) % ypir.p as usize) as u16)
        })
        .collect();
    let expected: Vec<u64> = db[TARGET_ROW * ypir.db_cols..(TARGET_ROW + 1) * ypir.db_cols]
        .iter()
        .map(|value| u64::from(*value))
        .collect();

    let server = YServer::new(ypir.clone(), db.into_iter(), false, true);
    let client = IPIRClient::new(&rlwe, &ypir);

    let offline_query_polys = client.generate_public_query_setup_simplepir_from_seed(SETUP_SEED);
    let offline = server.perform_offline_precomputation_simplepir(&rlwe, &offline_query_polys);
    let preprocessed =
        build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks).expect("preprocessing builds");

    // Published once per snapshot, not per query.
    let published_c1 = recover_published_c1(
        &published_c1_rows(&preprocessed, rlwe.q),
        rlwe.d,
        ypir.db_cols / rlwe.d,
        rlwe.q,
    );

    let top_keys = TopKeyImages::build(&rlwe);
    let (query, packing_keys, client_seed) =
        client.generate_fresh_query_simplepir(&offline_query_polys, TARGET_ROW);
    let query_bytes = query.to_switched_bytes(rlwe.q, ypir.query_bits);
    assert_eq!(
        query_bytes.len(),
        (ypir.db_rows * ypir.query_bits).div_ceil(8),
        "query is transmitted at the derived width"
    );

    let (response, _timing) = server
        .perform_full_online_computation_simplepir_measured(
            &rlwe,
            &query_bytes,
            &packing_keys,
            &top_keys,
            &preprocessed,
        )
        .expect("online response");

    let (decoded, max_error) =
        client.decode_response_simplepir_with_margin(client_seed, &published_c1, &response);
    assert_eq!(decoded, expected, "decoded row must match the database row");

    // The real regression signal: decoding is correct exactly while the worst
    // phase error stays under Δ/2. Assert real headroom, not bare correctness,
    // so that shrinking the query width or widening the database cannot quietly
    // consume the budget and still pass.
    let threshold = rlwe.delta / 2;
    let bits = |value: u64| {
        if value == 0 {
            0
        } else {
            64 - value.leading_zeros()
        }
    };
    eprintln!(
        "production flow: ||e||_inf = 2^{} against delta/2 = 2^{} (query at {} bits)",
        bits(max_error),
        bits(threshold),
        ypir.query_bits
    );
    assert!(
        max_error < threshold / 4,
        "decryption margin too thin: error 2^{} against delta/2 = 2^{}",
        bits(max_error),
        bits(threshold)
    );
}

/// The switched query must be strictly cheaper than the full-width one, and the
/// response must carry only `c2`.
#[test]
fn production_params_wire_sizes_shrink() {
    let (rlwe, ypir) = params_for_simplepir(ROWS, 2048 * 14).expect("production params");

    let full_width_query = (ypir.db_rows * 56).div_ceil(8);
    let switched_query = (ypir.db_rows * ypir.query_bits).div_ceil(8);
    assert!(
        switched_query < full_width_query,
        "switched query {switched_query} must beat {full_width_query}"
    );

    let blocks = ypir.db_cols / rlwe.d;
    let body_only = blocks * ipir_sp::modulus_switch::response_body_len(rlwe.d, ypir.q_prime_1);
    let with_c1 = blocks
        * ipir_sp::modulus_switch::switched_rlwe_response_len(
            rlwe.d,
            ypir.q_prime_1,
            ypir.q_prime_2,
        );
    assert!(
        body_only < with_c1,
        "body-only response {body_only} must beat {with_c1}"
    );
}
