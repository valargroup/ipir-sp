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
use ipir_sp::{ProductionSimplePirParams, SimplePirProfile};

/// The deployed row count, so the derived query width and the rounding term
/// it controls are exactly production's. Only the column count is reduced, and
/// the rounding error does not depend on it.
const ROWS: u64 = 28_672;
/// First, last, a block boundary, and a few interior rows.
const TARGET_ROWS: [usize; 8] = [0, 2_047, 2_048, 7_777, 13_000, 19_001, 25_555, 28_671];
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
    let profile = ProductionSimplePirParams::new(ROWS, 2048 * 14, SimplePirProfile::P14)
        .expect("production profile");
    let server = YServer::from_profile(&profile, db.iter().copied(), false, true);
    let client = IPIRClient::new(&profile);

    let offline_query_polys = client.generate_public_query_setup_simplepir_from_seed(SETUP_SEED);
    let offline =
        server.perform_offline_precomputation_simplepir(&rlwe, offline_query_polys.polys());
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
    let threshold = rlwe.delta / 2;
    let bits = |value: u64| {
        if value == 0 {
            0
        } else {
            64 - value.leading_zeros()
        }
    };

    // Each query samples a fresh secret, packing keys and errors. Measure
    // phase error against the known row across several independent draws.
    let mut worst_error = 0_u64;
    for target_row in TARGET_ROWS {
        let expected: Vec<u64> = db[target_row * ypir.db_cols..(target_row + 1) * ypir.db_cols]
            .iter()
            .map(|value| u64::from(*value))
            .collect();
        let (query, packing_keys, client_seed) =
            client.generate_fresh_query_simplepir(&offline_query_polys, target_row);
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

        let (decoded, max_error) = client.decode_response_simplepir_with_expected_phase_error(
            client_seed,
            &published_c1,
            &response,
            &expected,
        );
        assert_eq!(
            decoded, expected,
            "decoded row {target_row} must match the database row"
        );
        worst_error = worst_error.max(max_error);
    }

    // Assert headroom against the expected encoding, so a wrong plaintext
    // cannot masquerade as small error near another encoding.
    eprintln!(
        "production flow: ||e||_inf = 2^{} over {} queries against delta/2 = 2^{} (query at {} bits)",
        bits(worst_error),
        TARGET_ROWS.len(),
        bits(threshold),
        ypir.query_bits
    );
    assert!(
        worst_error < threshold / 4,
        "phase error too large: error 2^{} against delta/2 = 2^{}",
        bits(worst_error),
        bits(threshold)
    );
}

#[test]
fn p16_q46_profile_round_trip_has_decryption_margin() {
    const ROWS: u64 = 8_192;
    const TARGET: usize = ROWS as usize - 1;
    let profile = ProductionSimplePirParams::new(ROWS, 2048 * 16, SimplePirProfile::P16Q46)
        .expect("P16Q46 profile");
    let (rlwe, ypir) = (profile.rlwe(), profile.ypir());
    assert_eq!(ypir.p, 1 << 16);
    assert_eq!(ypir.query_bits, 46);

    let db: Vec<u16> = (0..ypir.db_rows)
        .flat_map(|row| {
            (0..ypir.db_cols).map(move |col| ((row * 31 + col * 17 + 5) % (1 << 16)) as u16)
        })
        .collect();
    let expected: Vec<u64> = db[TARGET * ypir.db_cols..(TARGET + 1) * ypir.db_cols]
        .iter()
        .map(|value| u64::from(*value))
        .collect();
    assert!(expected
        .iter()
        .any(|value| *value > u64::from(u16::MAX / 2)));

    let server = YServer::from_profile(&profile, db.into_iter(), false, true);
    let client = IPIRClient::new(&profile);
    let setup = client.generate_public_query_setup_simplepir_from_seed(SETUP_SEED);
    let offline = server.perform_offline_precomputation_simplepir(rlwe, setup.polys());
    let preprocessed =
        build_pack_preprocessed_blocks(rlwe, &offline.crs_blocks).expect("preprocessing builds");
    let published_c1 = recover_published_c1(
        &published_c1_rows(&preprocessed, rlwe.q),
        rlwe.d,
        ypir.db_cols / rlwe.d,
        rlwe.q,
    );
    let top_keys = TopKeyImages::build(rlwe);
    let (query, packing_keys, seed) = client.generate_fresh_query_simplepir(&setup, TARGET);
    let query_bytes = query.to_switched_bytes(rlwe.q, ypir.query_bits);
    let (response, _) = server
        .perform_full_online_computation_simplepir_measured(
            rlwe,
            &query_bytes,
            &packing_keys,
            &top_keys,
            &preprocessed,
        )
        .expect("online response");
    let (decoded, max_error) = client.decode_response_simplepir_with_expected_phase_error(
        seed,
        &published_c1,
        &response,
        &expected,
    );
    assert_eq!(decoded, expected);
    assert!(
        max_error < rlwe.delta / 4,
        "P16Q46 phase error too large: error {max_error} against delta/2 {}",
        rlwe.delta / 2
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
