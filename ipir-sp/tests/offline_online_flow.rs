use inspiring::key_switching::ks_call_count;
use inspiring::{GadgetParams, RlweParams};
use ipir_sp::client::{generate_ks_pairs, ClientSecret, IPIRClient};
use ipir_sp::modulus_switch::{recover_rlwe_rows, switched_rlwe_response_len};
use ipir_sp::server::{build_pack_preprocessed_blocks, offline_precompute_from_hint, YServer};
use ipir_sp::YpirSchemeParams;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn tiny_rlwe() -> RlweParams {
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
    .expect("valid params")
}

fn tiny_byte_rlwe() -> RlweParams {
    RlweParams::new(
        8,
        12289,
        256,
        0.1,
        GadgetParams {
            bits_per: 3,
            ell: 5,
        },
    )
    .expect("valid byte params")
}

fn tiny_ypir() -> YpirSchemeParams {
    YpirSchemeParams {
        num_items: 4,
        item_size_bits: 8 * 14,
        poly_len: 8,
        db_dim_1: 0,
        db_dim_2: 1,
        instances: 1,
        db_rows: 4,
        db_cols: 8,
        p: 4,
        q_prime_1: 16,
        q_prime_2: 257,
        q2_bits: 8,
        t_exp_left: 3,
        t_exp_right: 2,
    }
}

fn tiny_ypir_two_outputs() -> YpirSchemeParams {
    YpirSchemeParams {
        num_items: 4,
        item_size_bits: 16 * 14,
        poly_len: 8,
        db_dim_1: 0,
        db_dim_2: 1,
        instances: 2,
        db_rows: 4,
        db_cols: 16,
        p: 4,
        q_prime_1: 16,
        q_prime_2: 257,
        q2_bits: 8,
        t_exp_left: 3,
        t_exp_right: 2,
    }
}

fn add_poly(lhs: &[u64], rhs: &[u64], q: u64) -> Vec<u64> {
    lhs.iter().zip(rhs).map(|(x, y)| (x + y) % q).collect()
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

fn decode_rows(params: &RlweParams, row_0: &[u64], row_1: &[u64], secret: &[u64]) -> Vec<u8> {
    let phase = add_poly(row_1, &negacyclic_mul(row_0, secret, params.q), params.q);
    phase
        .iter()
        .map(|coeff| (((coeff + params.delta / 2) / params.delta) % params.p) as u8)
        .collect()
}

fn encrypted_selection_query(
    params: &RlweParams,
    offline_query: &[Vec<u64>],
    secret: &[u64],
    target_row: usize,
    db_rows: usize,
) -> Vec<u64> {
    assert_eq!(db_rows % params.d, 0);
    assert_eq!(offline_query.len(), db_rows / params.d);

    let mut query = vec![0u64; db_rows];
    for (block_idx, query_poly) in offline_query.iter().enumerate() {
        for coeff_idx in 0..params.d {
            let mut basis = vec![0u64; params.d];
            basis[coeff_idx] = 1;
            let a_row = negacyclic_mul(query_poly, &basis, params.q);
            let inner = a_row.iter().zip(secret).fold(0u64, |acc, (a, s)| {
                ((u128::from(acc) + u128::from(*a) * u128::from(*s)) % u128::from(params.q)) as u64
            });
            let row = block_idx * params.d + coeff_idx;
            let encoded_selection = if row == target_row { params.delta } else { 0 };
            query[row] = (params.q + encoded_selection - inner) % params.q;
        }
    }

    query
}

#[test]
fn client_keys_drive_server_online_response_serialization() {
    let rlwe = tiny_rlwe();
    let ypir = tiny_ypir();
    let server = YServer::new(ypir.clone(), 0u16..32, false, true);

    let secret = ClientSecret::from_coeffs(&rlwe, vec![1, 0, rlwe.q - 1, 1, 0, 1, 0, 0]);
    let mut rng = ChaCha20Rng::seed_from_u64(0x5150);
    let hint_0 = vec![0u64; rlwe.d * ypir.db_cols];
    let offline = offline_precompute_from_hint(&rlwe, &ypir, hint_0);
    let key_pairs = generate_ks_pairs(&rlwe, &secret, offline.crs_blocks.len(), &mut rng);
    let pre = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks, key_pairs)
        .expect("preprocessing builds with generated keys");

    let query = [1, 0, 0, 0];
    let response = server
        .perform_online_computation_simplepir(&rlwe, &query, &pre)
        .expect("online response serializes");

    assert_eq!(
        response.len(),
        switched_rlwe_response_len(rlwe.d, ypir.q_prime_1, ypir.q_prime_2)
    );

    let (_row_0, row_1) =
        recover_rlwe_rows(&response, rlwe.d, ypir.q_prime_1, ypir.q_prime_2, rlwe.q);
    let expected_intermediate = server.multiply_query(&rlwe, &query);
    let expected_row_1: Vec<_> = expected_intermediate
        .iter()
        .map(|value| {
            ipir_sp::modulus_switch::rescale(
                ipir_sp::modulus_switch::rescale(*value, rlwe.q, ypir.q_prime_1),
                ypir.q_prime_1,
                rlwe.q,
            )
        })
        .collect();

    assert_eq!(row_1, expected_row_1);
}

#[test]
fn online_response_uses_precomputed_switches_per_rlwe_output() {
    let rlwe = tiny_rlwe();
    let ypir = tiny_ypir_two_outputs();
    let server = YServer::new(ypir.clone(), 0u16..64, false, true);

    let secret = ClientSecret::from_coeffs(&rlwe, vec![1, 0, rlwe.q - 1, 1, 0, 1, 0, 0]);
    let mut rng = ChaCha20Rng::seed_from_u64(0x5151);
    let hint_0 = vec![0u64; rlwe.d * ypir.db_cols];
    let offline = offline_precompute_from_hint(&rlwe, &ypir, hint_0);
    let key_pairs = generate_ks_pairs(&rlwe, &secret, offline.crs_blocks.len(), &mut rng);

    ks_call_count::reset();
    let pre = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks, key_pairs)
        .expect("preprocessing builds with generated keys");
    assert_eq!(
        ks_call_count::get(),
        (offline.crs_blocks.len() * (rlwe.d - 1)) as u64
    );

    ks_call_count::reset();
    let query = [1, 0, 0, 0];
    let _response = server
        .perform_online_computation_simplepir(&rlwe, &query, &pre)
        .expect("online response serializes");

    assert_eq!(ks_call_count::get(), 0);
}

#[test]
fn generated_offline_hint_feeds_preprocessing_and_online_response() {
    let rlwe = tiny_rlwe();
    let mut ypir = tiny_ypir_two_outputs();
    ypir.num_items = 8;
    ypir.db_rows = 8;
    let server = YServer::new(ypir.clone(), 0u16..128, false, true);

    let offline_query = vec![vec![1, 0, 0, 0, 0, 0, 0, 0]];
    let offline = server.perform_offline_precomputation_simplepir(&rlwe, &offline_query);
    assert_eq!(offline.crs_blocks.len(), 2);
    assert_eq!(
        offline.crs_blocks[0].rows[0],
        vec![0, 16, 32, 48, 64, 80, 96, 112]
    );
    assert_eq!(
        offline.crs_blocks[1].rows[0],
        vec![8, 24, 40, 56, 72, 88, 104, 120]
    );

    let secret = ClientSecret::from_coeffs(&rlwe, vec![1, 0, rlwe.q - 1, 1, 0, 1, 0, 0]);
    let mut rng = ChaCha20Rng::seed_from_u64(0x5152);
    let key_pairs = generate_ks_pairs(&rlwe, &secret, offline.crs_blocks.len(), &mut rng);
    let pre = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks, key_pairs)
        .expect("preprocessing builds with generated hints");

    let query = [1, 0, 0, 0, 0, 0, 0, 0];
    let response = server
        .perform_online_computation_simplepir(&rlwe, &query, &pre)
        .expect("online response serializes");

    assert_eq!(
        response.len(),
        2 * switched_rlwe_response_len(rlwe.d, ypir.q_prime_1, ypir.q_prime_2)
    );
}

#[test]
fn mocked_db_query_decodes_exact_expected_row_bytes() {
    let rlwe = tiny_byte_rlwe();
    let mut ypir = tiny_ypir_two_outputs();
    ypir.num_items = 8;
    ypir.db_rows = 8;
    ypir.p = 256;
    ypir.q_prime_1 = rlwe.q;
    ypir.q_prime_2 = rlwe.q;

    let db_bytes: Vec<u8> = (0..ypir.db_rows)
        .flat_map(|row| (0..ypir.db_cols).map(move |col| (row * 17 + col * 3) as u8))
        .collect();
    let encoded_db = db_bytes
        .iter()
        .map(|byte| rlwe.delta * u64::from(*byte))
        .collect::<Vec<_>>();
    let server = YServer::new(ypir.clone(), encoded_db.into_iter(), false, true);

    let zero_secret = ClientSecret::from_coeffs(&rlwe, vec![0; rlwe.d]);
    let offline_query = vec![vec![1, 0, 0, 0, 0, 0, 0, 0]];
    let offline = server.perform_offline_precomputation_simplepir(&rlwe, &offline_query);
    let mut rng = ChaCha20Rng::seed_from_u64(0xE2E);
    let key_pairs = generate_ks_pairs(&rlwe, &zero_secret, offline.crs_blocks.len(), &mut rng);
    let pre = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks, key_pairs)
        .expect("preprocessing builds");

    let target_row = 3;
    let mut query = vec![0u64; ypir.db_rows];
    query[target_row] = 1;
    let response = server
        .perform_online_computation_simplepir(&rlwe, &query, &pre)
        .expect("online response serializes");

    let response_len = switched_rlwe_response_len(rlwe.d, ypir.q_prime_1, ypir.q_prime_2);
    let mut decoded = Vec::with_capacity(ypir.db_cols);
    for chunk in response.chunks_exact(response_len) {
        let (row_0, row_1) =
            recover_rlwe_rows(chunk, rlwe.d, ypir.q_prime_1, ypir.q_prime_2, rlwe.q);
        decoded.extend(decode_rows(&rlwe, &row_0, &row_1, &zero_secret.coeffs));
    }

    let expected = db_bytes[target_row * ypir.db_cols..(target_row + 1) * ypir.db_cols].to_vec();
    assert_eq!(decoded, expected);
}

#[test]
fn encrypted_pir_query_decodes_exact_expected_row_bytes() {
    let rlwe = tiny_rlwe();
    let mut ypir = tiny_ypir_two_outputs();
    ypir.num_items = 8;
    ypir.db_rows = 8;
    ypir.q_prime_1 = rlwe.q;
    ypir.q_prime_2 = rlwe.q;

    let db_bytes: Vec<u8> = (0..ypir.db_rows)
        .flat_map(|row| (0..ypir.db_cols).map(move |col| ((row + col * 2) % 4) as u8))
        .collect();
    let server = YServer::new(
        ypir.clone(),
        db_bytes.iter().map(|byte| u64::from(*byte)),
        false,
        true,
    );

    let secret = ClientSecret::from_coeffs(&rlwe, vec![1, 0, rlwe.q - 1, 1, 0, 1, 0, 0]);
    let offline_query = vec![vec![2, 1, 0, 3, 1, 0, 2, 1]];
    let offline = server.perform_offline_precomputation_simplepir(&rlwe, &offline_query);
    let mut rng = ChaCha20Rng::seed_from_u64(0xE2E1);
    let key_pairs = generate_ks_pairs(&rlwe, &secret, offline.crs_blocks.len(), &mut rng);
    let pre = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks, key_pairs)
        .expect("preprocessing builds");

    let target_row = 5;
    let query = encrypted_selection_query(
        &rlwe,
        &offline_query,
        &secret.coeffs,
        target_row,
        ypir.db_rows,
    );
    let response = server
        .perform_online_computation_simplepir(&rlwe, &query, &pre)
        .expect("online response serializes");

    let response_len = switched_rlwe_response_len(rlwe.d, ypir.q_prime_1, ypir.q_prime_2);
    let mut decoded = Vec::with_capacity(ypir.db_cols);
    for chunk in response.chunks_exact(response_len) {
        let (row_0, row_1) =
            recover_rlwe_rows(chunk, rlwe.d, ypir.q_prime_1, ypir.q_prime_2, rlwe.q);
        decoded.extend(decode_rows(&rlwe, &row_0, &row_1, &secret.coeffs));
    }

    let expected = db_bytes[target_row * ypir.db_cols..(target_row + 1) * ypir.db_cols].to_vec();
    assert_eq!(decoded, expected);
}

#[test]
fn ipir_client_facade_matches_server_full_online_shape() {
    let rlwe = tiny_rlwe();
    let mut ypir = tiny_ypir_two_outputs();
    ypir.num_items = 8;
    ypir.db_rows = 8;
    ypir.q_prime_1 = rlwe.q;
    ypir.q_prime_2 = rlwe.q;

    let db_values: Vec<u64> = (0..ypir.db_rows)
        .flat_map(|row| (0..ypir.db_cols).map(move |col| ((row + col * 3) % 4) as u64))
        .collect();
    let server = YServer::new(ypir.clone(), db_values.clone().into_iter(), false, true);
    let client = IPIRClient::new(&rlwe, &ypir);
    let setup = client.generate_setup_simplepir_from_seed([9u8; 32]);
    let offline =
        server.perform_offline_precomputation_simplepir(&rlwe, &setup.offline_query_polys);
    let (query, client_seed) = client.generate_query_simplepir(&setup, 6);
    let pre = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks, setup.key_pairs)
        .expect("preprocessing builds from facade setup");

    let response = server
        .perform_full_online_computation_simplepir(&rlwe, &query.to_bytes(), &pre)
        .expect("full online response");
    let decoded = client.decode_response_simplepir_raw(client_seed, &response);
    let expected = db_values[6 * ypir.db_cols..7 * ypir.db_cols].to_vec();

    assert_eq!(query.as_slice().len(), ypir.db_rows);
    assert_eq!(decoded, expected);
}
