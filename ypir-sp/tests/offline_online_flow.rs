use inspiring::{GadgetParams, RlweParams};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use ypir_sp::client::{generate_ks_pairs, ClientSecret};
use ypir_sp::modulus_switch::{recover_rlwe_rows, switched_rlwe_response_len};
use ypir_sp::server::{build_pack_preprocessed_blocks, offline_precompute_from_hint, YServer};
use ypir_sp::YpirSchemeParams;

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
            ypir_sp::modulus_switch::rescale(
                ypir_sp::modulus_switch::rescale(*value, rlwe.q, ypir.q_prime_1),
                ypir.q_prime_1,
                rlwe.q,
            )
        })
        .collect();

    assert_eq!(row_1, expected_row_1);
}
