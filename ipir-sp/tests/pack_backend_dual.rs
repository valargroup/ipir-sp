//! Dual-backend packing: Inspiring vs Reinspiring must agree on odd q.

use inspiring::{GadgetParams, PackingKeys, RlweParams, TopKeyImages};
use ipir_sp::params::YpirSchemeParams;
use ipir_sp::server::{
    build_pack_preprocessed_blocks, offline_precompute_from_hint, pack_intermediate_blocks,
};
use ipir_sp::{
    build_reinspiring_blocks, pack_intermediate_blocks_with_backend, PackBackend,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};

const SINGLE_CRT_Q: u64 = 72_057_594_037_641_217;

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

fn prodlike_rlwe() -> RlweParams {
    RlweParams::new(
        16,
        SINGLE_CRT_Q,
        1 << 14,
        6.4,
        GadgetParams {
            bits_per: 19,
            ell: 3,
        },
    )
    .expect("valid params")
}

fn ypir_shape(poly_len: usize, db_rows: usize, db_cols: usize, p: u64) -> YpirSchemeParams {
    YpirSchemeParams {
        num_items: db_rows as u64,
        item_size_bits: (db_cols * 14) as u64,
        poly_len,
        db_dim_1: 0,
        db_dim_2: 1,
        instances: db_cols / poly_len,
        db_rows,
        db_cols,
        p,
        q_prime_1: 16,
        q_prime_2: 257,
        q2_bits: 8,
        t_exp_left: 3,
        t_exp_right: 2,
        query_bits: 14,
    }
}

fn assert_backends_byte_equal(
    rlwe: &RlweParams,
    ypir: &YpirSchemeParams,
    hint_0: Vec<u64>,
    key_seed: [u8; 32],
) {
    let offline = offline_precompute_from_hint(rlwe, ypir, hint_0);
    let inspiring_pre =
        build_pack_preprocessed_blocks(rlwe, &offline.crs_blocks).expect("inspiring pre");
    let reinspiring_pre = build_reinspiring_blocks(&inspiring_pre).expect("reinspiring pre");

    let mut secret = PolyMatrixRaw::zero(&rlwe.spiral, 1, 1);
    secret.get_poly_mut(0, 0)[0] = 1;
    secret.get_poly_mut(0, 0)[3 % rlwe.d] = rlwe.q - 1;
    let mut rng = ChaCha20Rng::from_seed(key_seed);
    let keys = PackingKeys::generate_full(rlwe, &to_ntt_alloc(&secret), &mut rng);
    let top = TopKeyImages::build(rlwe);
    let intermediate: Vec<u64> = (0..ypir.db_cols)
        .map(|i| (i as u64 * 17 + 5) % rlwe.q)
        .collect();

    let via_inspiring = pack_intermediate_blocks(&intermediate, &keys, &top, &inspiring_pre)
        .expect("inspiring pack");
    let via_enum = pack_intermediate_blocks_with_backend(
        PackBackend::Reinspiring,
        &intermediate,
        &keys,
        &top,
        &inspiring_pre,
        Some(&reinspiring_pre),
    )
    .expect("reinspiring pack");
    let via_default = pack_intermediate_blocks_with_backend(
        PackBackend::Inspiring,
        &intermediate,
        &keys,
        &top,
        &inspiring_pre,
        None,
    )
    .expect("default pack");

    assert_eq!(via_inspiring.len(), via_enum.len());
    for (a, b) in via_inspiring.iter().zip(via_enum.iter()) {
        assert_eq!(
            a.inner.as_slice(),
            b.inner.as_slice(),
            "Reinspiring backend must match Inspiring byte-for-byte"
        );
    }
    for (a, b) in via_inspiring.iter().zip(via_default.iter()) {
        assert_eq!(a.inner.as_slice(), b.inner.as_slice());
    }
}

#[test]
fn reinspiring_backend_matches_inspiring_on_tiny_shape() {
    let rlwe = tiny_rlwe();
    let ypir = ypir_shape(8, 4, 16, 4);
    let hint_0 = vec![0u64; rlwe.d * ypir.db_cols];
    assert_backends_byte_equal(&rlwe, &ypir, hint_0, [42; 32]);
}

#[test]
fn reinspiring_backend_matches_inspiring_on_prodlike_nonzero_crs() {
    let rlwe = prodlike_rlwe();
    let ypir = ypir_shape(16, 16, 32, 1 << 14);
    let hint_0: Vec<u64> = (0..rlwe.d * ypir.db_cols)
        .map(|i| (i as u64 * 1_000_003 + 7) % rlwe.q)
        .collect();
    assert!(hint_0.iter().any(|&v| v != 0));
    assert_backends_byte_equal(&rlwe, &ypir, hint_0, [9; 32]);
}
