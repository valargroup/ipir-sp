#![cfg(feature = "experimental-key-reuse")]

use inspiring::TopKeyImages;
use ipir_sp::client::reusable::QueryPool;
use ipir_sp::modulus_switch::recover_published_c1;
use ipir_sp::serialize::{deserialize_packing_keys, serialize_packing_keys};
use ipir_sp::server::{build_pack_preprocessed_blocks, published_c1_rows};
use ipir_sp::{params_for_simplepir, IPIRClient, IPIRServer};

#[test]
fn reused_keys_recover_boundary_rows_across_sets_and_fresh_batches() {
    let (r, y) = params_for_simplepir(4096, 2048 * 14).unwrap();
    let pool = QueryPool::new(IPIRClient::new(&r, &y), [0x72; 32], 4).unwrap();
    let value = |row: usize, col: usize| ((row * 31 + col * 17 + 5) % y.p as usize) as u16;
    let server = IPIRServer::new_auto_kernel(
        y.clone(),
        (0..y.db_rows).flat_map(|row| (0..y.db_cols).map(move |col| value(row, col))),
        false,
        true,
    );
    let pre: Vec<_> = pool
        .sets()
        .iter()
        .map(|set| {
            let offline = server.perform_offline_precomputation_simplepir(&r, set);
            build_pack_preprocessed_blocks(&r, &offline.crs_blocks).unwrap()
        })
        .collect();
    let c1: Vec<_> = pre
        .iter()
        .map(|p| recover_published_c1(&published_c1_rows(p, r.q), r.d, y.db_cols / r.d, r.q))
        .collect();
    let top = TopKeyImages::build(&r);
    for _ in 0..2 {
        let mut batch = pool.start_batch();
        let upload = serialize_packing_keys(&r, batch.keys()).unwrap();
        let cached = deserialize_packing_keys(&r, &upload).unwrap();
        for (slot, row) in [0, 2047, 2048, 4095].into_iter().enumerate() {
            let query = batch.next_query(row).unwrap();
            assert_eq!(query.slot(), slot);
            let (response, _) = server
                .perform_full_online_computation_simplepir_measured(
                    &r,
                    query.bytes(),
                    &cached,
                    &top,
                    &pre[slot],
                )
                .unwrap();
            let (decoded, error) = batch.decode_with_margin(&c1[slot], &response);
            let expected: Vec<_> = (0..y.db_cols)
                .map(|col| u64::from(value(row, col)))
                .collect();
            assert_eq!(decoded, expected);
            assert!(error < r.delta / 8);
            // A metadata mixup does not yield a valid row: the transport must
            // bind this data before decryption, not treat rounding as integrity.
            let (wrong, _) = batch.decode_with_margin(&c1[(slot + 1) % 4], &response);
            assert_ne!(wrong, expected);
            let (retry, _) = server
                .perform_full_online_computation_simplepir_measured(
                    &r,
                    query.bytes(),
                    &cached,
                    &top,
                    &pre[slot],
                )
                .unwrap();
            assert_eq!(retry, response);
        }
        assert!(batch.next_query(0).is_err());
    }
}
