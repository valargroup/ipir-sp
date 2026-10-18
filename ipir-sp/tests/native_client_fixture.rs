#![cfg(feature = "native-reinspiring")]
use ipir_native_client::*;
use ipir_sp::native::NativeServer;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha2::{Digest, Sha256};
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
// SHA-256 expectations captured from the existing evaluator before extraction.
// Do not regenerate these from the moved implementation.
#[test]
fn extracted_client_preserves_existing_wire_vectors() {
    for (label, pbits, two, rounded, dithered) in [
        ("one_mask", 16, false, false, false),
        ("two_mask", 16, true, false, false),
        ("rounded_dithered", 16, true, true, true),
        ("byte_plaintext", 8, true, true, true),
    ] {
        let params = NativeParams::new(16, 54, pbits, 19, 2, SecretDistribution::Gaussian).unwrap();
        let mut profile = NativeProfile::new(params, 32, 16).unwrap();
        if two {
            profile = profile.with_two_mask_output().unwrap();
        }
        if rounded {
            profile = profile
                .with_published_mask_bits(if pbits == 8 { 22 } else { 27 })
                .unwrap();
        }
        if dithered {
            profile = profile
                .with_dithered_query_bits(if pbits == 8 { 28 } else { 43 })
                .unwrap();
        }
        if pbits == 8 {
            profile = profile.with_response_bits(10).unwrap();
        }
        let setup = NativePublicSetup::new(profile, [11; 32], [12; 32]);
        let setup_id = hash(&setup.id());
        let masks = hash(
            &setup
                .query_masks()
                .iter()
                .flatten()
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let request =
            NativeRequest::generate_with_rng(&setup, 5, &mut ChaCha20Rng::seed_from_u64(42))
                .unwrap();
        let db: Vec<u16> = (0..512).map(|i| (i % 251) as u16).collect();
        let expected: Vec<u64> = (0..16).map(|col| db[col * 32 + 5] as u64).collect();
        let server = NativeServer::build(setup, db).unwrap();
        let published = server.published().to_bytes();
        let response = server.respond(request.bytes()).unwrap().0;
        assert_eq!(
            request.decode(&server.published(), &response).unwrap(),
            expected
        );
        let expected_hashes = match label {
            "one_mask" => [
                "c54aeb6ef635d1b3dff1fde161b9345289e709295f8a9c81584c8a05e7ec8bbb",
                "1ff556782a13ee89d7df04e0c555d8f7f13a7a8207dcd75e362c8f869e06e952",
                "8d63ad2bddca84cb6388639113a879d41d48f561b9b3230b3869028155206ff5",
                "25a31d75af4459a0b5e992523ae9b5b7c0343169a27c5202f54cffd3cf062b06",
                "2c7647cac8dafb436522018112073abbf83a193fa62e8d368b8b2b508c000ce7",
            ],
            "two_mask" => [
                "4a2b34caf02da7cd0d75de7867069f18e45f6c6dd325ea339158dc4e00e9c9f3",
                "a29473f39cfe29d97976add9f6aaf04e8c7bf579734620acfae8cd6f73b1cef0",
                "8cec70cb195f3f4c8adb7834364a6f881d171f3443a135b9e42d5e244dce54e4",
                "3ae6620bd46b75788712922bc38e3ef5ed57ad5964e57f15f494eed8004b11bc",
                "239b258655fe835980d151a26d6d8fb0761bb14f1debae77c17dd56d1c2aa1d8",
            ],
            "rounded_dithered" => [
                "ab8c40205bdcd21baa13fad8ae8480a566d319375b2e3076c1cd521cdcbf0a81",
                "b07ce6e8fc37a951fc8dba4cdc50a580d783a2a97a1a828e19138bcf46a95f30",
                "7e2c07d6d268b0ff34edc496fba58726f58144cc726277d3fd19cd88c1f0eea2",
                "9f9e9adbf74e46f1c934bcb05790650ad6dfda2a1810a0070f4792c6594918cd",
                "3bae1b2ae139a53b1cd4712089de360b2b7a74c11d1df9272df2e5b30898a72e",
            ],
            "byte_plaintext" => [
                "174ca58e919d6ab8a4e24efd609e32fbb54a79da073bf913d9a0dd26d0418cc8",
                "02144bff3f4c9deb61a9a2511140a3b05042612f4f1680efe95060ecdd6eccea",
                "48d2b36870cb53fb034c9729d66e77dca0d48b471da0b7f96a9ea3d8d462780f",
                "c3139a4791782a81d24cf3c92784ca241b23eaa4388f03d7cf267b1a012efe6e",
                "1a8a0ff4c399e32f974a12f82b9d169006d8266e460a447439926e16c699c80b",
            ],
            _ => unreachable!(),
        };
        assert_eq!(
            [
                setup_id,
                masks,
                hash(request.bytes()),
                hash(&published),
                hash(&response)
            ],
            expected_hashes,
            "native wire changed for {label}"
        );
    }
}

#[test]
fn legacy_unaligned_keys_still_decode_through_the_existing_server() {
    let packing = NativeParams::new(2, 17, 1, 9, 2, SecretDistribution::Gaussian).unwrap();
    let profile = NativeProfile::new(packing, 2, 2)
        .unwrap()
        .with_kh_bits(17)
        .unwrap();
    let setup = NativePublicSetup::new(profile, [7; 32], [19; 32]);
    let request =
        NativeRequest::generate_with_rng(&setup, 1, &mut ChaCha20Rng::seed_from_u64(42)).unwrap();
    let server = NativeServer::build(setup, vec![0, 1, 1, 0]).unwrap();
    let response = server.respond(request.bytes()).unwrap().0;
    assert_eq!(
        request.decode(&server.published(), &response).unwrap(),
        vec![1, 0]
    );
}
