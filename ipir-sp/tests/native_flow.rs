#![cfg(feature = "native-reinspiring")]
use ipir_sp::native::*;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use reinspiring::native::*;
#[test]
fn native_ipir_full_wire_roundtrip_and_binding_rejections() {
    for ell in [2, 3] {
        for pbits in [14, 16] {
            let params =
                NativeParams::new(16, 54, pbits, 19, ell, SecretDistribution::Gaussian).unwrap();
            let profile = NativeProfile::new(params, 32, 48).unwrap();
            let setup = NativePublicSetup::new(profile.clone(), [1; 32], [9; 32]);
            let db: Vec<u16> = (0..48)
                .flat_map(|c| (0..32).map(move |r| ((r * 17 + c * 13) % (1 << pbits)) as u16))
                .collect();
            let server = NativeServer::build(setup, db).unwrap();
            let published =
                NativePublished::from_bytes(server.setup(), &server.published().to_bytes())
                    .unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(10);
            for row in [0, 15, 16, 31] {
                let req = NativeRequest::generate_with_rng(server.setup(), row, &mut rng).unwrap();
                let (response, _) = server.respond(req.bytes()).unwrap();
                let expected: Vec<_> = (0..48)
                    .map(|c| ((row * 17 + c * 13) % (1 << pbits)) as u64)
                    .collect();
                let (actual, error) = req
                    .decode_with_error(&published, &response, &expected)
                    .unwrap();
                assert_eq!(actual, expected);
                assert!(error < (1u64 << 54) / (1 << pbits) / 2);
                assert!(server
                    .respond(&req.bytes()[..req.bytes().len() - 1])
                    .is_err());
                assert!(req
                    .decode(&published, &response[..response.len() - 1])
                    .is_err());
                let other =
                    NativeRequest::generate_with_rng(server.setup(), row, &mut rng).unwrap();
                assert!(other.decode(&published, &response).is_err());
                let mut malformed = req.bytes().to_vec();
                malformed[4] ^= 1;
                assert!(server.respond(&malformed).is_err());
                let wrong = NativePublicSetup::new(profile.clone(), [2; 32], [9; 32]);
                assert!(NativePublished::from_bytes(&wrong, &published.to_bytes()).is_err());
            }
        }
    }
}

#[test]
fn immutable_server_handles_concurrent_fresh_queries() {
    let p = NativeParams::new(8, 54, 14, 19, 2, SecretDistribution::Gaussian).unwrap();
    let setup = NativePublicSetup::new(NativeProfile::new(p, 16, 16).unwrap(), [3; 32], [4; 32]);
    let db = (0..16)
        .flat_map(|c| (0..16).map(move |r| (c * 17 + r) as u16))
        .collect();
    let server = NativeServer::build(setup, db).unwrap();
    let published = server.published();
    std::thread::scope(|scope| {
        for row in [0, 7, 8, 15] {
            let server = &server;
            let published = &published;
            scope.spawn(move || {
                let request = NativeRequest::generate_with_rng(
                    server.setup(),
                    row,
                    &mut ChaCha20Rng::seed_from_u64(row as u64 + 10),
                )
                .unwrap();
                let response = server.respond(request.bytes()).unwrap().0;
                assert_eq!(
                    request.decode(published, &response).unwrap(),
                    (0..16).map(|c| (c * 17 + row) as u64).collect::<Vec<_>>()
                );
            });
        }
    });
}

#[test]
fn batched_preprocessing_preserves_block_order_and_wire_responses() {
    let p = NativeParams::new(8, 54, 14, 19, 2, SecretDistribution::Gaussian).unwrap();
    let profile = NativeProfile::new(p, 16, 40).unwrap();
    let setup = || NativePublicSetup::new(profile.clone(), [5; 32], [6; 32]);
    let db: Vec<_> = (0..40)
        .flat_map(|c| (0..16).map(move |r| (c * 71 + r * 13) as u16))
        .collect();
    assert!(NativeServer::build_with_concurrency(setup(), db.clone(), 0).is_err());
    let serial = NativeServer::build(setup(), db.clone()).unwrap();
    for concurrency in [2, 3, usize::MAX] {
        let batched =
            NativeServer::build_with_concurrency(setup(), db.clone(), concurrency).unwrap();
        assert_eq!(
            serial.published().to_bytes(),
            batched.published().to_bytes()
        );
        for row in [0, 8, 15] {
            let req = NativeRequest::generate_with_rng(
                serial.setup(),
                row,
                &mut ChaCha20Rng::seed_from_u64(row as u64 + 42),
            )
            .unwrap();
            let expected = serial.respond(req.bytes()).unwrap().0;
            let actual = batched.respond(req.bytes()).unwrap().0;
            assert_eq!(actual, expected);
            assert_eq!(
                req.decode(&batched.published(), &actual).unwrap(),
                (0..40)
                    .map(|c| (c * 71 + row * 13) as u64)
                    .collect::<Vec<_>>()
            );
        }
    }
}
