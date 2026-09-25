#![cfg(feature = "native-reinspiring")]
use ipir_sp::native::*;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use reinspiring::native::*;
#[test]
fn one_key_two_mask_roundtrip_and_mode_binding() {
    let params = NativeParams::new(16, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    let two = NativeProfile::new(params.clone(), 32, 48)
        .unwrap()
        .with_two_mask_output()
        .unwrap();
    assert!(two.clone().with_kh_bits(47).is_err());
    assert!(NativeProfile::new(params.clone(), 32, 48)
        .unwrap()
        .with_kh_bits(47)
        .unwrap()
        .with_two_mask_output()
        .is_err());
    let old = NativeProfile::new(params, 32, 48).unwrap();
    let setup = NativePublicSetup::new(two, [11; 32], [12; 32]);
    let old_setup = NativePublicSetup::new(old, [11; 32], [12; 32]);
    assert_ne!(setup.id(), old_setup.id());
    let db: Vec<u16> = (0..48)
        .flat_map(|c| (0..32).map(move |r| ((r * 19 + c * 31) % 65536) as u16))
        .collect();
    let server = NativeServer::build(setup, db).unwrap();
    let published_bytes = server.published().to_bytes();
    assert_eq!(&published_bytes[..4], b"RNP2");
    assert_eq!(published_bytes.len(), 36 + 2 * 48 * 8);
    assert!(NativePublished::from_bytes(&old_setup, &published_bytes).is_err());
    let published = NativePublished::from_bytes(server.setup(), &published_bytes).unwrap();
    let mut bad_published = published_bytes.clone();
    bad_published[36] = 0xff;
    bad_published[37] = 0xff;
    bad_published[38] = 0xff;
    bad_published[39] = 0xff;
    bad_published[40] = 0xff;
    bad_published[41] = 0xff;
    bad_published[42] = 0xff;
    bad_published[43] = 0xff;
    assert!(NativePublished::from_bytes(server.setup(), &bad_published).is_err());
    let mut rng = ChaCha20Rng::seed_from_u64(981);
    for row in [0, 15, 16, 31] {
        let mut req = NativeRequest::generate_with_rng(server.setup(), row, &mut rng).unwrap();
        assert_eq!(&req.bytes()[..4], b"RNQ3");
        assert_eq!(req.bytes().len(), 36 + (2 * 16 * 54) / 8 + (32 * 49) / 8);
        let response = server.respond(req.bytes()).unwrap().0;
        let prepared = published.prepare(server.setup()).unwrap();
        assert_eq!(
            req.decode_prepared(&prepared, &response).unwrap(),
            req.decode(&published, &response).unwrap()
        );
        req.prepare_decode(&prepared).unwrap();
        assert_eq!(
            req.decode_prepared(&prepared, &response).unwrap(),
            req.decode(&published, &response).unwrap()
        );
        assert!(req
            .decode_prepared(&prepared, &response[..response.len() - 1])
            .is_err());
        assert_eq!(&response[..4], b"RNR2");
        let expected: Vec<_> = (0..48)
            .map(|c| ((row * 19 + c * 31) % 65536) as u64)
            .collect();
        let (actual, error) = req
            .decode_with_error(&published, &response, &expected)
            .unwrap();
        assert_eq!(actual, expected);
        assert!(error < (1u64 << 37));
        let mut bad_request = req.bytes().to_vec();
        bad_request[3] = b'1';
        assert!(server.respond(&bad_request).is_err());
        assert!(server
            .respond(&req.bytes()[..req.bytes().len() - 1])
            .is_err());
        assert!(req
            .decode(&published, &response[..response.len() - 1])
            .is_err());
        assert!(req
            .decode(
                &NativePublished::from_bytes(&old_setup, &old_setup_fixture(&old_setup)).unwrap(),
                &response
            )
            .is_err());
    }
}

fn old_setup_fixture(setup: &NativePublicSetup) -> Vec<u8> {
    let mut bytes = b"RNP1".to_vec();
    bytes.extend(setup.id());
    bytes.resize(36 + setup.profile().cols() * 8, 0);
    bytes
}
#[test]
fn native_ipir_full_wire_roundtrip_and_binding_rejections() {
    for (ell, kh_bits) in [(2, 54), (3, 54), (2, 48), (3, 48), (2, 47)] {
        for pbits in [14, 16] {
            let params =
                NativeParams::new(16, 54, pbits, 19, ell, SecretDistribution::Gaussian).unwrap();
            let profile = NativeProfile::new(params, 32, 48)
                .unwrap()
                .with_kh_bits(kh_bits)
                .unwrap();
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
                let mut req =
                    NativeRequest::generate_with_rng(server.setup(), row, &mut rng).unwrap();
                assert_eq!(
                    req.bytes().len(),
                    36 + (ell * 16 * 54).div_ceil(8)
                        + (ell * 16 * kh_bits).div_ceil(8)
                        + (32usize * 49).div_ceil(8)
                );
                assert_eq!(
                    &req.bytes()[..4],
                    if kh_bits == 54 { b"RNQ1" } else { b"RNQ2" }
                );
                let (response, _) = server.respond(req.bytes()).unwrap();
                let prepared = published.prepare(server.setup()).unwrap();
                assert_eq!(
                    req.decode_prepared(&prepared, &response).unwrap(),
                    req.decode(&published, &response).unwrap()
                );
                req.prepare_decode(&prepared).unwrap();
                assert_eq!(
                    req.decode_prepared(&prepared, &response).unwrap(),
                    req.decode(&published, &response).unwrap()
                );
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
                assert!(other.decode_prepared(&prepared, &response).is_err());
                let mut malformed = req.bytes().to_vec();
                malformed[4] ^= 1;
                assert!(server.respond(&malformed).is_err());
                let wrong = NativePublicSetup::new(profile.clone(), [2; 32], [9; 32]);
                assert!(NativePublished::from_bytes(&wrong, &published.to_bytes()).is_err());
                assert!(published.prepare(&wrong).is_err());
            }
        }
    }
}

#[test]
fn compressed_keys_reject_padding_versions_and_other_precisions() {
    let p = NativeParams::new(2, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    let profile = NativeProfile::new(p, 2, 2).unwrap();
    assert!(profile.clone().with_kh_bits(39).is_err());
    assert!(profile.clone().with_kh_bits(55).is_err());
    let make = |bits| {
        NativePublicSetup::new(
            profile.clone().with_kh_bits(bits).unwrap(),
            [3; 32],
            [4; 32],
        )
    };
    assert_eq!(
        NativePublicSetup::new(profile.clone(), [3; 32], [4; 32]).id(),
        make(54).id()
    );
    assert_ne!(make(47).id(), make(48).id());
    let server = NativeServer::build(make(47), vec![1, 2, 3, 65535]).unwrap();
    let mut req =
        NativeRequest::generate_with_rng(server.setup(), 1, &mut ChaCha20Rng::seed_from_u64(42))
            .unwrap();
    let response = server.respond(req.bytes()).unwrap().0;
    let published = server.published();
    let prepared = published.prepare(server.setup()).unwrap();
    assert_eq!(
        req.decode_prepared(&prepared, &response).unwrap(),
        req.decode(&published, &response).unwrap()
    );
    req.prepare_decode(&prepared).unwrap();
    assert_eq!(
        req.decode_prepared(&prepared, &response).unwrap(),
        req.decode(&published, &response).unwrap()
    );
    assert!(req
        .decode_prepared(&prepared, &response[..response.len() - 1])
        .is_err());
    assert_eq!(
        req.decode(&server.published(), &response).unwrap(),
        vec![2, 65535]
    );
    for pos in [0, 36 + 27 + 24 - 1, req.bytes().len() - 1] {
        let mut bad = req.bytes().to_vec();
        bad[pos] ^= 0x80;
        assert!(server.respond(&bad).is_err());
    }
    let mut bad = req.bytes().to_vec();
    bad[3] = b'1';
    assert!(server.respond(&bad).is_err());
    let mut bad = req.bytes().to_vec();
    bad.push(0);
    assert!(server.respond(&bad).is_err());
    for bits in [48, 54] {
        let other = NativeServer::build(make(bits), vec![1, 2, 3, 65535]).unwrap();
        assert!(other.respond(req.bytes()).is_err());
    }
}

#[test]
fn analysis_preserves_preprocessing_and_response() {
    let p = NativeParams::new(8, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    let profile = NativeProfile::new(p, 16, 16)
        .unwrap()
        .with_kh_bits(48)
        .unwrap();
    let setup = || NativePublicSetup::new(profile.clone(), [7; 32], [19; 32]);
    let db: Vec<u16> = (0..256).map(|i| (i * 251) as u16).collect();
    let original = NativeServer::build(setup(), db.clone()).unwrap();
    let (analyzed, stats) = NativeServer::build_analyzed(setup(), db).unwrap();
    assert_eq!(stats.len(), 2);
    assert!(stats.iter().all(|s| s.packing.kh_l1 <= 2 * 8 * (1 << 18)));
    assert_eq!(
        original.published().to_bytes(),
        analyzed.published().to_bytes()
    );
    let req =
        NativeRequest::generate_with_rng(original.setup(), 7, &mut ChaCha20Rng::seed_from_u64(42))
            .unwrap();
    assert_eq!(
        original.respond(req.bytes()).unwrap().0,
        analyzed.respond(req.bytes()).unwrap().0
    );
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

#[test]
fn prepared_request_rejects_changed_masks_even_with_same_setup_id() {
    let p = NativeParams::new(8, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    let setup = NativePublicSetup::new(NativeProfile::new(p, 8, 8).unwrap(), [21; 32], [22; 32]);
    let server = NativeServer::build(setup, vec![123; 64]).unwrap();
    let published = server.published();
    let prepared = published.prepare(server.setup()).unwrap();
    let mut request =
        NativeRequest::generate_with_rng(server.setup(), 0, &mut ChaCha20Rng::seed_from_u64(777))
            .unwrap();
    request.prepare_decode(&prepared).unwrap();
    let response = server.respond(request.bytes()).unwrap().0;
    assert_eq!(
        request.decode_prepared(&prepared, &response).unwrap(),
        vec![123; 8]
    );
    let mut altered = published.to_bytes();
    altered[36] ^= 1;
    let altered = NativePublished::from_bytes(server.setup(), &altered)
        .unwrap()
        .prepare(server.setup())
        .unwrap();
    assert!(request.decode_prepared(&altered, &response).is_err());
    for len in [0, 1, 4, 35, 67, response.len() - 1] {
        assert!(request
            .decode_prepared(&prepared, &response[..len])
            .is_err());
    }
}

#[test]
fn rounded_public_masks_preserve_bytes_and_reject_mismatches() {
    for bits in 27..=32 {
        let pack = NativeParams::new(8, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
        let base = NativeProfile::new(pack, 16, 24).unwrap();
        assert!(base.clone().with_published_mask_bits(bits).is_err());
        let p = base
            .with_two_mask_output()
            .unwrap()
            .with_published_mask_bits(bits)
            .unwrap();
        assert!(p.clone().with_published_mask_bits(26).is_err());
        assert!(p.clone().with_published_mask_bits(33).is_err());
        let other = NativePublicSetup::new(
            p.clone().with_published_mask_bits(64).unwrap(),
            [31; 32],
            [32; 32],
        );
        let setup = NativePublicSetup::new(p, [31; 32], [32; 32]);
        assert_ne!(setup.id(), other.id());
        let data: Vec<u16> = (0..16 * 24).map(|x| (x * 157) as u16).collect();
        let (server, stats) = NativeServer::build_analyzed(setup, data.clone()).unwrap();
        assert!(stats.iter().all(|s| s.packing.weights
            == s.packing
                .public_mask_screens
                .iter()
                .find(|(b, _)| *b as usize == bits)
                .unwrap()
                .1));
        let bytes = server.published().to_bytes();
        assert_eq!(&bytes[..4], b"RNP3");
        assert_eq!(bytes.len(), 36 + 2 * 24 * bits / 8);
        assert!(bytes.len() <= 36 + 24 * 8);
        let published = NativePublished::from_bytes(server.setup(), &bytes).unwrap();
        assert_eq!(published.to_bytes(), bytes);
        assert!(NativePublished::from_bytes(&other, &bytes).is_err());
        let mut bad = bytes.clone();
        bad[3] = b'2';
        assert!(NativePublished::from_bytes(server.setup(), &bad).is_err());
        for n in [0, 1, 4, 35, bytes.len() - 1] {
            assert!(NativePublished::from_bytes(server.setup(), &bytes[..n]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(NativePublished::from_bytes(server.setup(), &extra).is_err());
        let prepared = published.prepare(server.setup()).unwrap();
        for row in [0, 8, 15] {
            let mut req = NativeRequest::generate_with_rng(
                server.setup(),
                row,
                &mut ChaCha20Rng::seed_from_u64(91 + row as u64),
            )
            .unwrap();
            req.prepare_decode(&prepared).unwrap();
            let response = server.respond(req.bytes()).unwrap().0;
            let expected: Vec<_> = (0..24).map(|c| data[c * 16 + row] as u64).collect();
            assert_eq!(req.decode(&published, &response).unwrap(), expected);
            assert_eq!(req.decode_prepared(&prepared, &response).unwrap(), expected);
            assert_eq!(
                req.decode(&server.published(), &response).unwrap(),
                expected
            );
        }
    }
}

#[test]
fn rounded_public_masks_reject_padding() {
    let p = NativeProfile::new(
        NativeParams::new(2, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap(),
        2,
        2,
    )
    .unwrap()
    .with_two_mask_output()
    .unwrap()
    .with_published_mask_bits(27)
    .unwrap();
    let setup = NativePublicSetup::new(p, [4; 32], [5; 32]);
    let server = NativeServer::build(setup, vec![1; 4]).unwrap();
    let bytes = server.published().to_bytes();
    assert_eq!(bytes.len(), 50); // 4 coefficients * 27 bits, 4 padding bits
    let mut bad = bytes.clone();
    *bad.last_mut().unwrap() |= 0x80;
    assert!(NativePublished::from_bytes(server.setup(), &bad).is_err());
}
