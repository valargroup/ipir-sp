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
    for (two_mask, bits) in [false, true].into_iter().flat_map(|two_mask| {
        (if two_mask { 27 } else { 28 }..=32)
            .chain([54])
            .map(move |bits| (two_mask, bits))
    }) {
        let pack = NativeParams::new(8, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
        let base = NativeProfile::new(pack, 16, 24).unwrap();
        // One-mask publication accepts lossless 54 and rounded 28..=32 only.
        assert_eq!(
            base.clone().with_published_mask_bits(bits).is_ok(),
            bits >= 28
        );
        assert!(base.clone().with_published_mask_bits(54).is_ok());
        assert!(base.clone().with_published_mask_bits(27).is_err());
        let mode = if two_mask {
            base.clone().with_two_mask_output().unwrap()
        } else {
            base.clone()
        };
        let p = mode.with_published_mask_bits(bits).unwrap();
        let opposite = if two_mask {
            base
        } else {
            base.with_two_mask_output().unwrap()
        };
        let opposite = NativePublicSetup::new(
            opposite.with_published_mask_bits(bits.max(28)).unwrap(),
            [31; 32],
            [32; 32],
        );
        let different_precision = NativePublicSetup::new(
            p.clone()
                .with_published_mask_bits(if bits == 28 { 29 } else { 28 })
                .unwrap(),
            [31; 32],
            [32; 32],
        );
        let different_snapshot = NativePublicSetup::new(p.clone(), [31; 32], [33; 32]);
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
        if bits != 54 {
            assert!(stats.iter().all(|s| s.packing.weights
                == s.packing
                    .public_mask_screens
                    .iter()
                    .find(|(b, _)| *b as usize == bits)
                    .unwrap()
                    .1));
        }
        let bytes = server.published().to_bytes();
        assert_eq!(&bytes[..4], b"RNP3");
        assert_eq!(
            bytes.len(),
            36 + (1 + usize::from(two_mask)) * 24 * bits / 8
        );
        let published = NativePublished::from_bytes(server.setup(), &bytes).unwrap();
        assert_eq!(published.to_bytes(), bytes);
        for mismatched in [&other, &opposite, &different_precision, &different_snapshot] {
            assert_ne!(server.setup().id(), mismatched.id());
            assert!(NativePublished::from_bytes(mismatched, &bytes).is_err());
            // Isolate setup binding from length checks by forging only the header.
            let mut wrong_id = bytes.clone();
            wrong_id[4..36].copy_from_slice(&mismatched.id());
            assert!(NativePublished::from_bytes(server.setup(), &wrong_id).is_err());
        }
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
    // d=2 leaves padding in one-mask 29/54-bit and two-mask 27-bit layouts.
    for (two_mask, bits) in [(false, 29), (false, 54), (true, 27)] {
        let p = NativeProfile::new(
            NativeParams::new(2, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap(),
            2,
            2,
        )
        .unwrap();
        let p = if two_mask {
            p.with_two_mask_output().unwrap()
        } else {
            p
        };
        let p = p.with_published_mask_bits(bits).unwrap();
        let setup = NativePublicSetup::new(p, [4; 32], [5; 32]);
        let server = NativeServer::build(setup, vec![1; 4]).unwrap();
        let bytes = server.published().to_bytes();
        let count = 2 * (1 + usize::from(two_mask));
        assert_ne!(count * bits % 8, 0);
        assert_eq!(bytes.len(), 36 + (count * bits).div_ceil(8));
        assert!(NativePublished::from_bytes(server.setup(), &bytes).is_ok());
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() |= 0x80;
        assert!(NativePublished::from_bytes(server.setup(), &bad).is_err());
    }
}

#[test]
fn dithered_queries_roundtrip_and_bind_precision() {
    let pack = NativeParams::new(8, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    let base = NativeProfile::new(pack, 16, 24).unwrap();
    assert_eq!((base.query_bits(), base.is_dithered_query()), (49, false));
    for bits in [0, 42, 50, 54] {
        assert!(base.clone().with_dithered_query_bits(bits).is_err());
    }
    let small = NativeParams::new(2, 17, 1, 9, 2, SecretDistribution::Gaussian).unwrap();
    assert!(NativeProfile::new(small, 2, 2)
        .unwrap()
        .with_dithered_query_bits(45)
        .is_err());
    let data: Vec<u16> = (0..16 * 24).map(|x| (x * 157) as u16).collect();
    // Query precision composes with reduced K_h precision in either order.
    assert_eq!(
        base.clone()
            .with_dithered_query_bits(45)
            .unwrap()
            .with_kh_bits(47)
            .unwrap(),
        base.clone()
            .with_kh_bits(47)
            .unwrap()
            .with_dithered_query_bits(45)
            .unwrap()
    );
    let modes = [
        base.clone(),
        base.clone().with_kh_bits(47).unwrap(),
        base.clone().with_two_mask_output().unwrap(),
        base.clone().with_published_mask_bits(28).unwrap(),
        base.clone()
            .with_two_mask_output()
            .unwrap()
            .with_published_mask_bits(29)
            .unwrap(),
    ];
    for mode in modes {
        let nearest = NativeServer::build(
            NativePublicSetup::new(mode.clone(), [31; 32], [32; 32]),
            data.clone(),
        )
        .unwrap();
        for bits in [43, 45, 49] {
            let p = mode.clone().with_dithered_query_bits(bits).unwrap();
            assert_eq!((p.query_bits(), p.is_dithered_query()), (bits, true));
            let setup = NativePublicSetup::new(p, [31; 32], [32; 32]);
            let other = NativePublicSetup::new(
                mode.clone()
                    .with_dithered_query_bits(if bits == 43 { 44 } else { 43 })
                    .unwrap(),
                [31; 32],
                [32; 32],
            );
            assert_ne!(setup.id(), nearest.setup().id());
            assert_ne!(setup.id(), other.id());
            let server = NativeServer::build(setup, data.clone()).unwrap();
            let published = server.published();
            let mut rng = ChaCha20Rng::seed_from_u64(bits as u64);
            for target in [0, 7, 15] {
                let request =
                    NativeRequest::generate_with_rng(server.setup(), target, &mut rng).unwrap();
                let legacy =
                    NativeRequest::generate_with_rng(nearest.setup(), target, &mut rng).unwrap();
                assert_eq!(
                    legacy.bytes().len() - request.bytes().len(),
                    (16 * 49usize).div_ceil(8) - (16 * bits).div_ceil(8)
                );
                let response = server.respond(request.bytes()).unwrap().0;
                let expected: Vec<u64> = (0..24).map(|c| data[c * 16 + target] as u64).collect();
                assert_eq!(request.decode(&published, &response).unwrap(), expected);
                // Precision is bound into the setup: no cross-acceptance.
                assert!(nearest.respond(request.bytes()).is_err());
                assert!(server.respond(legacy.bytes()).is_err());
                let truncated = &request.bytes()[..request.bytes().len() - 1];
                assert!(server.respond(truncated).is_err());
            }
        }
    }
}

#[test]
fn dithered_queries_reject_padding() {
    // d=2 with two rows leaves padding after an odd-width query body.
    let pack = NativeParams::new(2, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    for two_mask in [false, true] {
        for bits in [43, 45, 49] {
            let p = NativeProfile::new(pack.clone(), 2, 2).unwrap();
            let p = if two_mask {
                p.with_two_mask_output().unwrap()
            } else {
                p
            };
            let setup =
                NativePublicSetup::new(p.with_dithered_query_bits(bits).unwrap(), [4; 32], [5; 32]);
            let server = NativeServer::build(setup, vec![1, 2, 3, 65535]).unwrap();
            let request = NativeRequest::generate_with_rng(
                server.setup(),
                1,
                &mut ChaCha20Rng::seed_from_u64(bits as u64),
            )
            .unwrap();
            assert_ne!(2 * bits % 8, 0);
            let response = server.respond(request.bytes()).unwrap().0;
            assert_eq!(
                request.decode(&server.published(), &response).unwrap(),
                vec![2, 65535]
            );
            let mut bad = request.bytes().to_vec();
            *bad.last_mut().unwrap() |= 0x80;
            assert!(server.respond(&bad).is_err());
        }
    }
}

fn p8_db<T: From<u8>>(rows: usize, cols: usize) -> Vec<T> {
    (0..cols)
        .flat_map(|c| (0..rows).map(move |r| T::from(((r * 19 + c * 31 + 7) % 256) as u8)))
        .collect()
}

#[test]
fn p8_transport_floors_and_response_knob() {
    let p8 = NativeParams::new(16, 54, 8, 19, 2, SecretDistribution::Gaussian).unwrap();
    let p16 = NativeParams::new(16, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    let base8 = NativeProfile::new(p8.clone(), 32, 48).unwrap();
    let base16 = NativeProfile::new(p16.clone(), 32, 48).unwrap();
    // Dithered query floor: 24 at p8, unchanged 43 at p16.
    assert!(base8.clone().with_dithered_query_bits(24).is_ok());
    assert!(base8.clone().with_dithered_query_bits(23).is_err());
    assert!(base16.clone().with_dithered_query_bits(43).is_ok());
    assert!(base16.clone().with_dithered_query_bits(42).is_err());
    // Two-mask mask floor: 16 at p8, unchanged 27 at p16; one-mask stays 28.
    let two8 = base8.clone().with_two_mask_output().unwrap();
    assert!(two8.clone().with_published_mask_bits(16).is_ok());
    assert!(two8.clone().with_published_mask_bits(15).is_err());
    let two16 = base16.clone().with_two_mask_output().unwrap();
    assert!(two16.clone().with_published_mask_bits(27).is_ok());
    assert!(two16.clone().with_published_mask_bits(26).is_err());
    assert!(base8.clone().with_published_mask_bits(28).is_ok());
    assert!(base8.clone().with_published_mask_bits(27).is_err());
    // Response precision: p_bits+1 ..= p_bits+6; the default keeps setup IDs.
    assert_eq!(base8.response_bits(), 14);
    assert_eq!(base16.response_bits(), 22);
    assert!(base8.clone().with_response_bits(8).is_err());
    assert!(base8.clone().with_response_bits(15).is_err());
    let r10 = base8.clone().with_response_bits(10).unwrap();
    assert_eq!(r10.response_bits(), 10);
    let default_id = NativePublicSetup::new(base8.clone(), [1; 32], [2; 32]).id();
    let same_id = NativePublicSetup::new(
        base8.clone().with_response_bits(14).unwrap(),
        [1; 32],
        [2; 32],
    )
    .id();
    assert_eq!(default_id, same_id);
    assert_ne!(
        NativePublicSetup::new(r10, [1; 32], [2; 32]).id(),
        default_id
    );
    // Size guard counts entries per storage byte: 2^31 entries at p <= 2^8.
    let big8 = NativeParams::new(2048, 54, 8, 19, 2, SecretDistribution::Gaussian).unwrap();
    let big16 = NativeParams::new(2048, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    assert!(NativeProfile::new(big8, 28672, 65536).is_ok());
    assert!(NativeProfile::new(big16, 28672, 65536).is_err());
}

#[test]
fn p8_u8_and_u16_storage_respond_identically_for_both_gadgets() {
    for (gadget, ell) in [(19, 2), (27, 1)] {
        let params =
            NativeParams::new(16, 54, 8, gadget, ell, SecretDistribution::Gaussian).unwrap();
        let profile = NativeProfile::new(params, 32, 64)
            .unwrap()
            .with_two_mask_output()
            .unwrap()
            .with_published_mask_bits(20)
            .unwrap()
            .with_dithered_query_bits(28)
            .unwrap()
            .with_response_bits(10)
            .unwrap();
        let wide = NativeServer::build(
            NativePublicSetup::new(profile.clone(), [5; 32], [6; 32]),
            p8_db::<u16>(32, 64),
        )
        .unwrap();
        let narrow = NativeServer::build_u8_with_concurrency(
            NativePublicSetup::new(profile.clone(), [5; 32], [6; 32]),
            p8_db::<u8>(32, 64),
            2,
        )
        .unwrap();
        assert!(narrow.is_u8_storage() && !wide.is_u8_storage());
        assert_eq!(narrow.database_bytes() * 2, wide.database_bytes());
        assert_eq!(wide.published().to_bytes(), narrow.published().to_bytes());
        let published = narrow.published();
        let mut rng = ChaCha20Rng::seed_from_u64(77 + gadget as u64);
        for row in [0, 13, 31] {
            let req = NativeRequest::generate_with_rng(narrow.setup(), row, &mut rng).unwrap();
            let (from_narrow, _) = narrow.respond(req.bytes()).unwrap();
            let (from_wide, _) = wide.respond(req.bytes()).unwrap();
            assert_eq!(from_narrow, from_wide, "gadget={gadget} row={row}");
            let expected: Vec<u64> = (0..64)
                .map(|c| ((row * 19 + c * 31 + 7) % 256) as u64)
                .collect();
            assert_eq!(req.decode(&published, &from_narrow).unwrap(), expected);
            assert_eq!(from_narrow.len(), 68 + 64 * 10 / 8);
        }
        assert_eq!(narrow.matrix_storage().len(), 64 / 16);
        assert!(narrow.matrix_magnitude_bits().iter().all(|&b| b > 0));
    }
    // Rejections: entries must be below p, and u8 storage needs p <= 2^8.
    let p7 = NativeParams::new(16, 54, 7, 19, 2, SecretDistribution::Gaussian).unwrap();
    let setup = NativePublicSetup::new(NativeProfile::new(p7, 32, 64).unwrap(), [5; 32], [6; 32]);
    assert!(NativeServer::build_u8_with_concurrency(setup, vec![200; 32 * 64], 1).is_err());
    let p16 = NativeParams::new(16, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    let setup = NativePublicSetup::new(NativeProfile::new(p16, 32, 64).unwrap(), [5; 32], [6; 32]);
    assert!(NativeServer::build_u8_with_concurrency(setup, vec![1; 32 * 64], 1).is_err());
}

#[test]
fn p8_analyzed_build_screens_coarse_masks_and_tiny_shapes_use_columns() {
    let params = NativeParams::new(16, 54, 8, 19, 2, SecretDistribution::Gaussian).unwrap();
    let profile = NativeProfile::new(params, 32, 64)
        .unwrap()
        .with_two_mask_output()
        .unwrap()
        .with_published_mask_bits(18)
        .unwrap();
    let (server, blocks) = NativeServer::build_u8_analyzed(
        NativePublicSetup::new(profile, [8; 32], [9; 32]),
        p8_db::<u8>(32, 64),
    )
    .unwrap();
    assert_eq!(blocks.len(), 4);
    for block in &blocks {
        let bits: Vec<u32> = block
            .packing
            .public_mask_screens
            .iter()
            .map(|(b, _)| *b)
            .collect();
        assert_eq!(bits, (16..=32).collect::<Vec<_>>());
        let selected = block
            .packing
            .public_mask_screens
            .iter()
            .find(|(b, _)| *b == 18)
            .unwrap()
            .1;
        assert_eq!(block.packing.weights, selected);
    }
    // d = 2 shapes (rows not divisible into 16-column bands) use column storage.
    let tiny = NativeParams::new(2, 54, 8, 19, 2, SecretDistribution::Gaussian).unwrap();
    let setup = NativePublicSetup::new(NativeProfile::new(tiny, 2, 2).unwrap(), [3; 32], [4; 32]);
    let server2 = NativeServer::build_u8_with_concurrency(setup, vec![7, 200, 13, 255], 1).unwrap();
    let published = server2.published();
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    for row in 0..2 {
        let req = NativeRequest::generate_with_rng(server2.setup(), row, &mut rng).unwrap();
        let (response, _) = server2.respond(req.bytes()).unwrap();
        let expected = [[7u64, 13], [200, 255]][row];
        assert_eq!(req.decode(&published, &response).unwrap(), expected);
    }
    drop(server);
}
