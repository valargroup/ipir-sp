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
