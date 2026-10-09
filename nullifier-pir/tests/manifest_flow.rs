//! A served snapshot, its manifest, and a client that checks both: the
//! generator's row digests must match what the client decodes.
//!
//! Uses the production profile at its smallest shape (2048 rows, the last one
//! short), so the manifest describes exactly what `serve` would publish.

use std::io::{BufWriter, Seek, SeekFrom, Write};

use ed25519_dalek::SigningKey;
use ipir_sp::client::{ClientError, IPIRClient};
use ipir_sp::serialize::serialize_packing_keys;
use ipir_sp::{ProductionSimplePirParams, SimplePirProfile, VerifiedPublicParams};
use nullifier_pir::backend::{seed_from_u64, LocalIpirBackend, PirBackend};
use nullifier_pir::manifest::{generate, publish, ManifestArtifacts};
use nullifier_pir::{
    extract_nullifier, NullifierSnapshot, ITEM_BYTES, ITEM_SIZE_BITS, NULLIFIERS_PER_ITEM,
    NULLIFIER_BYTES,
};
use tempfile::TempDir;

const SETUP_SEED: u64 = 7;
/// Public, test-only dev signing seed.
const DEV_SEED: [u8; 32] = [0x5D; 32];
/// 2048 PIR rows, the smallest production shape; the last row is short.
const RECORDS: usize = 2047 * NULLIFIERS_PER_ITEM + 5;
const TARGET: usize = 3;

fn record(index: usize) -> [u8; NULLIFIER_BYTES] {
    let mut out = [0u8; NULLIFIER_BYTES];
    out[..8].copy_from_slice(
        &(index as u64 + 1)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .to_le_bytes(),
    );
    out[31] = 0x42;
    out
}

fn write_snapshot(dir: &TempDir) -> NullifierSnapshot {
    let path = dir.path().join("nullifiers.bin");
    let mut file = BufWriter::new(std::fs::File::create(&path).unwrap());
    for index in 0..RECORDS {
        file.write_all(&record(index)).unwrap();
    }
    file.flush().unwrap();
    NullifierSnapshot::open(&path).unwrap()
}

/// The same snapshot with every record of PIR row 0 zeroed.
fn write_blanked_copy(dir: &TempDir, snapshot: &NullifierSnapshot) -> NullifierSnapshot {
    let path = dir.path().join("blanked").join("nullifiers.bin");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::copy(snapshot.path(), &path).unwrap();
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&vec![0u8; ITEM_BYTES]).unwrap();
    NullifierSnapshot::open(&path).unwrap()
}

fn verify(
    profile: &ProductionSimplePirParams,
    key: &SigningKey,
    artifacts: &ManifestArtifacts,
    public_params: &[u8],
) -> Result<VerifiedPublicParams, ClientError> {
    VerifiedPublicParams::verify(
        profile,
        SETUP_SEED,
        &key.verifying_key().to_bytes(),
        &artifacts.manifest,
        &artifacts.signature.expect("signed"),
        public_params,
        &artifacts.row_digests,
    )
}

#[test]
fn served_manifest_authenticates_answers_and_catches_a_tampered_server() {
    let dir = TempDir::new().unwrap();
    let snapshot = write_snapshot(&dir);
    assert_eq!(snapshot.pir_row_count(), 2048);
    let backend = LocalIpirBackend::prepare(&snapshot, SETUP_SEED).expect("backend");
    let params = backend.production_params().expect("production profile");
    let public_params = backend.public_params();
    let (manifest, table) = generate(&snapshot, params, SETUP_SEED, &public_params).unwrap();
    let key = SigningKey::from_bytes(&DEV_SEED);
    let artifacts = publish(dir.path(), &manifest, &table, Some(&key)).unwrap();
    assert_eq!(manifest.db_rows as usize, backend.meta().db_rows);
    assert_eq!(
        manifest.snapshot_sha256,
        nullifier_pir::sha256_file(snapshot.path()).unwrap()
    );

    // Client side: everything is checked before a query exists.
    let meta = backend.meta();
    let profile = ProductionSimplePirParams::new(
        meta.pir_item_count as u64,
        ITEM_SIZE_BITS,
        SimplePirProfile::P14,
    )
    .unwrap();
    let verified = verify(&profile, &key, &artifacts, &public_params).expect("verifies");
    assert!(matches!(
        verify(
            &profile,
            &SigningKey::from_bytes(&[0x01; 32]),
            &artifacts,
            &public_params
        ),
        Err(ClientError::BadSignature)
    ));

    let client = IPIRClient::new(&profile);
    assert_eq!(verified.setup_seed(), seed_from_u64(SETUP_SEED));
    let setup = client.generate_public_query_setup_simplepir_from_seed(verified.setup_seed());
    let (query, keys, client_seed) = client.generate_fresh_query_simplepir(&setup, 0);
    let mut body = serialize_packing_keys(client.rlwe_params(), &keys).unwrap();
    body.extend(query.to_switched_bytes(client.rlwe_params().q, client.params().query_bits));

    let answer = backend.answer_query(&body).expect("answer");
    let row = client
        .decode_response_simplepir_verified(client_seed, &verified, &answer.body, 0)
        .expect("honest answer authenticates");
    assert_eq!(extract_nullifier(&row, TARGET), Some(record(TARGET)));

    // If the served database differs from the signed one in row 0, the
    // answer for row 0 fails its digest. (A server answering from a modified
    // copy, end to end, is covered in ipir-sp's production flow test; a second
    // production backend here would double this test's run time.)
    let blanked = write_blanked_copy(&dir, &snapshot);
    let (signed_blank, blank_table) =
        generate(&blanked, params, SETUP_SEED, &public_params).unwrap();
    assert_ne!(blank_table.get(0), table.get(0));
    assert_eq!(blank_table.get(1), table.get(1));
    let blank_dir = TempDir::new().unwrap();
    let blank_artifacts =
        publish(blank_dir.path(), &signed_blank, &blank_table, Some(&key)).unwrap();
    let mismatched = verify(&profile, &key, &blank_artifacts, &public_params).expect("verifies");
    assert_eq!(
        client.decode_response_simplepir_verified(client_seed, &mismatched, &answer.body, 0),
        Err(ClientError::TamperDetected { row: 0 })
    );
}
