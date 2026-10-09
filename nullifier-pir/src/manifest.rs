//! Snapshot manifest and row-digest artefacts served next to the PIR endpoints.
//!
//! For every served snapshot the server writes, next to the snapshot file:
//!
//! - `manifest.json`: the [`SnapshotManifest`] bytes the coordinator signs;
//! - `row-digests.bin`: the [`RowDigestTable`], 32 bytes per PIR row;
//! - `manifest.sig` (optional, provided by the coordinator): the Ed25519
//!   signature over the exact `manifest.json` bytes, as 128 hex characters or
//!   64 raw bytes.
//!
//! Production signatures come from the coordinator, which holds the key; the
//! server never needs it. `--dev-sign-key-file` signs locally for tests and
//! local runs only, and its key must never be pinned by a real client.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use ipir_sp::manifest::{RowDigestTable, SnapshotManifest, SIGNATURE_BYTES};
use ipir_sp::ProductionSimplePirParams;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::snapshot::NullifierSnapshot;

pub const MANIFEST_FILE: &str = "manifest.json";
pub const ROW_DIGESTS_FILE: &str = "row-digests.bin";
pub const SIGNATURE_FILE: &str = "manifest.sig";
/// Suffix given to a manifest or signature that no longer matches the
/// snapshot being served. Renamed, never deleted, so an operator can inspect it.
pub const STALE_SUFFIX: &str = "stale";

/// The manifest and digest table for one snapshot, plus a signature if one
/// is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestArtifacts {
    /// Exact manifest bytes; what the signature covers.
    pub manifest: Vec<u8>,
    /// Serialized row digest table, the `GET /row-digests` body.
    pub row_digests: Vec<u8>,
    /// Coordinator (or dev) signature over `manifest`.
    pub signature: Option<[u8; SIGNATURE_BYTES]>,
}

impl ManifestArtifacts {
    /// Lowercase hex SHA-256 of the manifest bytes, reported in `/meta`.
    #[must_use]
    pub fn manifest_sha256(&self) -> String {
        hex::encode(Sha256::digest(&self.manifest))
    }

    /// The `GET /manifest` body.
    #[must_use]
    pub fn envelope(&self) -> ManifestEnvelope {
        ManifestEnvelope {
            manifest: base64::engine::general_purpose::STANDARD.encode(&self.manifest),
            signature: self.signature.map(hex::encode),
        }
    }
}

/// `GET /manifest` response: the exact signed bytes and the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEnvelope {
    /// Standard base64 of the exact manifest bytes.
    pub manifest: String,
    /// Hex Ed25519 signature over those bytes, or `null` when the server has
    /// no signature for this snapshot yet.
    pub signature: Option<String>,
}

impl ManifestEnvelope {
    /// Decode into `(manifest bytes, signature bytes)`. Neither is trusted
    /// until [`ipir_sp::VerifiedPublicParams::verify`] accepts them.
    pub fn decode(&self) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        let manifest = base64::engine::general_purpose::STANDARD
            .decode(&self.manifest)
            .context("manifest is not valid base64")?;
        let signature = self
            .signature
            .as_deref()
            .map(hex::decode)
            .transpose()
            .context("manifest signature is not valid hex")?;
        Ok((manifest, signature))
    }
}

/// Compute the manifest and row digest table for a snapshot served with
/// `params` and `setup_seed`, whose `GET /public-params` body is
/// `public_params`. Reads the whole snapshot once.
pub fn generate(
    snapshot: &NullifierSnapshot,
    params: &ProductionSimplePirParams,
    setup_seed: u64,
    public_params: &[u8],
) -> Result<(SnapshotManifest, RowDigestTable)> {
    let ypir = params.ypir();
    let digests = snapshot
        .digest_rows(ypir.db_rows, ypir.db_cols, ypir.p)
        .context("hash snapshot rows")?;
    let manifest = SnapshotManifest::new(
        params,
        setup_seed,
        digests.snapshot_sha256,
        public_params,
        &digests.row_digests,
    )?;
    Ok((manifest, digests.row_digests))
}

/// Directory the artefacts for `snapshot_path` live in.
#[must_use]
pub fn artifact_dir(snapshot_path: &Path) -> PathBuf {
    match snapshot_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Write the artefacts into `dir` and load the signature, if any.
///
/// An existing `manifest.json` that parses to the same manifest is kept
/// byte-for-byte, because a coordinator signature covers those bytes. One that
/// describes something else is stale: it and any `manifest.sig` are renamed
/// with a `.stale` suffix, so a signature for an older snapshot is never
/// served next to a newer manifest. With `dev_key`, a fresh signature is
/// written; that path is for tests and local runs only.
pub fn publish(
    dir: &Path,
    manifest: &SnapshotManifest,
    row_digests: &RowDigestTable,
    dev_key: Option<&SigningKey>,
) -> Result<ManifestArtifacts> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let manifest_path = dir.join(MANIFEST_FILE);
    let signature_path = dir.join(SIGNATURE_FILE);

    let existing = match fs::read(&manifest_path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("read {}", manifest_path.display()));
        }
    };
    let manifest_bytes = match existing {
        Some(bytes)
            if serde_json::from_slice::<SnapshotManifest>(&bytes)
                .ok()
                .as_ref()
                == Some(manifest) =>
        {
            bytes
        }
        Some(_) => {
            eprintln!(
                "warning: {} describes a different snapshot; renaming it and any {SIGNATURE_FILE} to *.{STALE_SUFFIX}",
                manifest_path.display()
            );
            mark_stale(&manifest_path)?;
            mark_stale(&signature_path)?;
            write_file(&manifest_path, &manifest.to_bytes())?
        }
        None => write_file(&manifest_path, &manifest.to_bytes())?,
    };
    let row_digests = row_digests.to_bytes();
    write_file(&dir.join(ROW_DIGESTS_FILE), &row_digests)?;

    if let Some(key) = dev_key {
        let signature = key.sign(&manifest_bytes).to_bytes();
        write_file(
            &signature_path,
            format!("{}\n", hex::encode(signature)).as_bytes(),
        )?;
    }
    let signature = match fs::read(&signature_path) {
        Ok(bytes) => Some(
            parse_signature(&bytes)
                .with_context(|| format!("parse {}", signature_path.display()))?,
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("read {}", signature_path.display()));
        }
    };

    Ok(ManifestArtifacts {
        manifest: manifest_bytes,
        row_digests,
        signature,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<Vec<u8>> {
    // Write then rename so a reader never sees a half-written artefact.
    let tmp = path.with_extension("part");
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("move {} into place", path.display()))?;
    Ok(bytes.to_vec())
}

fn mark_stale(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut stale = path.as_os_str().to_owned();
    stale.push(".");
    stale.push(STALE_SUFFIX);
    fs::rename(path, &stale).with_context(|| format!("rename stale {}", path.display()))
}

/// Parse a signature file: 64 raw bytes, or 128 hex characters with optional
/// surrounding whitespace.
pub fn parse_signature(bytes: &[u8]) -> Result<[u8; SIGNATURE_BYTES]> {
    if let Ok(raw) = <[u8; SIGNATURE_BYTES]>::try_from(bytes) {
        return Ok(raw);
    }
    let text = std::str::from_utf8(bytes).context("signature is neither 64 raw bytes nor hex")?;
    let decoded = hex::decode(text.trim()).context("signature is not valid hex")?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        anyhow::anyhow!(
            "signature must be {SIGNATURE_BYTES} bytes, got {}",
            decoded.len()
        )
    })
}

/// Read a dev signing key: a file holding the 32-byte Ed25519 seed as hex.
pub fn read_dev_signing_key(path: &Path) -> Result<SigningKey> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let seed = hex::decode(text.trim()).context("dev signing key is not valid hex")?;
    let Ok(seed) = <[u8; 32]>::try_from(seed.as_slice()) else {
        bail!("dev signing key must be a 32-byte seed (64 hex characters)");
    };
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use ipir_sp::manifest::verify_manifest_signature;
    use ipir_sp::SimplePirProfile;
    use tempfile::TempDir;

    use super::*;

    const DEV_SEED: [u8; 32] = [0x44; 32];

    fn sample(seed: u64) -> (SnapshotManifest, RowDigestTable) {
        let params =
            ProductionSimplePirParams::new(2048, crate::ITEM_SIZE_BITS, SimplePirProfile::P14)
                .expect("profile");
        let table = RowDigestTable::from_digests(vec![[seed as u8; 32]; params.ypir().db_rows]);
        let manifest =
            SnapshotManifest::new(&params, seed, [1; 32], b"c1", &table).expect("manifest");
        (manifest, table)
    }

    #[test]
    fn publish_writes_artifacts_and_signs_with_dev_key() {
        let dir = TempDir::new().unwrap();
        let (manifest, table) = sample(7);
        let unsigned = publish(dir.path(), &manifest, &table, None).unwrap();
        assert_eq!(unsigned.signature, None);
        assert_eq!(unsigned.manifest, manifest.to_bytes());
        assert_eq!(
            fs::read(dir.path().join(ROW_DIGESTS_FILE)).unwrap(),
            table.to_bytes()
        );

        let key = SigningKey::from_bytes(&DEV_SEED);
        let signed = publish(dir.path(), &manifest, &table, Some(&key)).unwrap();
        let signature = signed.signature.expect("signed");
        verify_manifest_signature(
            &key.verifying_key().to_bytes(),
            &signed.manifest,
            &signature,
        )
        .expect("dev signature verifies");

        // A later start without the key still serves the stored signature.
        let reloaded = publish(dir.path(), &manifest, &table, None).unwrap();
        assert_eq!(reloaded, signed);

        let (decoded, sig) = signed.envelope().decode().unwrap();
        assert_eq!(decoded, signed.manifest);
        assert_eq!(sig.as_deref(), Some(signature.as_slice()));
        assert_eq!(signed.manifest_sha256().len(), 64);
    }

    /// A coordinator-signed file is served byte-for-byte even if this build
    /// would format it differently.
    #[test]
    fn publish_keeps_equivalent_signed_bytes() {
        let dir = TempDir::new().unwrap();
        let (manifest, table) = sample(7);
        let compact = serde_json::to_vec(&manifest).unwrap();
        fs::write(dir.path().join(MANIFEST_FILE), &compact).unwrap();
        let key = SigningKey::from_bytes(&DEV_SEED);
        fs::write(
            dir.path().join(SIGNATURE_FILE),
            key.sign(&compact).to_bytes(),
        )
        .unwrap();

        let served = publish(dir.path(), &manifest, &table, None).unwrap();
        assert_eq!(served.manifest, compact);
        verify_manifest_signature(
            &key.verifying_key().to_bytes(),
            &served.manifest,
            &served.signature.unwrap(),
        )
        .expect("coordinator signature still verifies");
    }

    #[test]
    fn publish_retires_a_stale_manifest_and_signature() {
        let dir = TempDir::new().unwrap();
        let key = SigningKey::from_bytes(&DEV_SEED);
        let (old, old_table) = sample(7);
        publish(dir.path(), &old, &old_table, Some(&key)).unwrap();

        let (new, new_table) = sample(8);
        let served = publish(dir.path(), &new, &new_table, None).unwrap();
        assert_eq!(served.manifest, new.to_bytes());
        assert_eq!(served.signature, None, "old signature must not be served");
        assert!(dir.path().join("manifest.json.stale").exists());
        assert!(dir.path().join("manifest.sig.stale").exists());
    }

    #[test]
    fn signature_files_parse_as_raw_or_hex() {
        let raw = [9u8; SIGNATURE_BYTES];
        assert_eq!(parse_signature(&raw).unwrap(), raw);
        assert_eq!(
            parse_signature(format!(" {}\n", hex::encode(raw)).as_bytes()).unwrap(),
            raw
        );
        assert!(parse_signature(b"abcd").is_err());
        assert!(parse_signature(&[0u8; 63]).is_err());
    }

    #[test]
    fn dev_key_file_must_hold_a_hex_seed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dev.key");
        fs::write(&path, format!("{}\n", hex::encode(DEV_SEED))).unwrap();
        assert_eq!(read_dev_signing_key(&path).unwrap().to_bytes(), DEV_SEED);
        fs::write(&path, "00").unwrap();
        assert!(read_dev_signing_key(&path).is_err());
    }

    #[test]
    fn artifact_dir_handles_bare_file_names() {
        assert_eq!(
            artifact_dir(Path::new("nullifiers.bin")),
            PathBuf::from(".")
        );
        assert_eq!(
            artifact_dir(Path::new("data/nullifiers.bin")),
            PathBuf::from("data")
        );
    }
}
