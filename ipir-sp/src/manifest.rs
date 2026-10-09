//! Coordinator-signed snapshot manifests and response authentication.
//!
//! PIR hides which row a client asks for from a server that follows the
//! protocol. It does not authenticate the answer: both the published `c1` rows
//! (`GET /public-params`) and every response body (`c2`) are chosen by the
//! server. Two consequences:
//!
//! - A server that publishes `c1 = Δ` and answers `c2 = 0` makes the decoded
//!   "row" equal the client's secret key modulo `p`. Decoded output is
//!   therefore key-equivalent until `c1` is trusted.
//! - A server answering from a modified database (for example with half the
//!   rows blanked) changes what the client decodes, and learns a bit from any
//!   client behaviour that depends on the decoded row.
//!
//! The coordinator signs a [`SnapshotManifest`] binding the profile, shape and
//! setup seed, the SHA-256 of the exact `/public-params` bytes, and the SHA-256
//! of a [`RowDigestTable`] holding one digest per PIR row. A client builds
//! [`VerifiedPublicParams`] from those artefacts and a pinned Ed25519 key
//! *before* sending its first query, then decodes with
//! [`crate::IPIRClient::decode_response_simplepir_verified`], which rejects any
//! row whose digest does not match. The client downloads the whole table, so
//! no per-row fetch reveals the target. Nothing on the PIR wire changes.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bits::u64s_to_contiguous_bytes;
use crate::client::{ClientError, IPIRSeed};
use crate::modulus_switch::recover_published_c1;
use crate::params::ProductionSimplePirParams;

/// The only manifest format this crate understands.
pub const MANIFEST_VERSION: u32 = 1;
/// Bytes per [`RowDigestTable`] entry (SHA-256).
pub const ROW_DIGEST_BYTES: usize = 32;
/// Length of an Ed25519 public key.
pub const COORDINATOR_KEY_BYTES: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;

/// Description of one served snapshot, signed by the coordinator.
///
/// The signature is Ed25519 over the exact manifest bytes as served (see
/// [`Self::to_bytes`]); clients verify those bytes before parsing them, so the
/// JSON layout never has to be canonicalised. Digests are lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    /// Manifest format version, [`MANIFEST_VERSION`].
    pub version: u32,
    /// SHA-256 of the raw snapshot file the database was built from.
    pub snapshot_sha256: String,
    /// [`crate::SimplePirProfile::id`] of the served profile.
    pub profile_id: String,
    /// Setup seed as a `u64`, expanded with [`setup_seed_from_u64`].
    pub setup_seed: u64,
    /// SimplePIR rows, including padding rows.
    pub db_rows: u64,
    /// SimplePIR columns (plaintext coefficients per row).
    pub db_cols: u64,
    /// Item size the profile was derived for.
    pub item_size_bits: u64,
    /// SHA-256 over the exact `GET /public-params` body, i.e. the output of
    /// [`crate::server::published_c1_rows`].
    pub c1_sha256: String,
    /// SHA-256 over the exact `GET /row-digests` body.
    pub row_digests_sha256: String,
    /// Bytes per row digest; always [`ROW_DIGEST_BYTES`].
    pub row_digest_bytes: u64,
    /// Number of row digests; always `db_rows`.
    pub row_count: u64,
}

impl SnapshotManifest {
    /// Describe a snapshot served under `params`.
    ///
    /// Used by the server-side generator. `public_params` must be the exact
    /// `GET /public-params` body and `row_digests` the table built from the
    /// same database.
    pub fn new(
        params: &ProductionSimplePirParams,
        setup_seed: u64,
        snapshot_sha256: [u8; 32],
        public_params: &[u8],
        row_digests: &RowDigestTable,
    ) -> Result<Self, ClientError> {
        let ypir = params.ypir();
        if row_digests.len() != ypir.db_rows {
            return Err(ClientError::Length {
                what: "row digest table entries",
                expected: ypir.db_rows,
                actual: row_digests.len(),
            });
        }
        Ok(Self {
            version: MANIFEST_VERSION,
            snapshot_sha256: hex::encode(snapshot_sha256),
            profile_id: params.profile().id().to_string(),
            setup_seed,
            db_rows: ypir.db_rows as u64,
            db_cols: ypir.db_cols as u64,
            item_size_bits: ypir.item_size_bits,
            c1_sha256: hex::encode(sha256(public_params)),
            row_digests_sha256: hex::encode(sha256(&row_digests.to_bytes())),
            row_digest_bytes: ROW_DIGEST_BYTES as u64,
            row_count: row_digests.len() as u64,
        })
    }

    /// The bytes a coordinator signs and a server serves.
    ///
    /// Pretty-printed JSON with a trailing newline. Only these exact bytes are
    /// ever verified; re-serialising a parsed manifest is not guaranteed to
    /// reproduce a signed file written by another tool.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = serde_json::to_vec_pretty(self).expect("manifest serializes");
        out.push(b'\n');
        out
    }
}

/// One SHA-256 digest per PIR row, row-major by PIR row index.
///
/// Entry `r` is [`row_digest`] of the plaintext row `r` — the bytes
/// [`crate::IPIRClient::decode_response_simplepir`] returns for an honest
/// response to row `r`. Padding rows hash the all-zero row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowDigestTable {
    digests: Vec<[u8; ROW_DIGEST_BYTES]>,
}

impl RowDigestTable {
    /// Build a table from plaintext rows, in row order.
    ///
    /// Each row is hashed with [`row_digest`], the same helper the client uses
    /// to check a decoded row.
    pub fn from_rows<I, R>(rows: I, plaintext_modulus: u64) -> Self
    where
        I: IntoIterator<Item = R>,
        R: AsRef<[u64]>,
    {
        Self::from_digests(
            rows.into_iter()
                .map(|row| row_digest(row.as_ref(), plaintext_modulus))
                .collect(),
        )
    }

    /// Wrap precomputed digests, in row order.
    #[must_use]
    pub fn from_digests(digests: Vec<[u8; ROW_DIGEST_BYTES]>) -> Self {
        Self { digests }
    }

    /// Parse a serialized table; the length must be a whole number of digests.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() % ROW_DIGEST_BYTES != 0 {
            return Err(ClientError::Malformed(format!(
                "row digest table is {} bytes, not a multiple of {ROW_DIGEST_BYTES}",
                bytes.len()
            )));
        }
        Ok(Self::from_digests(
            bytes
                .chunks_exact(ROW_DIGEST_BYTES)
                .map(|chunk| chunk.try_into().expect("exact chunk"))
                .collect(),
        ))
    }

    /// Serialize as `len() * 32` bytes, the `GET /row-digests` body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.digests.concat()
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.digests.len()
    }

    /// Whether the table has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// Digest of row `row`, if in range.
    #[must_use]
    pub fn get(&self, row: usize) -> Option<&[u8; ROW_DIGEST_BYTES]> {
        self.digests.get(row)
    }
}

/// Serialize decoded plaintext coefficients the way
/// [`crate::IPIRClient::decode_response_simplepir`] returns them: contiguous,
/// little-endian, `ceil(log2 p)` bits per coefficient.
#[must_use]
pub fn decoded_row_bytes(coefficients: &[u64], plaintext_modulus: u64) -> Vec<u8> {
    u64s_to_contiguous_bytes(coefficients, plaintext_modulus_bits(plaintext_modulus))
}

/// Digest of one plaintext row: SHA-256 of [`decoded_row_bytes`].
///
/// The single definition shared by the table generator and the client-side
/// check, so the two cannot drift apart.
#[must_use]
pub fn row_digest(coefficients: &[u64], plaintext_modulus: u64) -> [u8; ROW_DIGEST_BYTES] {
    row_digest_of_bytes(&decoded_row_bytes(coefficients, plaintext_modulus))
}

fn row_digest_of_bytes(row_bytes: &[u8]) -> [u8; ROW_DIGEST_BYTES] {
    sha256(row_bytes)
}

pub(crate) fn plaintext_modulus_bits(modulus: u64) -> usize {
    assert!(modulus > 1, "plaintext modulus must be at least 2");
    (u64::BITS - (modulus - 1).leading_zeros()) as usize
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Expand a manifest `setup_seed` into the [`IPIRSeed`] both peers use: its
/// little-endian bytes followed by 24 zero bytes.
#[must_use]
pub fn setup_seed_from_u64(value: u64) -> IPIRSeed {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    seed
}

/// Verify a coordinator signature over the exact manifest bytes, then parse.
///
/// The signature is checked with `verify_strict` before any byte is parsed.
pub fn verify_manifest_signature(
    coordinator_key: &[u8; COORDINATOR_KEY_BYTES],
    manifest: &[u8],
    signature: &[u8],
) -> Result<SnapshotManifest, ClientError> {
    let key = VerifyingKey::from_bytes(coordinator_key)
        .map_err(|_| ClientError::Malformed("coordinator key is not a valid Ed25519 key".into()))?;
    let signature: &[u8; SIGNATURE_BYTES] =
        signature.try_into().map_err(|_| ClientError::Length {
            what: "manifest signature",
            expected: SIGNATURE_BYTES,
            actual: signature.len(),
        })?;
    key.verify_strict(manifest, &Signature::from_bytes(signature))
        .map_err(|_| ClientError::BadSignature)?;
    let parsed: SnapshotManifest = serde_json::from_slice(manifest)
        .map_err(|err| ClientError::Malformed(format!("signed manifest is not valid: {err}")))?;
    if parsed.version != MANIFEST_VERSION {
        return Err(ClientError::ManifestMismatch(format!(
            "manifest version {} is not supported (expected {MANIFEST_VERSION})",
            parsed.version
        )));
    }
    Ok(parsed)
}

/// Snapshot public parameters checked against a coordinator-signed manifest.
///
/// This is the only way to obtain `c1` rows that the decoders accept, other
/// than the explicitly unverified research entry points. It has no public
/// constructor besides [`Self::verify`] and is not deserializable, so holding
/// one means every check below passed for these bytes.
#[derive(Debug, Clone)]
pub struct VerifiedPublicParams {
    manifest: SnapshotManifest,
    manifest_sha256: [u8; 32],
    c1: Vec<Vec<u64>>,
    row_digests: RowDigestTable,
    shape: ClientShape,
}

/// The client parameters a [`VerifiedPublicParams`] was checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientShape {
    pub(crate) d: usize,
    pub(crate) q: u64,
    pub(crate) p: u64,
    pub(crate) db_rows: usize,
    pub(crate) db_cols: usize,
    pub(crate) item_size_bits: u64,
}

impl VerifiedPublicParams {
    /// Check snapshot artefacts fetched from a server and keep the result.
    ///
    /// Call this before sending the first query; if it fails, send nothing.
    ///
    /// - `params`, `setup_seed`: what this client will query with.
    /// - `coordinator_key`: the pinned Ed25519 public key. Never take it from
    ///   the PIR server.
    /// - `manifest`, `signature`: the exact signed bytes and the signature.
    /// - `public_params`: the `GET /public-params` body.
    /// - `row_digests`: the `GET /row-digests` body.
    ///
    /// Checks, in order: the signature; profile, setup seed and shape against
    /// `params`; `sha256(public_params)`; table length and `sha256(table)`;
    /// that `c1` decodes to in-range coefficients; and that `c1` does not have
    /// the structure the key-extraction attack needs (see
    /// [`check_c1_is_unstructured`]).
    pub fn verify(
        params: &ProductionSimplePirParams,
        setup_seed: u64,
        coordinator_key: &[u8; COORDINATOR_KEY_BYTES],
        manifest: &[u8],
        signature: &[u8],
        public_params: &[u8],
        row_digests: &[u8],
    ) -> Result<Self, ClientError> {
        let parsed = verify_manifest_signature(coordinator_key, manifest, signature)?;
        let rlwe = params.rlwe();
        let ypir = params.ypir();

        let expect = |field: &str, signed: String, local: String| {
            if signed == local {
                Ok(())
            } else {
                Err(ClientError::ManifestMismatch(format!(
                    "{field}: manifest has {signed}, client uses {local}"
                )))
            }
        };
        expect(
            "profile_id",
            parsed.profile_id.clone(),
            params.profile().id().to_string(),
        )?;
        expect(
            "setup_seed",
            parsed.setup_seed.to_string(),
            setup_seed.to_string(),
        )?;
        expect(
            "db_rows",
            parsed.db_rows.to_string(),
            ypir.db_rows.to_string(),
        )?;
        expect(
            "db_cols",
            parsed.db_cols.to_string(),
            ypir.db_cols.to_string(),
        )?;
        expect(
            "item_size_bits",
            parsed.item_size_bits.to_string(),
            ypir.item_size_bits.to_string(),
        )?;
        expect(
            "row_digest_bytes",
            parsed.row_digest_bytes.to_string(),
            ROW_DIGEST_BYTES.to_string(),
        )?;
        expect(
            "row_count",
            parsed.row_count.to_string(),
            ypir.db_rows.to_string(),
        )?;

        if !digest_matches(&parsed.c1_sha256, public_params) {
            return Err(ClientError::DigestMismatch("public params (c1)"));
        }
        let expected_table_len = ypir.db_rows * ROW_DIGEST_BYTES;
        if row_digests.len() != expected_table_len {
            return Err(ClientError::Length {
                what: "row digest table",
                expected: expected_table_len,
                actual: row_digests.len(),
            });
        }
        if !digest_matches(&parsed.row_digests_sha256, row_digests) {
            return Err(ClientError::DigestMismatch("row digest table"));
        }

        let c1 = recover_published_c1(public_params, rlwe.d, ypir.db_cols / rlwe.d, rlwe.q)?;
        check_c1_is_unstructured(&c1, rlwe.delta)?;

        Ok(Self {
            manifest: parsed,
            manifest_sha256: sha256(manifest),
            c1,
            row_digests: RowDigestTable::from_bytes(row_digests)?,
            shape: ClientShape {
                d: rlwe.d,
                q: rlwe.q,
                p: rlwe.p,
                db_rows: ypir.db_rows,
                db_cols: ypir.db_cols,
                item_size_bits: ypir.item_size_bits,
            },
        })
    }

    /// The verified manifest.
    #[must_use]
    pub fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }

    /// SHA-256 of the signed manifest bytes. Compare with a server's
    /// `/meta` `manifest_sha256` to detect a stale cached copy.
    #[must_use]
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }

    /// The signed setup seed, expanded with [`setup_seed_from_u64`]. Pass it
    /// to [`crate::IPIRClient::generate_public_query_setup_simplepir_from_seed`].
    #[must_use]
    pub fn setup_seed(&self) -> IPIRSeed {
        setup_seed_from_u64(self.manifest.setup_seed)
    }

    /// The verified `c1` row of every output block.
    #[must_use]
    pub fn published_c1(&self) -> &[Vec<u64>] {
        &self.c1
    }

    /// The verified row digest table.
    #[must_use]
    pub fn row_digests(&self) -> &RowDigestTable {
        &self.row_digests
    }

    pub(crate) fn shape(&self) -> ClientShape {
        self.shape
    }

    /// Whether `row_bytes` is the honest plaintext of `row`.
    pub(crate) fn check_row(&self, row: usize, row_bytes: &[u8]) -> Result<(), ClientError> {
        let expected = self
            .row_digests
            .get(row)
            .ok_or(ClientError::RowOutOfRange {
                row,
                rows: self.row_digests.len(),
            })?;
        if &row_digest_of_bytes(row_bytes) == expected {
            Ok(())
        } else {
            Err(ClientError::TamperDetected { row })
        }
    }
}

fn digest_matches(signed_hex: &str, bytes: &[u8]) -> bool {
    hex::decode(signed_hex).is_ok_and(|signed| signed == sha256(bytes))
}

/// Number of equal-width bins the `[0, Δ)` residue histogram uses.
const C1_RESIDUE_BINS: u64 = 16;

/// Reject a `c1` whose coefficients sit at structured residues modulo `Δ`.
///
/// Defence in depth behind the manifest digest, for a mis-signed manifest.
/// Decoding computes `round((c2 + c1·s) / Δ)`. If `c1` is a multiple of `Δ`
/// (the constant `Δ` is the simplest), `c1·s / Δ` is an exact small-integer
/// combination of the secret coefficients and the decoded row leaks `s`.
/// An honest `c1` is pseudo-random modulo `q`, so its residues modulo `Δ` are
/// uniform. Per output block, this rejects `c1` when more than half of the
/// coefficients lie within `Δ/8` of a multiple of `Δ` (expected: a quarter),
/// or when any one of sixteen residue bins holds more than a quarter of them
/// (expected: a sixteenth). At `d = 2048` both thresholds sit more than twenty
/// standard deviations from the honest mean.
///
/// This is a heuristic, not a proof that `c1` is safe: the signed digest is
/// the authentication.
pub fn check_c1_is_unstructured(c1: &[Vec<u64>], delta: u64) -> Result<(), ClientError> {
    if delta < C1_RESIDUE_BINS {
        return Err(ClientError::Malformed(format!(
            "delta {delta} is too small for the c1 residue check"
        )));
    }
    let near = delta / 8;
    for (block, row) in c1.iter().enumerate() {
        let mut near_multiple = 0usize;
        let mut bins = [0usize; C1_RESIDUE_BINS as usize];
        for coeff in row {
            let residue = coeff % delta;
            if residue < near || residue > delta - near {
                near_multiple += 1;
            }
            let bin =
                (u128::from(residue) * u128::from(C1_RESIDUE_BINS) / u128::from(delta)) as usize;
            bins[bin] += 1;
        }
        let max_bin = bins.iter().copied().max().unwrap_or(0);
        if near_multiple * 2 > row.len() || max_bin * 4 > row.len() {
            return Err(ClientError::SuspiciousPublicParams(format!(
                "c1 block {block}: {near_multiple} of {} coefficients within delta/8 of a \
                 multiple of delta and {max_bin} in one residue bin; a random c1 is uniform \
                 modulo delta",
                row.len()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::bits::u64s_to_contiguous_bytes;
    use crate::modulus_switch::modulus_bits;
    use crate::params::SimplePirProfile;
    use crate::sampling::uniform_u64_below;

    /// Public, test-only signing seeds.
    const COORDINATOR_SEED: [u8; 32] = [0x11; 32];
    const OTHER_SEED: [u8; 32] = [0x22; 32];
    const SETUP_SEED: u64 = 7;

    struct Fixture {
        params: ProductionSimplePirParams,
        key: [u8; 32],
        manifest: Vec<u8>,
        signature: Vec<u8>,
        public_params: Vec<u8>,
        table: Vec<u8>,
    }

    fn production_params() -> ProductionSimplePirParams {
        ProductionSimplePirParams::new(2048, 2048 * 14 * 2, SimplePirProfile::P14).expect("profile")
    }

    fn random_c1_bytes(params: &ProductionSimplePirParams, seed: u64) -> Vec<u8> {
        let rlwe = params.rlwe();
        let blocks = params.ypir().db_cols / rlwe.d;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let coeffs: Vec<u64> = (0..rlwe.d)
            .map(|_| uniform_u64_below(&mut rng, rlwe.q))
            .collect();
        (0..blocks)
            .flat_map(|_| u64s_to_contiguous_bytes(&coeffs, modulus_bits(rlwe.q)))
            .collect()
    }

    fn table_for(params: &ProductionSimplePirParams) -> RowDigestTable {
        let ypir = params.ypir();
        RowDigestTable::from_rows(
            (0..ypir.db_rows).map(|row| vec![(row as u64) % ypir.p; ypir.db_cols]),
            ypir.p,
        )
    }

    fn sign(seed: &[u8; 32], manifest: &[u8]) -> Vec<u8> {
        SigningKey::from_bytes(seed)
            .sign(manifest)
            .to_bytes()
            .to_vec()
    }

    fn fixture_with_c1(public_params: Vec<u8>) -> Fixture {
        let params = production_params();
        let table = table_for(&params);
        let manifest =
            SnapshotManifest::new(&params, SETUP_SEED, [0xAB; 32], &public_params, &table)
                .expect("manifest")
                .to_bytes();
        Fixture {
            key: SigningKey::from_bytes(&COORDINATOR_SEED)
                .verifying_key()
                .to_bytes(),
            signature: sign(&COORDINATOR_SEED, &manifest),
            manifest,
            public_params,
            table: table.to_bytes(),
            params,
        }
    }

    fn fixture() -> Fixture {
        let params = production_params();
        fixture_with_c1(random_c1_bytes(&params, 1))
    }

    fn verify(f: &Fixture) -> Result<VerifiedPublicParams, ClientError> {
        VerifiedPublicParams::verify(
            &f.params,
            SETUP_SEED,
            &f.key,
            &f.manifest,
            &f.signature,
            &f.public_params,
            &f.table,
        )
    }

    /// Re-sign a modified manifest with the real key, to test the field
    /// checks behind the signature.
    fn resigned(f: &Fixture, edit: impl FnOnce(&mut SnapshotManifest)) -> Fixture {
        let mut manifest: SnapshotManifest = serde_json::from_slice(&f.manifest).unwrap();
        edit(&mut manifest);
        let bytes = manifest.to_bytes();
        Fixture {
            params: f.params.clone(),
            key: f.key,
            signature: sign(&COORDINATOR_SEED, &bytes),
            manifest: bytes,
            public_params: f.public_params.clone(),
            table: f.table.clone(),
        }
    }

    #[test]
    fn honest_artefacts_verify() {
        let f = fixture();
        let verified = verify(&f).expect("honest artefacts verify");
        assert_eq!(verified.manifest().profile_id, "simplepir-p14-v1");
        assert_eq!(verified.manifest().row_count, 2048);
        assert_eq!(verified.manifest_sha256(), sha256(&f.manifest));
        assert_eq!(verified.published_c1().len(), 2);
        assert_eq!(verified.row_digests().len(), 2048);
    }

    #[test]
    fn manifest_signature_rejects_bad_sig_wrong_key_and_modified_byte() {
        let f = fixture();
        assert!(verify_manifest_signature(&f.key, &f.manifest, &f.signature).is_ok());

        let mut bad_sig = f.signature.clone();
        bad_sig[5] ^= 1;
        assert_eq!(
            verify_manifest_signature(&f.key, &f.manifest, &bad_sig),
            Err(ClientError::BadSignature)
        );

        let other_key = SigningKey::from_bytes(&OTHER_SEED)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify_manifest_signature(&other_key, &f.manifest, &f.signature),
            Err(ClientError::BadSignature)
        );

        // Every byte is covered, including whitespace the parser would ignore.
        for index in [0, f.manifest.len() / 2, f.manifest.len() - 1] {
            let mut modified = f.manifest.clone();
            modified[index] ^= 0x01;
            assert_eq!(
                verify_manifest_signature(&f.key, &modified, &f.signature),
                Err(ClientError::BadSignature),
                "byte {index}"
            );
        }

        assert!(matches!(
            verify_manifest_signature(&f.key, &f.manifest, &f.signature[..63]),
            Err(ClientError::Length { .. })
        ));
        let full = Fixture {
            signature: sign(&OTHER_SEED, &f.manifest),
            ..fixture()
        };
        assert_eq!(verify(&full).unwrap_err(), ClientError::BadSignature);
    }

    #[test]
    fn rejects_a_manifest_that_does_not_describe_this_client() {
        let f = fixture();
        for (field, edit) in [
            (
                "profile_id",
                Box::new(|m: &mut SnapshotManifest| {
                    m.profile_id = SimplePirProfile::P16Q46.id().into();
                }) as Box<dyn FnOnce(&mut SnapshotManifest)>,
            ),
            ("setup_seed", Box::new(|m| m.setup_seed += 1)),
            ("db_rows", Box::new(|m| m.db_rows += 2048)),
            ("db_cols", Box::new(|m| m.db_cols /= 2)),
            ("item_size_bits", Box::new(|m| m.item_size_bits += 1)),
            ("row_count", Box::new(|m| m.row_count -= 1)),
            ("row_digest_bytes", Box::new(|m| m.row_digest_bytes = 16)),
        ] {
            let err = verify(&resigned(&f, edit)).unwrap_err();
            assert!(
                matches!(&err, ClientError::ManifestMismatch(msg) if msg.starts_with(field)),
                "{field}: {err}"
            );
        }
        let err = verify(&resigned(&f, |m| m.version = 2)).unwrap_err();
        assert!(matches!(err, ClientError::ManifestMismatch(_)));

        // Same manifest, but the client queries with another seed or shape.
        let wrong_seed = VerifiedPublicParams::verify(
            &f.params,
            SETUP_SEED + 1,
            &f.key,
            &f.manifest,
            &f.signature,
            &f.public_params,
            &f.table,
        );
        assert!(matches!(wrong_seed, Err(ClientError::ManifestMismatch(_))));
        let other_shape = Fixture {
            params: ProductionSimplePirParams::new(4096, 2048 * 14 * 2, SimplePirProfile::P14)
                .unwrap(),
            ..fixture()
        };
        assert!(matches!(
            verify(&other_shape),
            Err(ClientError::ManifestMismatch(_))
        ));
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let f = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&f.manifest).unwrap();
        value["extra"] = serde_json::json!(1);
        let bytes = serde_json::to_vec(&value).unwrap();
        let err = verify_manifest_signature(&f.key, &bytes, &sign(&COORDINATOR_SEED, &bytes))
            .unwrap_err();
        assert!(matches!(err, ClientError::Malformed(_)));
    }

    #[test]
    fn rejects_c1_that_does_not_match_the_signed_digest() {
        let f = fixture();
        let swapped = Fixture {
            public_params: random_c1_bytes(&f.params, 2),
            ..fixture()
        };
        assert_eq!(
            verify(&swapped).unwrap_err(),
            ClientError::DigestMismatch("public params (c1)")
        );
        let truncated = Fixture {
            public_params: f.public_params[..f.public_params.len() - 1].to_vec(),
            ..fixture()
        };
        assert_eq!(
            verify(&truncated).unwrap_err(),
            ClientError::DigestMismatch("public params (c1)")
        );
    }

    #[test]
    fn rejects_truncated_or_modified_digest_table() {
        let f = fixture();
        let truncated = Fixture {
            table: f.table[..f.table.len() - ROW_DIGEST_BYTES].to_vec(),
            ..fixture()
        };
        assert!(matches!(
            verify(&truncated),
            Err(ClientError::Length {
                what: "row digest table",
                ..
            })
        ));
        let mut modified = f.table.clone();
        modified[100] ^= 1;
        let modified = Fixture {
            table: modified,
            ..fixture()
        };
        assert_eq!(
            verify(&modified).unwrap_err(),
            ClientError::DigestMismatch("row digest table")
        );
    }

    /// Attack A: `c1 = Δ` turns the decoded row into the secret key. Even if a
    /// manifest were signed over it, the residue check refuses it.
    #[test]
    fn rejects_delta_poison_even_when_signed() {
        let params = production_params();
        let rlwe = params.rlwe();
        let blocks = params.ypir().db_cols / rlwe.d;
        let mut poison = vec![0u64; rlwe.d];
        poison[0] = rlwe.delta;
        let bytes: Vec<u8> = (0..blocks)
            .flat_map(|_| u64s_to_contiguous_bytes(&poison, modulus_bits(rlwe.q)))
            .collect();
        let err = verify(&fixture_with_c1(bytes)).unwrap_err();
        assert!(
            matches!(err, ClientError::SuspiciousPublicParams(_)),
            "{err}"
        );

        // Dense multiples of delta, and a constant mid-range residue, too.
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let dense: Vec<u64> = (0..rlwe.d)
            .map(|_| uniform_u64_below(&mut rng, rlwe.p) * rlwe.delta)
            .collect();
        let constant = vec![rlwe.delta / 2; rlwe.d];
        for row in [dense, constant] {
            let bytes: Vec<u8> = (0..blocks)
                .flat_map(|_| u64s_to_contiguous_bytes(&row, modulus_bits(rlwe.q)))
                .collect();
            assert!(matches!(
                verify(&fixture_with_c1(bytes)),
                Err(ClientError::SuspiciousPublicParams(_))
            ));
        }
    }

    #[test]
    fn residue_check_accepts_many_random_c1() {
        let params = production_params();
        let rlwe = params.rlwe();
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        for _ in 0..32 {
            let row: Vec<u64> = (0..rlwe.d)
                .map(|_| uniform_u64_below(&mut rng, rlwe.q))
                .collect();
            check_c1_is_unstructured(&[row], rlwe.delta).expect("random c1 passes");
        }
        // A single structured block among random ones is still caught.
        let random: Vec<u64> = (0..rlwe.d).map(|_| rng.next_u64() % rlwe.q).collect();
        assert!(check_c1_is_unstructured(&[random, vec![0; rlwe.d]], rlwe.delta).is_err());
    }

    #[test]
    fn rejects_out_of_range_c1_coefficients() {
        let params = production_params();
        let rlwe = params.rlwe();
        let blocks = params.ypir().db_cols / rlwe.d;
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let mut row: Vec<u64> = (0..rlwe.d)
            .map(|_| uniform_u64_below(&mut rng, rlwe.q))
            .collect();
        row[7] = (1 << modulus_bits(rlwe.q)) - 1;
        let bytes: Vec<u8> = (0..blocks)
            .flat_map(|_| u64s_to_contiguous_bytes(&row, modulus_bits(rlwe.q)))
            .collect();
        assert!(matches!(
            verify(&fixture_with_c1(bytes)),
            Err(ClientError::Malformed(_))
        ));
    }

    #[test]
    fn table_roundtrips_and_rejects_ragged_bytes() {
        let table = RowDigestTable::from_rows([vec![1u64, 2, 3], vec![0; 3]], 1 << 14);
        assert_eq!(
            RowDigestTable::from_bytes(&table.to_bytes()),
            Ok(table.clone())
        );
        assert_eq!(table.len(), 2);
        assert_eq!(
            table.get(1),
            Some(&row_digest(&[0, 0, 0], 1 << 14)),
            "padding rows hash the all-zero row"
        );
        assert!(RowDigestTable::from_bytes(&[0u8; 33]).is_err());
    }
}
