//! Experimental native ReinspiRING integration with the IPIR-SP first dimension.
//!
//! Distinct versioned transport; never accepted as an existing production profile.
//! Setup identifiers prevent accidental mixing, not malicious-server forgery.
use crate::bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes};
use rand::TryRngCore;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use rayon::prelude::*;
use reinspiring::{lift_ntt::LiftContext, native::*, ReinspiringError};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Validated profile and database shape. All fields are immutable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeProfile {
    pack: NativeParams,
    rows: usize,
    cols: usize,
    query_bits: usize,
    response_bits: usize,
}
impl NativeProfile {
    /// Database dimensions must be nonzero multiples of d, with bounded size.
    /// Gaussian secrets are required by the integrated client; ternary remains
    /// confined to the standalone packing research configuration.
    pub fn new(pack: NativeParams, rows: usize, cols: usize) -> Result<Self, ReinspiringError> {
        if rows == 0
            || cols == 0
            || rows % pack.d() != 0
            || cols % pack.d() != 0
            || rows.checked_mul(cols).filter(|&n| n <= 1 << 30).is_none()
            || pack.sampler() != SecretDistribution::Gaussian
            || pack.p() > 65536
        {
            return Err(err("invalid native IPIR profile or database shape"));
        }
        let query_bits = 49.min(pack.q().trailing_zeros() as usize);
        let response_bits =
            (pack.p().trailing_zeros() as usize + 6).min(pack.q().trailing_zeros() as usize);
        Ok(Self {
            pack,
            rows,
            cols,
            query_bits,
            response_bits,
        })
    }
    /// Packing profile.
    pub fn packing(&self) -> &NativeParams {
        &self.pack
    }
    /// Number of database rows.
    pub fn rows(&self) -> usize {
        self.rows
    }
    /// Coefficients in one retrieved row.
    pub fn cols(&self) -> usize {
        self.cols
    }
}

/// Seed-derived query masks and packing setup. The client expands these itself.
pub struct NativePublicSetup {
    profile: NativeProfile,
    id: [u8; 32],
    polys: Vec<Vec<u64>>,
    packing: NativeSetup,
}
impl NativePublicSetup {
    /// Domain-separated expansion bound to profile, database shape and snapshot ID.
    /// Snapshot IDs identify data versions but do not authenticate their contents.
    pub fn new(profile: NativeProfile, seed: [u8; 32], snapshot: [u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(b"ipir-sp/native/v1/setup");
        h.update(profile.pack.encoding());
        for n in [
            profile.rows,
            profile.cols,
            profile.query_bits,
            profile.response_bits,
        ] {
            h.update((n as u64).to_le_bytes());
        }
        h.update(seed);
        h.update(snapshot);
        let id: [u8; 32] = h.finalize().into();
        let mut rng = ChaCha20Rng::from_seed(id);
        let polys = (0..profile.rows / profile.pack.d())
            .map(|_| {
                (0..profile.pack.d())
                    .map(|_| rng.next_u64() & (profile.pack.q() - 1))
                    .collect()
            })
            .collect();
        let packing = NativeSetup::new(profile.pack.clone(), id);
        Self {
            profile,
            id,
            polys,
            packing,
        }
    }
    /// Public first-dimension masks for distributed hint construction.
    pub fn query_masks(&self) -> &[Vec<u64>] {
        &self.polys
    }
    /// Profile and dimensions.
    pub fn profile(&self) -> &NativeProfile {
        &self.profile
    }
    /// Public setup identifier.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
}

/// Per-request client state; consumes fresh OS entropy and retains the secret locally.
pub struct NativeRequest {
    secret: NativeSecret,
    profile: NativeProfile,
    setup_id: [u8; 32],
    query_id: [u8; 32],
    bytes: Vec<u8>,
}
impl NativeRequest {
    /// Generate fresh query/key randomness. Target selection is branch-free.
    pub fn generate(setup: &NativePublicSetup, target: usize) -> Result<Self, ReinspiringError> {
        let mut seed = [0; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| err("OS entropy unavailable"))?;
        Self::generate_with_rng(setup, target, &mut ChaCha20Rng::from_seed(seed))
    }
    /// Deterministic RNG entry point for reproducible tests and benchmarks.
    /// Production callers should use generate; seeds must never be public/reused.
    pub fn generate_with_rng(
        setup: &NativePublicSetup,
        target: usize,
        rng: &mut ChaCha20Rng,
    ) -> Result<Self, ReinspiringError> {
        let p = &setup.profile;
        if target >= p.rows {
            return Err(err("target out of range"));
        }
        let secret = NativeSecret::sample(&p.pack, rng);
        let keys = NativeKeys::generate(&setup.packing, &secret, rng)?;
        let query = secret.encrypt_selection(&setup.polys, target, rng)?;
        let mut bytes = b"RNQ1".to_vec();
        bytes.extend(setup.id);
        bytes.extend(encode(&keys.words(), p.pack.q().trailing_zeros() as usize));
        bytes.extend(encode(
            &down(&query, p.pack.q(), p.query_bits),
            p.query_bits,
        ));
        let query_id = Sha256::digest(&bytes).into();
        Ok(Self {
            secret,
            profile: p.clone(),
            setup_id: setup.id,
            query_id,
            bytes,
        })
    }
    /// Canonical versioned request bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Decode a response using the public c1 rows for this snapshot.
    pub fn decode(
        &self,
        published: &NativePublished,
        response: &[u8],
    ) -> Result<Vec<u64>, ReinspiringError> {
        self.decode_inner(published, response, None).map(|x| x.0)
    }
    /// Decode and measure true phase error against the known expected row.
    pub fn decode_with_error(
        &self,
        published: &NativePublished,
        response: &[u8],
        expected: &[u64],
    ) -> Result<(Vec<u64>, u64), ReinspiringError> {
        if expected.len() != self.profile.cols
            || expected.iter().any(|&x| x >= self.profile.pack.p())
        {
            return Err(err("invalid expected row"));
        }
        self.decode_inner(published, response, Some(expected))
    }
    fn decode_inner(
        &self,
        published: &NativePublished,
        response: &[u8],
        expected: Option<&[u64]>,
    ) -> Result<(Vec<u64>, u64), ReinspiringError> {
        let p = &self.profile;
        let d = p.pack.d();
        if published.setup_id != self.setup_id
            || response.len() != 68 + packed_len(p.cols, p.response_bits)
            || &response[..4] != b"RNR1"
            || response[4..36] != self.setup_id
            || response[36..68] != self.query_id
        {
            return Err(err("response/setup/request binding mismatch"));
        }
        let b = up(
            &decode(&response[68..], p.cols, p.response_bits)?,
            p.pack.q(),
            p.response_bits,
        );
        let mut out = Vec::with_capacity(p.cols);
        let mut error = 0;
        for (i, block) in b.chunks_exact(d).enumerate() {
            let ct =
                NativeCiphertext::from_rows(&p.pack, published.masks[i].clone(), block.to_vec())?;
            out.extend(self.secret.decrypt(&ct)?);
            if let Some(expected) = expected {
                error = error.max(
                    self.secret
                        .phase_error(&ct, &expected[i * d..(i + 1) * d])?,
                );
            }
        }
        Ok((out, error))
    }
}

/// Public masks associated with exactly one setup/snapshot.
pub struct NativePublished {
    setup_id: [u8; 32],
    masks: Vec<Vec<u64>>,
}
impl NativePublished {
    /// Canonical full-precision published state. Count offline bytes separately.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = b"RNP1".to_vec();
        out.extend(self.setup_id);
        for &x in self.masks.iter().flatten() {
            out.extend(x.to_le_bytes());
        }
        out
    }
    /// Bounded parser using a locally expanded setup as the source of dimensions.
    pub fn from_bytes(setup: &NativePublicSetup, bytes: &[u8]) -> Result<Self, ReinspiringError> {
        let p = &setup.profile;
        if bytes.len() != 36 + p.cols * 8 || &bytes[..4] != b"RNP1" || bytes[4..36] != setup.id {
            return Err(err("published mask mismatch"));
        }
        let words: Vec<_> = bytes[36..]
            .chunks_exact(8)
            .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
            .collect();
        if words.iter().any(|&x| x >= p.pack.q()) {
            return Err(err("noncanonical published mask"));
        }
        Ok(Self {
            setup_id: setup.id,
            masks: words.chunks_exact(p.pack.d()).map(|x| x.to_vec()).collect(),
        })
    }
}

/// Disjoint timing stages for the complete server response.
#[derive(Debug, Default)]
pub struct NativeTiming {
    /// Parsing and query expansion.
    pub deserialize: Duration,
    /// Database matrix-vector product.
    pub matrix_vector: Duration,
    /// All output packing blocks.
    pub packing: Duration,
    /// Modulus switching and encoding.
    pub serialization: Duration,
}

/// Immutable database and compiled public preprocessing. Supported SIMD hosts
/// retain byte-plane tiles; other hosts retain the column-major input layout.
pub struct NativeServer {
    setup: NativePublicSetup,
    db: Vec<u16>,
    interleaved: bool,
    pre: Vec<NativePreprocessed>,
}
impl NativeServer {
    /// Build all public preprocessing; the database must contain canonical Z_p values.
    /// Process output blocks sequentially to bound peak scratch memory.
    pub fn build(setup: NativePublicSetup, db: Vec<u16>) -> Result<Self, ReinspiringError> {
        Self::build_with_concurrency(setup, db, 1)
    }
    /// Build with at most `concurrent_blocks` output blocks in flight. Each
    /// block also uses the current Rayon pool. Larger batches trade peak
    /// scratch memory for throughput; zero is rejected before any work.
    pub fn build_with_concurrency(
        setup: NativePublicSetup,
        mut db: Vec<u16>,
        concurrent_blocks: usize,
    ) -> Result<Self, ReinspiringError> {
        if concurrent_blocks == 0 {
            return Err(err("zero preprocessing concurrency"));
        }
        let p = &setup.profile;
        let d = p.pack.d();
        let q = p.pack.q();
        if db.len() != p.rows * p.cols || db.iter().any(|&x| x as u64 >= p.pack.p()) {
            return Err(err("database shape or plaintext range mismatch"));
        }
        let lift = LiftContext::new(d, q)?;
        let public_polys = lift.prepare_public_dot(&setup.polys, (p.pack.p() - 1).min(q / 2))?;
        let mut pre = Vec::with_capacity(p.cols / d);
        for start in (0..p.cols / d).step_by(concurrent_blocks) {
            let end = start.saturating_add(concurrent_blocks).min(p.cols / d);
            let batch: Result<Vec<_>, _> = (start..end)
                .into_par_iter()
                .map(|block| {
                    let masks: Result<Vec<_>, _> = (block * d..(block + 1) * d)
                        .into_par_iter()
                        .map(|col| {
                            let coeffs: Vec<Vec<u64>> = db[col * p.rows..(col + 1) * p.rows]
                                .chunks_exact(d)
                                .map(|poly| poly.iter().map(|&x| x as u64).collect())
                                .collect();
                            lift.public_dot(&public_polys, &coeffs)
                        })
                        .collect();
                    NativePreprocessed::build(&setup.packing, &masks?)
                })
                .collect();
            pre.extend(batch?);
        }
        let interleaved = p.rows % 4 == 0
            && p.cols % 16 == 0
            && reinspiring::native_kernel::PreparedU16Query::supports_interleaved();
        if interleaved {
            db.par_chunks_mut(p.rows * 16).for_each(|band| {
                reinspiring::native_kernel::PreparedU16Query::interleave_columns(band, p.rows)
            });
        }
        Ok(Self {
            setup,
            db,
            interleaved,
            pre,
        })
    }
    /// Publish setup-bound c1 rows.
    pub fn published(&self) -> NativePublished {
        NativePublished {
            setup_id: self.setup.id,
            masks: self.pre.iter().map(|p| p.mask().to_vec()).collect(),
        }
    }
    /// Public setup for clients; reconstructible from its seed and snapshot ID.
    pub fn setup(&self) -> &NativePublicSetup {
        &self.setup
    }
    /// Retained compiled coefficient bytes, excluding database and NTT tables.
    pub fn coefficient_bytes(&self) -> usize {
        self.pre.iter().map(|p| p.coefficient_bytes()).sum()
    }
    /// Parse, execute, and serialize a complete versioned response.
    pub fn respond(&self, bytes: &[u8]) -> Result<(Vec<u8>, NativeTiming), ReinspiringError> {
        let p = &self.setup.profile;
        let q = p.pack.q();
        let d = p.pack.d();
        let start = Instant::now();
        let keys_len = packed_len(2 * p.pack.ell() * d, q.trailing_zeros() as usize);
        if bytes.len() != 36 + keys_len + packed_len(p.rows, p.query_bits)
            || &bytes[..4] != b"RNQ1"
            || bytes[4..36] != self.setup.id
        {
            return Err(err("request/profile/setup mismatch"));
        }
        let keys = NativeKeys::from_words(
            &self.setup.packing,
            &decode(
                &bytes[36..36 + keys_len],
                2 * p.pack.ell() * d,
                q.trailing_zeros() as usize,
            )?,
        )?;
        let query = up(
            &decode(&bytes[36 + keys_len..], p.rows, p.query_bits)?,
            q,
            p.query_bits,
        );
        let prepared_query = reinspiring::native_kernel::PreparedU16Query::new(&query, q)?;
        let deserialize = start.elapsed();
        let t = Instant::now();
        let mut intermediate = vec![0; p.cols];
        if self.interleaved {
            intermediate
                .par_chunks_mut(16)
                .zip(self.db.par_chunks(p.rows * 16))
                .for_each(|(out, db)| prepared_query.multiply_interleaved(db, out));
        } else {
            intermediate
                .par_iter_mut()
                .zip(self.db.par_chunks_exact(p.rows))
                .for_each(|(out, col)| *out = prepared_query.dot(col));
        }
        let matrix_vector = t.elapsed();
        let t = Instant::now();
        let prepared_keys = self.pre[0].prepare_keys(&keys)?;
        let packed: Result<Vec<_>, _> = self
            .pre
            .par_iter()
            .zip(intermediate.par_chunks_exact(d))
            .map(|(pre, b)| pre.prepare_pack(&prepared_keys)?.finish(b))
            .collect();
        let packed = packed?;
        let packing = t.elapsed();
        let t = Instant::now();
        let bodies: Vec<_> = packed
            .iter()
            .flat_map(|ct| ct.rows().1.iter().copied())
            .collect();
        let mut out = b"RNR1".to_vec();
        out.extend(self.setup.id);
        out.extend(Sha256::digest(bytes));
        out.extend(encode(&down(&bodies, q, p.response_bits), p.response_bits));
        Ok((
            out,
            NativeTiming {
                deserialize,
                matrix_vector,
                packing,
                serialization: t.elapsed(),
            },
        ))
    }
}
fn packed_len(n: usize, bits: usize) -> usize {
    (n * bits).div_ceil(8)
}
fn encode(words: &[u64], bits: usize) -> Vec<u8> {
    u64s_to_contiguous_bytes(words, bits)
}
fn decode(bytes: &[u8], n: usize, bits: usize) -> Result<Vec<u64>, ReinspiringError> {
    if bytes.len() != packed_len(n, bits) {
        return Err(err("invalid payload length"));
    }
    let words = contiguous_bytes_to_u64s(bytes, bits);
    if encode(&words, bits) != bytes {
        return Err(err("noncanonical padding"));
    }
    Ok(words)
}
fn down(words: &[u64], q: u64, bits: usize) -> Vec<u64> {
    let shift = q.trailing_zeros() as usize - bits;
    words
        .iter()
        .map(|&x| {
            if shift == 0 {
                x
            } else {
                ((x + (1 << (shift - 1))) >> shift) & ((1 << bits) - 1)
            }
        })
        .collect()
}
fn up(words: &[u64], q: u64, bits: usize) -> Vec<u64> {
    let shift = q.trailing_zeros() as usize - bits;
    words.iter().map(|&x| x << shift).collect()
}
fn err(s: &str) -> ReinspiringError {
    ReinspiringError::InvalidParams(s.into())
}
