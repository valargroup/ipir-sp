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
    kh_bits: usize,
    two_mask: bool,
    published_mask_bits: usize,
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
            kh_bits: pack.q().trailing_zeros() as usize,
            pack,
            rows,
            cols,
            query_bits,
            response_bits,
            two_mask: false,
            published_mask_bits: 64,
        })
    }
    /// Experimental, lossy final-key transport. No correctness approval is implied.
    /// Full precision preserves the original RNQ1 profile and setup bytes.
    pub fn with_kh_bits(mut self, bits: usize) -> Result<Self, ReinspiringError> {
        let full = self.pack.q().trailing_zeros() as usize;
        if self.two_mask && bits != full {
            return Err(err("two-mask mode has no K_h precision"));
        }
        if bits != full && !(40..full).contains(&bits) {
            return Err(err("Kh precision must be between 40 and log2(q)"));
        }
        self.kh_bits = bits;
        Ok(self)
    }
    /// Transmitted bits per final-key ciphertext coefficient.
    pub fn kh_bits(&self) -> usize {
        self.kh_bits
    }
    /// Experimental one-key output decoded under two public masks.
    pub fn with_two_mask_output(mut self) -> Result<Self, ReinspiringError> {
        if self.kh_bits != self.pack.q().trailing_zeros() as usize {
            return Err(err("two-mask mode has no K_h precision"));
        }
        self.two_mask = true;
        Ok(self)
    }
    /// Experimental two-mask transport at 27..=32 bits per coefficient.
    /// 64 selects the legacy exact u64 encoding. Requires a snapshot certificate.
    pub fn with_published_mask_bits(mut self, bits: usize) -> Result<Self, ReinspiringError> {
        if bits != 64
            && (!self.two_mask || self.pack.q() != 1u64 << 54 || !(27..=32).contains(&bits))
        {
            return Err(err(
                "rounded public masks require native q54 two-mask mode and 27..=32 bits",
            ));
        }
        self.published_mask_bits = bits;
        Ok(self)
    }
    /// Bits transmitted per public mask coefficient (64 is exact legacy encoding).
    pub fn published_mask_bits(&self) -> usize {
        self.published_mask_bits
    }
    /// Whether the response is decoded under two public masks.
    pub fn is_two_mask(&self) -> bool {
        self.two_mask
    }
    fn request_magic(&self) -> &'static [u8; 4] {
        if self.two_mask {
            b"RNQ3"
        } else if self.kh_bits == self.pack.q().trailing_zeros() as usize {
            b"RNQ1"
        } else {
            b"RNQ2"
        }
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
        if profile.request_magic() == b"RNQ2" {
            h.update(b"/kh-transport-v2/");
            h.update((profile.kh_bits as u64).to_le_bytes());
        }
        if profile.two_mask {
            h.update(b"/two-mask-one-key-v1/");
        }
        if profile.published_mask_bits != 64 {
            h.update(b"/rounded-public-masks-v1/");
            h.update((profile.published_mask_bits as u64).to_le_bytes());
        }
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
    decoding: Option<([u8; 32], NativeDecodingState)>,
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
        let keys = if p.two_mask {
            NativeKeys::generate_one_key(&setup.packing, &secret, rng)?
        } else {
            NativeKeys::generate(&setup.packing, &secret, rng)?
        };
        let query = secret.encrypt_selection(&setup.polys, target, rng)?;
        let mut bytes = p.request_magic().to_vec();
        bytes.extend(setup.id);
        let words = keys.words();
        let half = p.pack.ell() * p.pack.d();
        if p.two_mask {
            bytes.extend(encode(
                &keys.kg_words(),
                p.pack.q().trailing_zeros() as usize,
            ));
        } else if p.request_magic() == b"RNQ1" {
            bytes.extend(encode(&words, p.kh_bits));
        } else {
            bytes.extend(encode(&words[..half], p.pack.q().trailing_zeros() as usize));
            bytes.extend(encode(
                &down(&words[half..], p.pack.q(), p.kh_bits),
                p.kh_bits,
            ));
        }
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
            decoding: None,
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
    /// Precompute request-local mask products before sending the query.
    /// This is online client work and must be included in generation timings.
    pub fn prepare_decode(
        &mut self,
        published: &NativePreparedPublished,
    ) -> Result<(), ReinspiringError> {
        if published.setup_id != self.setup_id || published.profile != self.profile {
            return Err(err("prepared setup/profile mismatch"));
        }
        self.decoding = Some((
            published.mask_digest,
            published.decoder.prepare_request(&self.secret)?,
        ));
        Ok(())
    }
    /// Decode with cached public transforms bound to this snapshot and profile.
    pub fn decode_prepared(
        &self,
        published: &NativePreparedPublished,
        response: &[u8],
    ) -> Result<Vec<u64>, ReinspiringError> {
        let p = &self.profile;
        if published.setup_id != self.setup_id
            || published.profile != *p
            || response.len() != 68 + packed_len(p.cols, p.response_bits)
            || &response[..4] != if p.two_mask { b"RNR2" } else { b"RNR1" }
            || response[4..36] != self.setup_id
            || response[36..68] != self.query_id
        {
            return Err(err("prepared response/setup/request binding mismatch"));
        }
        let bodies = up(
            &decode(&response[68..], p.cols, p.response_bits)?,
            p.pack.q(),
            p.response_bits,
        );
        if let Some((digest, state)) = &self.decoding {
            if *digest != published.mask_digest {
                return Err(err("prepared mask digest mismatch"));
            }
            state.decrypt(&bodies)
        } else {
            published.decoder.decrypt(&self.secret, &bodies)
        }
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
            || published.masks.len() != p.cols / d
            || published.other_masks.is_some() != p.two_mask
            || published
                .other_masks
                .as_ref()
                .is_some_and(|x| x.len() != p.cols / d)
            || response.len() != 68 + packed_len(p.cols, p.response_bits)
            || &response[..4] != if p.two_mask { b"RNR2" } else { b"RNR1" }
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
            if let Some(others) = &published.other_masks {
                let ct = NativeTwoMaskCiphertext::from_rows(
                    &p.pack,
                    published.masks[i].clone(),
                    others[i].clone(),
                    block.to_vec(),
                )?;
                out.extend(self.secret.decrypt_two_mask(&ct)?);
                if let Some(expected) = expected {
                    error = error.max(
                        self.secret
                            .phase_error_two_mask(&ct, &expected[i * d..(i + 1) * d])?,
                    );
                }
            } else {
                let ct = NativeCiphertext::from_rows(
                    &p.pack,
                    published.masks[i].clone(),
                    block.to_vec(),
                )?;
                out.extend(self.secret.decrypt(&ct)?);
                if let Some(expected) = expected {
                    error = error.max(
                        self.secret
                            .phase_error(&ct, &expected[i * d..(i + 1) * d])?,
                    );
                }
            }
        }
        Ok((out, error))
    }
}

/// Cached public decoding transforms bound to an immutable setup and mode.
pub struct NativePreparedPublished {
    setup_id: [u8; 32],
    profile: NativeProfile,
    decoder: NativeDecoder,
    mask_digest: [u8; 32],
}
impl NativePreparedPublished {
    /// Retained transformed coefficient bytes; excludes context tables.
    pub fn coefficient_bytes(&self) -> usize {
        self.decoder.coefficient_bytes()
    }
}

/// Public masks associated with exactly one setup/snapshot.
pub struct NativePublished {
    setup_id: [u8; 32],
    masks: Vec<Vec<u64>>,
    other_masks: Option<Vec<Vec<u64>>>,
    mask_bits: usize,
    q: u64,
}
impl NativePublished {
    /// Cache public transforms once per snapshot, with explicit setup validation.
    pub fn prepare(
        &self,
        setup: &NativePublicSetup,
    ) -> Result<NativePreparedPublished, ReinspiringError> {
        let p = &setup.profile;
        if self.setup_id != setup.id
            || self.masks.len() != p.cols / p.pack.d()
            || self.other_masks.is_some() != p.two_mask
            || self.mask_bits != p.published_mask_bits
            || self.q != p.pack.q()
        {
            return Err(err("published setup mismatch"));
        }
        Ok(NativePreparedPublished {
            setup_id: self.setup_id,
            profile: p.clone(),
            mask_digest: Sha256::digest(self.to_bytes()).into(),
            decoder: NativeDecoder::new(&p.pack, &self.masks, self.other_masks.as_deref())?,
        })
    }

    /// Canonical profile-selected published state. Count snapshot bytes separately.
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.mask_bits != 64 {
            let mut out = b"RNP3".to_vec();
            out.extend(self.setup_id);
            let words: Vec<_> = self
                .masks
                .iter()
                .flatten()
                .chain(self.other_masks.iter().flatten().flatten())
                .copied()
                .collect();
            out.extend(encode(
                &down(&words, self.q, self.mask_bits),
                self.mask_bits,
            ));
            return out;
        }
        let mut out = if self.other_masks.is_some() {
            b"RNP2".to_vec()
        } else {
            b"RNP1".to_vec()
        };
        out.extend(self.setup_id);
        for &x in self.masks.iter().flatten() {
            out.extend(x.to_le_bytes());
        }
        if let Some(others) = &self.other_masks {
            for &x in others.iter().flatten() {
                out.extend(x.to_le_bytes());
            }
        }
        out
    }
    /// Bounded parser using a locally expanded setup as the source of dimensions.
    pub fn from_bytes(setup: &NativePublicSetup, bytes: &[u8]) -> Result<Self, ReinspiringError> {
        let p = &setup.profile;
        let count = p.cols * (1 + usize::from(p.two_mask));
        let length = if p.published_mask_bits == 64 {
            count * 8
        } else {
            packed_len(count, p.published_mask_bits)
        };
        let magic = if p.published_mask_bits != 64 {
            b"RNP3"
        } else if p.two_mask {
            b"RNP2"
        } else {
            b"RNP1"
        };
        if bytes.len() != 36 + length || &bytes[..4] != magic || bytes[4..36] != setup.id {
            return Err(err("published mask mismatch"));
        }
        let words: Vec<_> = if p.published_mask_bits == 64 {
            bytes[36..]
                .chunks_exact(8)
                .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
                .collect()
        } else {
            up(
                &decode(&bytes[36..], count, p.published_mask_bits)?,
                p.pack.q(),
                p.published_mask_bits,
            )
        };
        if words.iter().any(|&x| x >= p.pack.q()) {
            return Err(err("noncanonical published mask"));
        }
        let (first, second) = words.split_at(p.cols);
        Ok(Self {
            setup_id: setup.id,
            mask_bits: p.published_mask_bits,
            q: p.pack.q(),
            masks: first.chunks_exact(p.pack.d()).map(|x| x.to_vec()).collect(),
            other_masks: if p.two_mask {
                Some(
                    second
                        .chunks_exact(p.pack.d())
                        .map(|x| x.to_vec())
                        .collect(),
                )
            } else {
                None
            },
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
/// Offline public bounds for one response block. These are certificate inputs,
/// not a claim of a particular failure probability.
pub struct NativeBlockNoise {
    /// Compiled packing weights, combining reused secret coefficients.
    pub packing: reinspiring::noise::NativeNoiseAnalysis,
    /// Envelope of database weights on independent query-error samples.
    pub query: reinspiring::noise::WeightNorms,
}
impl NativeServer {
    /// Screen counterfactual gadgets on a selected public output block.
    /// Results are offline bounds, never executable profiles or certificates.
    pub fn screen_gadgets(
        setup: &NativePublicSetup,
        db: &[u16],
        block: usize,
        mut emit: impl FnMut([u32; 2], NativeBlockNoise),
    ) -> Result<(), ReinspiringError> {
        let p = &setup.profile;
        let d = p.pack.d();
        if db.len() != p.rows * p.cols
            || db.iter().any(|&x| x as u64 >= p.pack.p())
            || block >= p.cols / d
        {
            return Err(err("invalid research snapshot"));
        }
        let lift = LiftContext::new(d, p.pack.q())?;
        let polys = lift.prepare_public_dot(&setup.polys, (p.pack.p() - 1).min(p.pack.q() / 2))?;
        let masks = (block * d..(block + 1) * d)
            .into_par_iter()
            .map(|col| {
                let words = db[col * p.rows..(col + 1) * p.rows]
                    .chunks_exact(d)
                    .map(|p| p.iter().map(|&x| x as u64).collect())
                    .collect::<Vec<_>>();
                lift.public_dot(&polys, &words)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let query = db[block * d * p.rows..(block + 1) * d * p.rows]
            .chunks_exact(p.rows)
            .map(|col| reinspiring::noise::WeightNorms::measure(col.iter().map(|&x| x as i128)))
            .fold(
                reinspiring::noise::WeightNorms::default(),
                reinspiring::noise::WeightNorms::envelope,
            );
        for a in 16..=22 {
            for b in 16..=22 {
                emit(
                    [a, b],
                    NativeBlockNoise {
                        packing: NativePreprocessed::screen_gadget(&setup.packing, &masks, [a, b])?,
                        query,
                    },
                );
            }
        }
        Ok(())
    }

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
        db: Vec<u16>,
        concurrent_blocks: usize,
    ) -> Result<Self, ReinspiringError> {
        Self::build_internal(setup, db, concurrent_blocks, false).map(|(server, _)| server)
    }
    /// Build with snapshot-specific noise statistics. Analyze blocks serially to
    /// limit scratch memory; no statistics or secret state enter the online path.
    pub fn build_analyzed(
        setup: NativePublicSetup,
        db: Vec<u16>,
    ) -> Result<(Self, Vec<NativeBlockNoise>), ReinspiringError> {
        Self::build_internal(setup, db, 1, true)
    }
    fn build_internal(
        setup: NativePublicSetup,
        mut db: Vec<u16>,
        concurrent_blocks: usize,
        analyze: bool,
    ) -> Result<(Self, Vec<NativeBlockNoise>), ReinspiringError> {
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
        let mut analyses = Vec::new();
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
                    let masks = masks?;
                    if analyze {
                        let (pre, mut packing) = if p.two_mask {
                            NativePreprocessed::build_two_mask_analyzed(&setup.packing, &masks)?
                        } else {
                            NativePreprocessed::build_analyzed(&setup.packing, &masks)?
                        };
                        if p.published_mask_bits != 64 {
                            packing.weights = packing
                                .public_mask_screens
                                .iter()
                                .find(|(bits, _)| *bits as usize == p.published_mask_bits)
                                .ok_or_else(|| err("missing rounded-mask noise analysis"))?
                                .1;
                        }
                        let query = db[block * d * p.rows..(block + 1) * d * p.rows]
                            .chunks_exact(p.rows)
                            .map(|col| {
                                reinspiring::noise::WeightNorms::measure(
                                    col.iter().map(|&x| x as i128),
                                )
                            })
                            .fold(reinspiring::noise::WeightNorms::default(), |a, b| {
                                a.envelope(b)
                            });
                        Ok((pre, Some(NativeBlockNoise { packing, query })))
                    } else {
                        (if p.two_mask {
                            NativePreprocessed::build_two_mask(&setup.packing, &masks)
                        } else {
                            NativePreprocessed::build(&setup.packing, &masks)
                        })
                        .map(|pre| (pre, None))
                    }
                })
                .collect();
            for (block, analysis) in batch? {
                pre.push(block);
                if let Some(analysis) = analysis {
                    analyses.push(analysis);
                }
            }
        }
        let interleaved = p.rows % 4 == 0
            && p.cols % 16 == 0
            && reinspiring::native_kernel::PreparedU16Query::supports_interleaved();
        if interleaved {
            db.par_chunks_mut(p.rows * 16).for_each(|band| {
                reinspiring::native_kernel::PreparedU16Query::interleave_columns(band, p.rows)
            });
        }
        Ok((
            Self {
                setup,
                db,
                interleaved,
                pre,
            },
            analyses,
        ))
    }
    /// Publish setup-bound c1 rows.
    pub fn published(&self) -> NativePublished {
        let profile = &self.setup.profile;
        let round = |x: &[u64]| {
            if profile.published_mask_bits == 64 {
                x.to_vec()
            } else {
                up(
                    &down(x, profile.pack.q(), profile.published_mask_bits),
                    profile.pack.q(),
                    profile.published_mask_bits,
                )
            }
        };
        NativePublished {
            setup_id: self.setup.id,
            mask_bits: profile.published_mask_bits,
            q: profile.pack.q(),
            masks: self.pre.iter().map(|p| round(p.mask())).collect(),
            other_masks: if self.setup.profile.two_mask {
                Some(
                    self.pre
                        .iter()
                        .map(|p| round(p.other_mask().unwrap()))
                        .collect(),
                )
            } else {
                None
            },
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
        let half = p.pack.ell() * d;
        let kg_len = packed_len(half, q.trailing_zeros() as usize);
        let keys_len = if p.two_mask {
            kg_len
        } else if p.request_magic() == b"RNQ1" {
            packed_len(2 * half, p.kh_bits)
        } else {
            kg_len + packed_len(half, p.kh_bits)
        };
        if bytes.len() != 36 + keys_len + packed_len(p.rows, p.query_bits)
            || &bytes[..4] != p.request_magic()
            || bytes[4..36] != self.setup.id
        {
            return Err(err("request/profile/setup mismatch"));
        }
        let words = if p.two_mask {
            decode(&bytes[36..36 + keys_len], half, q.trailing_zeros() as usize)?
        } else if p.request_magic() == b"RNQ1" {
            decode(&bytes[36..36 + keys_len], 2 * half, p.kh_bits)?
        } else {
            let mut words = decode(&bytes[36..36 + kg_len], half, q.trailing_zeros() as usize)?;
            words.extend(up(
                &decode(&bytes[36 + kg_len..36 + keys_len], half, p.kh_bits)?,
                q,
                p.kh_bits,
            ));
            words
        };
        let keys = if p.two_mask {
            NativeKeys::from_kg_words(&self.setup.packing, &words)?
        } else {
            NativeKeys::from_words(&self.setup.packing, &words)?
        };
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
        let bodies: Result<Vec<Vec<u64>>, _> = self
            .pre
            .par_iter()
            .zip(intermediate.par_chunks_exact(d))
            .map(|(pre, b)| -> Result<Vec<u64>, ReinspiringError> {
                let pending = pre.prepare_pack(&prepared_keys)?;
                if p.two_mask {
                    Ok(pending.finish_two_mask(b)?.rows().2.to_vec())
                } else {
                    Ok(pending.finish(b)?.rows().1.to_vec())
                }
            })
            .collect();
        let bodies = bodies?;
        let packing = t.elapsed();
        let t = Instant::now();
        let bodies: Vec<_> = bodies.into_iter().flatten().collect();
        let mut out = if p.two_mask {
            b"RNR2".to_vec()
        } else {
            b"RNR1".to_vec()
        };
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

#[cfg(test)]
mod transport_tests {
    use super::*;
    #[test]
    fn full_precision_preserves_legacy_setup_and_unsplit_key_encoding() {
        // Low degree/modulus makes each key half non-byte-aligned, so this
        // catches accidentally adding separate padding to legacy RNQ1 keys.
        let pack = NativeParams::new(2, 17, 1, 9, 2, SecretDistribution::Gaussian).unwrap();
        let profile = NativeProfile::new(pack, 2, 2)
            .unwrap()
            .with_kh_bits(17)
            .unwrap();
        let setup = NativePublicSetup::new(profile, [7; 32], [19; 32]);
        let p = &setup.profile;
        let mut old_hash = Sha256::new();
        old_hash.update(b"ipir-sp/native/v1/setup");
        old_hash.update(p.pack.encoding());
        for n in [p.rows, p.cols, p.query_bits, p.response_bits] {
            old_hash.update((n as u64).to_le_bytes());
        }
        old_hash.update([7; 32]);
        old_hash.update([19; 32]);
        let old_id: [u8; 32] = old_hash.finalize().into();
        assert_eq!(setup.id, old_id);
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = NativeSecret::sample(&p.pack, &mut rng);
        let keys = NativeKeys::generate(&setup.packing, &secret, &mut rng).unwrap();
        let query = secret.encrypt_selection(&setup.polys, 1, &mut rng).unwrap();
        let mut expected = b"RNQ1".to_vec();
        expected.extend(old_id);
        expected.extend(encode(&keys.words(), 17));
        expected.extend(encode(
            &down(&query, p.pack.q(), p.query_bits),
            p.query_bits,
        ));
        let actual =
            NativeRequest::generate_with_rng(&setup, 1, &mut ChaCha20Rng::seed_from_u64(42))
                .unwrap();
        assert_eq!(actual.bytes(), expected);
        assert_eq!(expected.len(), 58);
        let server = NativeServer::build(setup, vec![0, 1, 1, 0]).unwrap();
        let response = server.respond(&expected).unwrap().0;
        assert_eq!(
            actual.decode(&server.published(), &response).unwrap(),
            vec![1, 0]
        );
    }
    #[test]
    fn key_and_public_mask_rounding_known_answers_and_modular_bound() {
        let q = 1u64 << 54;
        for bits in (27..=32).chain(40..=54) {
            let unit = 1u64 << (54 - bits);
            let radius = if bits == 54 { 0 } else { unit / 2 };
            let words = [
                0,
                radius.saturating_sub(1),
                radius,
                unit - 1,
                q - 1,
                q - radius,
            ];
            let words: Vec<_> = words.into_iter().map(|x| x % q).collect();
            let round = up(
                &decode(&encode(&down(&words, q, bits), bits), words.len(), bits).unwrap(),
                q,
                bits,
            );
            for (&a, &b) in words.iter().zip(&round) {
                let error = a.wrapping_sub(b) & (q - 1);
                assert!(error.min(q - error) <= radius);
            }
            if bits < 54 {
                assert_eq!(round, vec![0, 0, unit, unit, 0, 0]);
            } else {
                assert_eq!(round, words);
            }
        }
    }
}
