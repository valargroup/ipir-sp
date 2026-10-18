//! Native client protocol re-exports and the IPIR database evaluator.

use ipir_native_client::wire::{decode, down, encode, packed_len, up};
pub use ipir_native_client::{
    NativePreparedPublished, NativeProfile, NativePublicSetup, NativePublished, NativeRequest,
};
use rayon::prelude::*;
use reinspiring::{
    lift_ntt::LiftContext,
    native::{NativeKeys, NativePreprocessed},
    ReinspiringError,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

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

/// Offline build durations. Hint and packing are summed over output blocks
/// (block-seconds, comparable across concurrency); layout and total are wall time.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeOfflineTiming {
    /// Database-by-query-mask hint construction, summed over blocks.
    pub hints: Duration,
    /// Packing preprocessing (mask trace and matrix compilation), summed over blocks.
    pub packing: Duration,
    /// Conversion of the database into scan tiles.
    pub layout: Duration,
    /// Complete build.
    pub total: Duration,
}

/// Database entries retained in their storage width. 8-bit plaintexts may use
/// one byte per entry; wider plaintexts always use u16.
enum NativeDatabase {
    U16(Vec<u16>),
    U8(Vec<u8>),
}

/// Plaintext word types the server can store and scan.
trait DatabaseEntry: Copy + Send + Sync + Into<u64> + Into<i128> {
    fn interleave(band: &mut [Self], rows: usize);
    fn wrap(db: Vec<Self>) -> NativeDatabase;
}
impl DatabaseEntry for u16 {
    fn interleave(band: &mut [Self], rows: usize) {
        reinspiring::native_kernel::PreparedU16Query::interleave_columns(band, rows)
    }
    fn wrap(db: Vec<Self>) -> NativeDatabase {
        NativeDatabase::U16(db)
    }
}
impl DatabaseEntry for u8 {
    fn interleave(band: &mut [Self], rows: usize) {
        reinspiring::native_kernel::PreparedU16Query::interleave_u8_columns(band, rows)
    }
    fn wrap(db: Vec<Self>) -> NativeDatabase {
        NativeDatabase::U8(db)
    }
}

/// Immutable database and compiled public preprocessing. Supported SIMD hosts
/// retain byte-plane tiles; other hosts retain the column-major input layout.
pub struct NativeServer {
    setup: NativePublicSetup,
    db: NativeDatabase,
    interleaved: bool,
    pre: Vec<NativePreprocessed>,
    offline: NativeOfflineTiming,
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
        let p = setup.profile();
        let d = p.packing().d();
        if db.len() != p.rows() * p.cols()
            || db.iter().any(|&x| x as u64 >= p.packing().p())
            || block >= p.cols() / d
        {
            return Err(err("invalid research snapshot"));
        }
        let lift = LiftContext::new(d, p.packing().q())?;
        let polys = lift.prepare_public_dot(
            setup.query_masks(),
            (p.packing().p() - 1).min(p.packing().q() / 2),
        )?;
        let masks = (block * d..(block + 1) * d)
            .into_par_iter()
            .map(|col| {
                let words = db[col * p.rows()..(col + 1) * p.rows()]
                    .chunks_exact(d)
                    .map(|p| p.iter().map(|&x| x as u64).collect())
                    .collect::<Vec<_>>();
                lift.public_dot(&polys, &words)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let query = db[block * d * p.rows()..(block + 1) * d * p.rows()]
            .chunks_exact(p.rows())
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
                        packing: NativePreprocessed::screen_gadget(
                            setup.packing_setup(),
                            &masks,
                            [a, b],
                        )?,
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
        Self::require_u16(&setup)?;
        Self::build_internal(setup, db, concurrent_blocks, false).map(|(server, _)| server)
    }
    /// Build with snapshot-specific noise statistics. Analyze blocks serially to
    /// limit scratch memory; no statistics or secret state enter the online path.
    pub fn build_analyzed(
        setup: NativePublicSetup,
        db: Vec<u16>,
    ) -> Result<(Self, Vec<NativeBlockNoise>), ReinspiringError> {
        Self::require_u16(&setup)?;
        Self::build_internal(setup, db, 1, true)
    }
    /// Build an 8-bit database stored one byte per entry (p <= 2^8). Same
    /// arithmetic, setup and responses as the u16 builder for the same entries;
    /// it halves database memory and scans one byte plane.
    pub fn build_u8_with_concurrency(
        setup: NativePublicSetup,
        db: Vec<u8>,
        concurrent_blocks: usize,
    ) -> Result<Self, ReinspiringError> {
        Self::require_u8(&setup)?;
        Self::build_internal(setup, db, concurrent_blocks, false).map(|(server, _)| server)
    }
    /// 8-bit storage with snapshot-specific noise statistics.
    pub fn build_u8_analyzed(
        setup: NativePublicSetup,
        db: Vec<u8>,
    ) -> Result<(Self, Vec<NativeBlockNoise>), ReinspiringError> {
        Self::require_u8(&setup)?;
        Self::build_internal(setup, db, 1, true)
    }
    /// The profile admits 2^31 entries at p <= 2^8 because 8-bit storage
    /// holds one byte per entry; two-byte storage keeps the 2^30 (2 GiB) limit.
    fn require_u16(setup: &NativePublicSetup) -> Result<(), ReinspiringError> {
        if setup.profile().rows() * setup.profile().cols() > 1 << 30 {
            return Err(err(
                "more than 2^30 entries require 8-bit storage (build_u8_*)",
            ));
        }
        Ok(())
    }
    fn require_u8(setup: &NativePublicSetup) -> Result<(), ReinspiringError> {
        if setup.profile().packing().p() > 256 {
            return Err(err("8-bit storage requires p <= 2^8"));
        }
        Ok(())
    }
    fn build_internal<T: DatabaseEntry>(
        setup: NativePublicSetup,
        mut db: Vec<T>,
        concurrent_blocks: usize,
        analyze: bool,
    ) -> Result<(Self, Vec<NativeBlockNoise>), ReinspiringError> {
        let total_start = Instant::now();
        if concurrent_blocks == 0 {
            return Err(err("zero preprocessing concurrency"));
        }
        let p = setup.profile();
        let d = p.packing().d();
        let q = p.packing().q();
        if db.len() != p.rows() * p.cols()
            || db.iter().any(|&x| Into::<u64>::into(x) >= p.packing().p())
        {
            return Err(err("database shape or plaintext range mismatch"));
        }
        let mut offline = NativeOfflineTiming::default();
        let lift = LiftContext::new(d, q)?;
        let public_polys =
            lift.prepare_public_dot(setup.query_masks(), (p.packing().p() - 1).min(q / 2))?;
        let mut pre = Vec::with_capacity(p.cols() / d);
        let mut analyses = Vec::new();
        for start in (0..p.cols() / d).step_by(concurrent_blocks) {
            let end = start.saturating_add(concurrent_blocks).min(p.cols() / d);
            let batch: Result<Vec<_>, _> = (start..end)
                .into_par_iter()
                .map(|block| {
                    let hint_start = Instant::now();
                    let masks: Result<Vec<_>, _> = (block * d..(block + 1) * d)
                        .into_par_iter()
                        .map(|col| {
                            let coeffs: Vec<Vec<u64>> = db[col * p.rows()..(col + 1) * p.rows()]
                                .chunks_exact(d)
                                .map(|poly| poly.iter().map(|&x| x.into()).collect())
                                .collect();
                            lift.public_dot(&public_polys, &coeffs)
                        })
                        .collect();
                    let masks = masks?;
                    let hint = hint_start.elapsed();
                    let pack_start = Instant::now();
                    let timed = |(pre, analysis)| (pre, analysis, hint, pack_start.elapsed());
                    if analyze {
                        let (pre, mut packing) = if p.is_two_mask() {
                            NativePreprocessed::build_two_mask_analyzed_with_screens(
                                setup.packing_setup(),
                                &masks,
                                p.public_mask_screens(),
                            )?
                        } else {
                            NativePreprocessed::build_analyzed(setup.packing_setup(), &masks)?
                        };
                        // 54 is lossless: the analysis weights already apply.
                        if p.published_mask_bits() != 64 && p.published_mask_bits() != 54 {
                            packing.weights = packing
                                .public_mask_screens
                                .iter()
                                .find(|(bits, _)| *bits as usize == p.published_mask_bits())
                                .ok_or_else(|| err("missing rounded-mask noise analysis"))?
                                .1;
                        }
                        let query = db[block * d * p.rows()..(block + 1) * d * p.rows()]
                            .chunks_exact(p.rows())
                            .map(|col| {
                                reinspiring::noise::WeightNorms::measure(
                                    col.iter().map(|&x| Into::<i128>::into(x)),
                                )
                            })
                            .fold(reinspiring::noise::WeightNorms::default(), |a, b| {
                                a.envelope(b)
                            });
                        Ok(timed((pre, Some(NativeBlockNoise { packing, query }))))
                    } else {
                        (if p.is_two_mask() {
                            NativePreprocessed::build_two_mask(setup.packing_setup(), &masks)
                        } else {
                            NativePreprocessed::build(setup.packing_setup(), &masks)
                        })
                        .map(|pre| timed((pre, None)))
                    }
                })
                .collect();
            for (block, analysis, hint, packing) in batch? {
                pre.push(block);
                offline.hints += hint;
                offline.packing += packing;
                if let Some(analysis) = analysis {
                    analyses.push(analysis);
                }
            }
        }
        let layout_start = Instant::now();
        let interleaved = p.rows() % 4 == 0
            && p.cols() % 16 == 0
            && reinspiring::native_kernel::PreparedU16Query::supports_interleaved();
        if interleaved {
            db.par_chunks_mut(p.rows() * 16)
                .for_each(|band| T::interleave(band, p.rows()));
        }
        offline.layout = layout_start.elapsed();
        offline.total = total_start.elapsed();
        Ok((
            Self {
                setup,
                db: T::wrap(db),
                interleaved,
                pre,
                offline,
            },
            analyses,
        ))
    }
    /// Bytes retained for database entries (1 per entry for 8-bit storage, else 2).
    pub fn database_bytes(&self) -> usize {
        match &self.db {
            NativeDatabase::U16(x) => x.len() * 2,
            NativeDatabase::U8(x) => x.len(),
        }
    }
    /// Whether entries are stored one byte each.
    pub fn is_u8_storage(&self) -> bool {
        matches!(self.db, NativeDatabase::U8(_))
    }
    /// Storage width chosen for each output block's compiled packing matrix.
    pub fn matrix_storage(&self) -> Vec<reinspiring::native_matrix::NativeMatrixStorage> {
        self.pre.iter().map(|p| p.matrix_storage()).collect()
    }
    /// Signed width of each block's compiled matrix entries. Diagnostic: scans
    /// every retained matrix once.
    pub fn matrix_magnitude_bits(&self) -> Vec<u32> {
        self.pre.iter().map(|p| p.matrix_magnitude_bits()).collect()
    }
    /// Offline build durations.
    pub fn offline_timing(&self) -> NativeOfflineTiming {
        self.offline
    }
    /// Publish setup-bound c1 rows.
    pub fn published(&self) -> NativePublished {
        NativePublished::from_masks(
            &self.setup,
            self.pre.iter().map(|block| block.mask().to_vec()).collect(),
            self.setup.profile().is_two_mask().then(|| {
                self.pre
                    .iter()
                    .map(|block| block.other_mask().unwrap().to_vec())
                    .collect()
            }),
        )
        .expect("server preprocessing produces canonical masks for its setup")
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
        let p = self.setup.profile();
        let q = p.packing().q();
        let d = p.packing().d();
        let start = Instant::now();
        let half = p.packing().ell() * d;
        let kg_len = packed_len(half, q.trailing_zeros() as usize);
        let keys_len = if p.is_two_mask() {
            kg_len
        } else if p.request_magic() == b"RNQ1" {
            packed_len(2 * half, p.kh_bits())
        } else {
            kg_len + packed_len(half, p.kh_bits())
        };
        if bytes.len() != 36 + keys_len + packed_len(p.rows(), p.query_bits())
            || &bytes[..4] != p.request_magic()
            || bytes[4..36] != self.setup.id()
        {
            return Err(err("request/profile/setup mismatch"));
        }
        let words = if p.is_two_mask() {
            decode(&bytes[36..36 + keys_len], half, q.trailing_zeros() as usize)?
        } else if p.request_magic() == b"RNQ1" {
            decode(&bytes[36..36 + keys_len], 2 * half, p.kh_bits())?
        } else {
            let mut words = decode(&bytes[36..36 + kg_len], half, q.trailing_zeros() as usize)?;
            words.extend(up(
                &decode(&bytes[36 + kg_len..36 + keys_len], half, p.kh_bits())?,
                q,
                p.kh_bits(),
            ));
            words
        };
        let keys = if p.is_two_mask() {
            NativeKeys::from_kg_words(self.setup.packing_setup(), &words)?
        } else {
            NativeKeys::from_words(self.setup.packing_setup(), &words)?
        };
        let query = up(
            &decode(&bytes[36 + keys_len..], p.rows(), p.query_bits())?,
            q,
            p.query_bits(),
        );
        let prepared_query = reinspiring::native_kernel::PreparedU16Query::new(&query, q)?;
        let deserialize = start.elapsed();
        let t = Instant::now();
        let mut intermediate = vec![0; p.cols()];
        match (&self.db, self.interleaved) {
            (NativeDatabase::U16(db), true) => intermediate
                .par_chunks_mut(16)
                .zip(db.par_chunks(p.rows() * 16))
                .for_each(|(out, db)| prepared_query.multiply_interleaved(db, out)),
            (NativeDatabase::U16(db), false) => intermediate
                .par_iter_mut()
                .zip(db.par_chunks_exact(p.rows()))
                .for_each(|(out, col)| *out = prepared_query.dot(col)),
            (NativeDatabase::U8(db), true) => intermediate
                .par_chunks_mut(16)
                .zip(db.par_chunks(p.rows() * 16))
                .for_each(|(out, db)| prepared_query.multiply_interleaved_u8(db, out)),
            (NativeDatabase::U8(db), false) => intermediate
                .par_iter_mut()
                .zip(db.par_chunks_exact(p.rows()))
                .for_each(|(out, col)| *out = prepared_query.dot_u8(col)),
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
                if p.is_two_mask() {
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
        let mut out = if p.is_two_mask() {
            b"RNR2".to_vec()
        } else {
            b"RNR1".to_vec()
        };
        out.extend(self.setup.id());
        out.extend(Sha256::digest(bytes));
        out.extend(encode(
            &down(&bodies, q, p.response_bits()),
            p.response_bits(),
        ));
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

fn err(s: &str) -> ReinspiringError {
    ReinspiringError::InvalidParams(s.into())
}
