//! Server-side SimplePIR database layout and offline block extraction.
//!
//! This module ports the parts of `/root/ypir/src/server.rs` that are not tied
//! to YPIR's old two-CRT CDKS packing path: transposed DB storage, plaintext
//! query/database multiplication, and the `hint_0` block layout consumed by
//! InspiRING preprocessing.

use inspiring::{
    InspiringError, PackingKeys, QueryPackPreprocessed, RlweCiphertext, RlweParams, TopKeyImages,
};
use rayon::prelude::*;
pub use simplepir_kernel::ToU64;
use simplepir_kernel::{ChunkedSplitKernel, FirstDimKernel, U16Avx512Kernel};
use spiral_rs::poly::{
    add_into, from_ntt, from_ntt_alloc, multiply, to_ntt, to_ntt_alloc, PolyMatrix, PolyMatrixNTT,
    PolyMatrixRaw,
};
use std::time::Duration;

use crate::client::IPIRSimpleQuery;
use crate::modulus_switch::serialize_rlwe_response_bodies;
use crate::params::YpirSchemeParams;

/// A YPIR-formatted server database.
///
/// Internally the DB is stored column-major (`col * padded_rows + row`), which
/// matches the layout YPIR's fast dot-product kernels consume. The arithmetic
/// here is routed through a swappable kernel so optimized CPU and GPU backends
/// can be added without changing the surrounding InspiRING boundary.
pub struct YServer<T> {
    params: YpirSchemeParams,
    db: Vec<T>,
    pad_rows: bool,
    /// Largest value present in `db`, measured at load.
    ///
    /// Kernels use this to size their delayed-reduction window; see
    /// [`FirstDimKernel::multiply_query`].
    element_max: u64,
    kernel: Box<dyn FirstDimKernel<T>>,
}

/// Measured server-side online subphases for one SimplePIR request.
#[derive(Debug, Clone, Copy, Default)]
pub struct OnlineServerTiming {
    /// Time spent parsing the uploaded query bytes.
    pub deserialize: Duration,
    /// Time spent in the first-dimension database/query matrix-vector product.
    pub matrix_vector: Duration,
    /// Time spent packing intermediate values into RLWE ciphertexts.
    pub packing: Duration,
    /// Time spent serializing/modulus-switching the response bytes.
    pub serialization: Duration,
}

impl<T> YServer<T>
where
    T: Copy + Default + ToU64 + 'static,
{
    /// Build a server from a database iterator.
    ///
    /// If `input_is_transposed` is false, the iterator is logical row-major
    /// (`row, col`). If true, it is already in server column-major order. In
    /// both cases the internal storage is column-major.
    pub fn new<I>(
        params: YpirSchemeParams,
        db: I,
        input_is_transposed: bool,
        pad_rows: bool,
    ) -> Self
    where
        I: Iterator<Item = T>,
    {
        Self::with_kernel(
            params,
            db,
            input_is_transposed,
            pad_rows,
            Box::new(ChunkedSplitKernel::default()),
        )
    }

    /// Build a server with an explicit first-dimension query kernel.
    ///
    /// This is the extension point for swapping the online DB/query multiply
    /// without changing the rest of the IPIR-SP server pipeline. The input
    /// database is materialized into the same internal column-major layout as
    /// [`YServer::new`], then [`FirstDimKernel::prepare`] is called once with the
    /// stored database and shape. CPU kernels normally ignore `prepare`; an
    /// accelerator backend can use it to upload or pre-index the DB.
    ///
    /// `input_is_transposed` has the same meaning as in [`YServer::new`]:
    /// `false` means the iterator is logical row-major `(row, col)`, and `true`
    /// means it is already in column-major server order.
    pub fn with_kernel<I>(
        params: YpirSchemeParams,
        mut db: I,
        input_is_transposed: bool,
        pad_rows: bool,
        mut kernel: Box<dyn FirstDimKernel<T>>,
    ) -> Self
    where
        I: Iterator<Item = T>,
    {
        let rows = params.db_rows;
        let padded_rows = if pad_rows {
            params.db_rows_padded_simplepir()
        } else {
            rows
        };
        let cols = params.db_cols;
        let mut stored = vec![T::default(); padded_rows * cols];

        // Kernels size their delayed-reduction window from a bound on the
        // database values. Tracking the true maximum on the pass we are already
        // making gives them a tight one for free: for SimplePIR plaintexts it
        // is far below the storage type's maximum, which is what lets a whole
        // column stay inside one reduction window.
        let mut element_max = 0_u64;
        let take = |db: &mut I, element_max: &mut u64| {
            let value = db.next().expect("database is too short");
            *element_max = (*element_max).max(value.to_u64());
            value
        };

        if input_is_transposed {
            // Column-major in, column-major out: already one sequential sweep.
            for col in 0..cols {
                for row in 0..rows {
                    stored[col * padded_rows + row] = take(&mut db, &mut element_max);
                }
            }
        } else {
            ingest_row_major(
                &mut db,
                &mut stored,
                rows,
                cols,
                padded_rows,
                &mut element_max,
                take,
            );
        }

        kernel.prepare(&stored, padded_rows, cols);

        Self {
            params,
            db: stored,
            pad_rows,
            element_max,
            kernel,
        }
    }

    /// YPIR scheme parameters.
    #[must_use]
    pub fn params(&self) -> &YpirSchemeParams {
        &self.params
    }

    /// Logical database rows.
    #[must_use]
    pub fn db_rows(&self) -> usize {
        self.params.db_rows
    }

    /// Stored database rows, including optional padding.
    #[must_use]
    pub fn db_rows_padded(&self) -> usize {
        if self.pad_rows {
            self.params.db_rows_padded_simplepir()
        } else {
            self.params.db_rows
        }
    }

    /// SimplePIR database columns.
    #[must_use]
    pub fn db_cols(&self) -> usize {
        self.params.db_cols
    }

    /// Internal column-major DB storage.
    #[must_use]
    pub fn db(&self) -> &[T] {
        &self.db
    }

    /// Return the element at logical `(row, col)`.
    #[must_use]
    pub fn get_elem_row_col(&self, row: usize, col: usize) -> T {
        assert!(row < self.db_rows(), "row out of bounds");
        assert!(col < self.db_cols(), "column out of bounds");
        self.db[col * self.db_rows_padded() + row]
    }

    /// Return a logical database row.
    #[must_use]
    pub fn get_row(&self, row: usize) -> Vec<T> {
        (0..self.db_cols())
            .map(|col| self.get_elem_row_col(row, col))
            .collect()
    }

    /// Multiply one packed first-dimension query by the stored database.
    ///
    /// The default backend is the portable YPIR-style chunked split kernel,
    /// with reduction into InspiRING's single CRT modulus.
    #[must_use]
    pub fn multiply_query(&self, rlwe: &RlweParams, query: &[u64]) -> Vec<u64> {
        let rows = self.db_rows_padded();
        let cols = self.db_cols();
        assert_eq!(query.len(), rows, "query length must match padded rows");

        let mut out = vec![0u64; cols];
        self.kernel.multiply_query(
            rlwe,
            &self.db,
            rows,
            cols,
            query,
            self.element_max,
            &mut out,
        );
        out
    }

    /// Generate YPIR's `hint_0` from supplied offline query polynomials.
    ///
    /// This is the scalar, single-CRT analogue of YPIR's
    /// `answer_hint_ring`: for each DB column, split the column into `d`-row
    /// polynomial blocks, multiply by the corresponding query polynomial in
    /// `Z_q[X]/(X^d+1)`, and output the transposed `poly_len x db_cols`
    /// layout consumed by [`offline_precompute_from_hint`].
    #[must_use]
    /// Produce every hint column in coefficient form.
    ///
    /// Column `col` holds `hint_0[coeff * db_cols + col]` for each `coeff`,
    /// which is both what the row-major `hint_0` layout is transposed from and
    /// what a CRS block row is. Callers that only need the CRS blocks should use
    /// this and skip `hint_0` entirely.
    pub fn generate_hint_columns(
        &self,
        rlwe: &RlweParams,
        query_polys: &[Vec<u64>],
    ) -> Vec<Vec<u64>>
    where
        T: Sync,
    {
        self.validate_query_polys(rlwe, query_polys);
        let rows = self.db_rows_padded();
        let query_ntts: Vec<_> = query_polys
            .iter()
            .map(|query| polynomial_to_ntt(rlwe, query))
            .collect();

        (0..self.db_cols())
            .into_par_iter()
            .map(|col| self.generate_hint_column_from_query_ntts(rlwe, rows, col, &query_ntts))
            .collect()
    }

    fn validate_query_polys(&self, rlwe: &RlweParams, query_polys: &[Vec<u64>]) {
        // Hint generation feeds database elements straight into the NTT without
        // reducing them, which is only sound because SimplePIR plaintexts are
        // below `p <= q`. `element_max` was measured over the whole database at
        // load, so this restores that guarantee for one comparison rather than
        // the 9.4e8 divisions the old per-element `% q` cost.
        assert!(
            self.element_max < rlwe.q,
            "database elements must be reduced modulo q: max {} is not below q {}",
            self.element_max,
            rlwe.q
        );
        assert_eq!(
            self.db_rows() % rlwe.d,
            0,
            "db rows must split into d-row blocks"
        );
        assert_eq!(
            query_polys.len(),
            self.db_rows() / rlwe.d,
            "one query polynomial is required per d-row DB block"
        );
        for query in query_polys {
            assert_eq!(query.len(), rlwe.d, "query polynomial must have degree d");
        }
    }

    pub fn generate_hint_from_query_polys(
        &self,
        rlwe: &RlweParams,
        query_polys: &[Vec<u64>],
    ) -> Vec<u64>
    where
        T: Sync,
    {
        self.validate_query_polys(rlwe, query_polys);

        let cols = self.db_cols();
        let rows = self.db_rows_padded();
        // The offline query polynomials are reused for every DB column, so pay
        // the forward NTT cost once and keep the hot path in evaluation form.
        let query_ntts: Vec<_> = query_polys
            .iter()
            .map(|query| polynomial_to_ntt(rlwe, query))
            .collect();

        // Columns are independent. Each worker returns one coefficient-form
        // column so the final transpose can preserve YPIR's row-major hint
        // layout.
        let columns: Vec<_> = (0..cols)
            .into_par_iter()
            .map(|col| self.generate_hint_column_from_query_ntts(rlwe, rows, col, &query_ntts))
            .collect();

        let mut hint_0 = vec![0u64; rlwe.d * cols];

        // `hint_0[coeff * cols + col]` walked column-first is a scatter with one
        // live stream per column — the same shape that dominated snapshot
        // ingestion. Tiling both indices keeps the reads inside a
        // `HINT_TILE^2 * 8` byte working set and makes each write run of
        // `HINT_TILE` coefficients contiguous.
        for col_base in (0..cols).step_by(HINT_TILE) {
            let col_end = (col_base + HINT_TILE).min(cols);
            for coeff_base in (0..rlwe.d).step_by(HINT_TILE) {
                let coeff_end = (coeff_base + HINT_TILE).min(rlwe.d);
                for coeff in coeff_base..coeff_end {
                    let dst = &mut hint_0[coeff * cols + col_base..coeff * cols + col_end];
                    for (offset, slot) in dst.iter_mut().enumerate() {
                        *slot = columns[col_base + offset][coeff];
                    }
                }
            }
        }

        hint_0
    }

    /// Compute one `hint_0` column from pre-transformed query polynomials.
    ///
    /// The accumulator stays in NTT form across all row blocks. This replaces
    /// one inverse transform per product with a single inverse transform after
    /// all products for the column have been added.
    fn generate_hint_column_from_query_ntts<'a>(
        &self,
        rlwe: &'a RlweParams,
        rows: usize,
        col: usize,
        query_ntts: &[PolyMatrixNTT<'a>],
    ) -> Vec<u64> {
        // Three allocations per (column, block) is 1.4 M allocations at the
        // deployed shape. Hoist them: the buffers are overwritten every block.
        let mut acc = PolyMatrixNTT::zero(&rlwe.spiral, 1, 1);
        let mut db_raw = PolyMatrixRaw::zero(&rlwe.spiral, 1, 1);
        let mut db_ntt = PolyMatrixNTT::zero(&rlwe.spiral, 1, 1);
        let mut prod = PolyMatrixNTT::zero(&rlwe.spiral, 1, 1);

        for (block_idx, query_ntt) in query_ntts.iter().enumerate() {
            let row_start = block_idx * rlwe.d;
            {
                let db_poly = db_raw.get_poly_mut(0, 0);
                let src = &self.db[col * rows + row_start..][..rlwe.d];
                // Database entries are plaintexts below `p <= q`, so the
                // reduction the old code applied here was a no-op — and a
                // 64-bit division per element, 9.4e8 of them per snapshot.
                for (slot, value) in db_poly.iter_mut().zip(src) {
                    let value = value.to_u64();
                    debug_assert!(value < rlwe.q);
                    *slot = value;
                }
            }

            to_ntt(&mut db_ntt, &db_raw);
            multiply(&mut prod, query_ntt, &db_ntt);
            add_into(&mut acc, &prod);
        }

        // `from_ntt` reduces into `[0, q)`, so no further reduction is needed.
        let mut raw = PolyMatrixRaw::zero(&rlwe.spiral, 1, 1);
        from_ntt(&mut raw, &acc);
        raw.get_poly(0, 0).to_vec()
    }

    /// Generate `hint_0` and split it into InspiRING CRS blocks.
    #[must_use]
    pub fn perform_offline_precomputation_simplepir(
        &self,
        rlwe: &RlweParams,
        query_polys: &[Vec<u64>],
    ) -> OfflinePrecomputedValues
    where
        T: Sync,
    {
        assert_eq!(
            self.db_cols() % rlwe.d,
            0,
            "db_cols must split into RLWE blocks"
        );
        let blocks = self.db_cols() / rlwe.d;
        // `hint_0` is never read in production: `extract_crs_block` maps
        // `hint_0[coeff * db_cols + block * d + row]` back to hint column
        // `block * d + row`, coefficient `coeff` — which is exactly what
        // `generate_hint_column_from_query_ntts` already produces. Building the
        // 537 MiB buffer, transposing into it, and slicing it back out is an
        // identity re-layout. Assemble the CRS blocks from the columns instead.
        let columns = self.generate_hint_columns(rlwe, query_polys);
        // Move the column vectors into the blocks; cloning them here would deep
        // copy every coefficient back out again.
        let mut columns = columns.into_iter();
        let crs_blocks = (0..blocks)
            .map(|_| CrsBlock {
                rows: columns.by_ref().take(rlwe.d).collect(),
            })
            .collect();

        OfflinePrecomputedValues { crs_blocks }
    }

    /// Parse a raw `/query` body and use uploaded packing-key bodies.
    pub fn perform_full_online_computation_simplepir_measured<'a>(
        &self,
        rlwe: &RlweParams,
        query: &[u8],
        packing_keys: &PackingKeys<'a>,
        top_key_images: &TopKeyImages<'a>,
        preprocessed: &'a [QueryPackPreprocessed<'a>],
    ) -> Result<(Vec<u8>, OnlineServerTiming), InspiringError> {
        let deserialize_started = std::time::Instant::now();
        let first_dim_query = deserialize_first_dim_query(rlwe, &self.params, query)?;
        let deserialize = deserialize_started.elapsed();

        let matrix_started = std::time::Instant::now();
        let intermediate = self.multiply_query(rlwe, &first_dim_query);
        let matrix_vector = matrix_started.elapsed();

        let packing_started = std::time::Instant::now();
        let packed =
            pack_intermediate_blocks(&intermediate, packing_keys, top_key_images, preprocessed)?;
        let packing = packing_started.elapsed();

        let serialization_started = std::time::Instant::now();
        // Only `c2` goes back; `c1` is the snapshot-constant row served from
        // `published_c1_rows`.
        let response = serialize_rlwe_response_bodies(&packed, self.params.q_prime_1);
        let serialization = serialization_started.elapsed();

        Ok((
            response,
            OnlineServerTiming {
                deserialize,
                matrix_vector,
                packing,
                serialization,
            },
        ))
    }
}

/// Parse the switched first-dimension query for a declared global database.
///
/// A distributed coordinator uses this once, then gives every row shard the
/// matching coefficient slice. Workers never need packing keys or a target
/// index, and the concatenation of all slices is exactly the monolithic query.
pub fn deserialize_first_dim_query(
    rlwe: &RlweParams,
    ypir: &YpirSchemeParams,
    query: &[u8],
) -> Result<Vec<u64>, InspiringError> {
    let first_dim_query =
        IPIRSimpleQuery::from_switched_bytes(query, ypir.db_rows, rlwe.q, ypir.query_bits)?
            .into_first_dim();

    if first_dim_query.len() != ypir.db_rows {
        return Err(InspiringError::LweShape(format!(
            "expected {} first-dimension query values, got {}",
            ypir.db_rows,
            first_dim_query.len()
        )));
    }

    Ok(first_dim_query)
}

impl YServer<u16> {
    /// Build a `u16` server using the fastest available local first-pass kernel.
    ///
    /// On AVX512F hosts this selects the YPIR-style explicit vector kernel;
    /// otherwise it falls back to the portable chunked split kernel.
    pub fn new_auto_kernel<I>(
        params: YpirSchemeParams,
        db: I,
        input_is_transposed: bool,
        pad_rows: bool,
    ) -> Self
    where
        I: Iterator<Item = u16>,
    {
        let kernel: Box<dyn FirstDimKernel<u16>> = if U16Avx512Kernel::is_supported() {
            Box::new(U16Avx512Kernel::default())
        } else {
            Box::new(ChunkedSplitKernel::default())
        };

        Self::with_kernel(params, db, input_is_transposed, pad_rows, kernel)
    }
}

/// Convert a coefficient-form polynomial into the single-CRT NTT domain.
///
/// Callers validate the polynomial length before reaching this helper; reducing
/// here keeps both query and test inputs canonical under the RLWE modulus.
fn polynomial_to_ntt<'a>(rlwe: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixNTT<'a> {
    let mut raw = PolyMatrixRaw::zero(&rlwe.spiral, 1, 1);
    raw.get_poly_mut(0, 0)
        .iter_mut()
        .zip(coeffs)
        .for_each(|(out, coeff)| *out = coeff % rlwe.q);
    to_ntt_alloc(&raw)
}

/// IPIR-named alias for the YPIR-shaped server database.
pub type IPIRServer<T> = YServer<T>;

#[cfg(test)]
fn add_assign_mod(out: &mut [u64], rhs: &[u64], modulus: u64) {
    assert_eq!(out.len(), rhs.len());
    for (out_coeff, rhs_coeff) in out.iter_mut().zip(rhs) {
        *out_coeff = ((*out_coeff as u128 + *rhs_coeff as u128) % modulus as u128) as u64;
    }
}

#[cfg(test)]
fn negacyclic_mul_mod(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    assert_eq!(left.len(), right.len());
    let degree = left.len();
    let mut out = vec![0u64; degree];

    for (i, left_coeff) in left.iter().enumerate() {
        for (j, right_coeff) in right.iter().enumerate() {
            let product = (*left_coeff as u128 * *right_coeff as u128) % modulus as u128;
            let idx = i + j;
            if idx < degree {
                out[idx] = ((out[idx] as u128 + product) % modulus as u128) as u64;
            } else {
                let wrapped = idx - degree;
                out[wrapped] =
                    ((out[wrapped] as u128 + modulus as u128 - product) % modulus as u128) as u64;
            }
        }
    }

    out
}

/// Offline values that are independent of the user's online query.
#[derive(Debug, Clone)]
pub struct OfflinePrecomputedValues {
    /// CRS blocks, one per RLWE output block.
    ///
    /// YPIR's `hint_0` used to be carried here alongside them. It is gone:
    /// nothing outside tests ever read it, and materializing the full
    /// `poly_len x db_cols` buffer (537 MiB at the deployed shape) only to
    /// transpose into it and slice it straight back out was an identity
    /// re-layout. `YServer::generate_hint_from_query_polys` still builds it for
    /// callers that want that layout.
    pub crs_blocks: Vec<CrsBlock>,
}

/// One InspiRING CRS block, represented before conversion to `PolyMatrixNTT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrsBlock {
    /// `d` LWE `a` rows, each with `d` coefficients.
    pub rows: Vec<Vec<u64>>,
}

impl CrsBlock {
    /// Convert this block into the `[d, 1]` NTT CRS shape expected by packing
    /// preprocessing.
    pub fn to_ntt<'a>(&self, params: &'a RlweParams) -> PolyMatrixNTT<'a> {
        assert_eq!(self.rows.len(), params.d, "CRS block must have d rows");

        let mut raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
        for (row_idx, row) in self.rows.iter().enumerate() {
            assert_eq!(row.len(), params.d, "CRS row must have d coefficients");
            let poly = raw.get_poly_mut(row_idx, 0);
            for (coeff_idx, coeff) in row.iter().enumerate() {
                poly[coeff_idx] = coeff % params.q;
            }
        }

        to_ntt_alloc(&raw)
    }

    fn validate_shape(&self, params: &RlweParams) -> Result<(), InspiringError> {
        if self.rows.len() != params.d || self.rows.iter().any(|row| row.len() != params.d) {
            return Err(InspiringError::PreprocessMismatch(format!(
                "CRS block must be {}x{}",
                params.d, params.d
            )));
        }

        Ok(())
    }
}

/// Add a worker's SimplePIR intermediate into a coordinator accumulator.
///
/// The first-dimension operation is linear over `Z_q`: if row shards partition
/// a database, summing their fixed-width outputs produces the exact monolithic
/// matrix-vector product. Inputs are required to be canonical residues so a
/// corrupt worker cannot smuggle an overflow or a second representation of the
/// same value across the protocol boundary.
pub fn add_intermediate_assign_mod(
    accumulator: &mut [u64],
    contribution: &[u64],
    modulus: u64,
) -> Result<(), InspiringError> {
    if modulus < 2 {
        return Err(InspiringError::PreprocessMismatch(
            "intermediate modulus must be at least two".to_string(),
        ));
    }
    if accumulator.len() != contribution.len() {
        return Err(InspiringError::LweShape(format!(
            "intermediate widths differ: {} and {}",
            accumulator.len(),
            contribution.len()
        )));
    }

    for (left, right) in accumulator.iter_mut().zip(contribution) {
        if *left >= modulus || *right >= modulus {
            return Err(InspiringError::PreprocessMismatch(
                "intermediate coefficient is not reduced modulo q".to_string(),
            ));
        }
        let sum = u128::from(*left) + u128::from(*right);
        *left = (sum % u128::from(modulus)) as u64;
    }

    Ok(())
}

/// Add one shard's partial CRS/hint contribution into the global CRS.
///
/// Each contribution must have the complete output-block shape. This function
/// is deliberately shape-strict because the resulting public `c1` is bound to
/// the snapshot and a missing coefficient would silently make clients decode
/// garbage.
pub fn add_crs_blocks_assign_mod(
    accumulator: &mut [CrsBlock],
    contribution: &[CrsBlock],
    params: &RlweParams,
) -> Result<(), InspiringError> {
    if accumulator.len() != contribution.len() {
        return Err(InspiringError::PreprocessMismatch(format!(
            "CRS block counts differ: {} and {}",
            accumulator.len(),
            contribution.len()
        )));
    }

    for (left_block, right_block) in accumulator.iter_mut().zip(contribution) {
        left_block.validate_shape(params)?;
        right_block.validate_shape(params)?;
        for (left_row, right_row) in left_block.rows.iter_mut().zip(&right_block.rows) {
            add_intermediate_assign_mod(left_row, right_row, params.q)?;
        }
    }

    Ok(())
}

/// Produce offline values from a supplied `hint_0`.
///
/// The old YPIR implementation continues from this point into CDKS
/// `prep_pack_many_lwes` and `precompute_pack`; `ipir-sp` stops at CRS block
/// extraction so the next layer can build the public packing precomputation.
#[must_use]
pub fn offline_precompute_from_hint(
    rlwe: &RlweParams,
    ypir: &YpirSchemeParams,
    hint_0: Vec<u64>,
) -> OfflinePrecomputedValues {
    assert_eq!(
        hint_0.len(),
        rlwe.d * ypir.db_cols,
        "hint_0 must be poly_len x db_cols"
    );
    assert_eq!(
        ypir.db_cols % rlwe.d,
        0,
        "db_cols must split into RLWE blocks"
    );

    let num_rlwe_outputs = ypir.db_cols / rlwe.d;
    let crs_blocks = (0..num_rlwe_outputs)
        .map(|block| extract_crs_block(rlwe, ypir, &hint_0, block))
        .collect();

    OfflinePrecomputedValues { crs_blocks }
}

/// Build CRS/public preprocessing for uploaded packing-key queries.
pub fn build_pack_preprocessed_blocks<'a>(
    params: &'a RlweParams,
    crs_blocks: &[CrsBlock],
) -> Result<Vec<QueryPackPreprocessed<'a>>, InspiringError> {
    // Blocks are independent. Each one is internally parallel only in its
    // aggregate step; its collapse cascade is serial, so building them one at a
    // time left most cores idle for most of the offline phase.
    crs_blocks
        .par_iter()
        .map(|block| {
            let crs = block.to_ntt(params);
            QueryPackPreprocessed::build(params, &crs)
        })
        .collect()
}

/// Tile edge for the hint transpose, in both coefficients and columns.
///
/// `HINT_TILE * HINT_TILE * 8` bytes (512 KiB) is the read working set.
const HINT_TILE: usize = 256;

/// Rows of input staged before being scattered into column-major storage.
///
/// Sized so one tile stays comfortably inside last-level cache
/// (`INGEST_ROW_TILE * cols * size_of::<T>()`; 4 MiB for the deployed
/// `u16` shape) and so each per-column write covers whole cache lines:
/// 64 `u16` is 128 bytes, two full lines.
const INGEST_ROW_TILE: usize = 64;

/// Columns processed per pass over a staged tile.
///
/// Bounds the staging working set of the transpose step to
/// `INGEST_ROW_TILE * INGEST_COL_TILE * size_of::<T>()` — 64 KiB for `u16` —
/// which keeps it in L2 while the strided reads run.
const INGEST_COL_TILE: usize = 512;

/// Materialize a row-major database into column-major storage, blocked.
///
/// The straightforward loop — write `stored[col * padded_rows + row]` while
/// walking the input row-major — is a scatter with one live write stream per
/// column. At the deployed shape that is 32,768 streams touching 2.1 MiB of
/// distinct cache lines per input row, and it dominated cold start at 184 s,
/// 91% of the total. It is also why widening the database made ingestion
/// disproportionately slower: the element count is fixed, but the stream count
/// scales with the column count.
///
/// Staging a tile of rows first turns each per-column write into
/// `tile_rows` contiguous elements, so a cache line is filled once instead of
/// being revisited `tile_rows` times. The result is byte-identical to the
/// naive order; `ingest_row_major_matches_naive_scatter` pins that.
fn ingest_row_major<T, I, F>(
    db: &mut I,
    stored: &mut [T],
    rows: usize,
    cols: usize,
    padded_rows: usize,
    element_max: &mut u64,
    mut take: F,
) where
    T: Copy + Default,
    I: Iterator<Item = T>,
    F: FnMut(&mut I, &mut u64) -> T,
{
    if rows == 0 || cols == 0 {
        return;
    }

    let mut staging = vec![T::default(); INGEST_ROW_TILE * cols];
    let mut row_base = 0;

    while row_base < rows {
        let tile_rows = INGEST_ROW_TILE.min(rows - row_base);

        // Consume the iterator in its natural row-major order.
        for slot in staging[..tile_rows * cols].iter_mut() {
            *slot = take(db, element_max);
        }

        for col_base in (0..cols).step_by(INGEST_COL_TILE) {
            let col_end = (col_base + INGEST_COL_TILE).min(cols);
            for col in col_base..col_end {
                let dst = &mut stored[col * padded_rows + row_base..][..tile_rows];
                for (offset, slot) in dst.iter_mut().enumerate() {
                    *slot = staging[offset * cols + col];
                }
            }
        }

        row_base += tile_rows;
    }
}

/// Serialize the snapshot-constant `c1` row of every output block.
///
/// `QueryPackPreprocessed::collapse_a_final_ntt` is derived from the CRS and
/// the fixed reference seeds alone, so it is the same for every client and
/// every query against a snapshot. Publishing it once with the server metadata
/// removes it from every response — at the production shape that is 28,672 of
/// the 49,152 response bytes — and lets it be sent at full precision, which
/// also drops the rounding term it used to add to the client's noise.
#[must_use]
pub fn published_c1_rows(preprocessed: &[QueryPackPreprocessed<'_>], q: u64) -> Vec<u8> {
    let bits = crate::modulus_switch::modulus_bits(q);
    let mut out = Vec::new();
    for pre in preprocessed {
        let raw = from_ntt_alloc(&pre.collapse_a_final_ntt);
        out.extend_from_slice(&crate::bits::u64s_to_contiguous_bytes(
            raw.get_poly(0, 0),
            bits,
        ));
    }
    out
}

/// Pack online SimplePIR intermediate values using uploaded packing-key bodies.
pub fn pack_intermediate_blocks<'a>(
    intermediate: &[u64],
    packing_keys: &PackingKeys<'a>,
    top_key_images: &TopKeyImages<'a>,
    preprocessed: &'a [QueryPackPreprocessed<'a>],
) -> Result<Vec<RlweCiphertext<'a>>, InspiringError> {
    let Some(first) = preprocessed.first() else {
        return if intermediate.is_empty() {
            Ok(Vec::new())
        } else {
            Err(InspiringError::PreprocessMismatch(
                "non-empty intermediate with no preprocessing blocks".to_string(),
            ))
        };
    };
    let params = first.params;
    if intermediate.len() != preprocessed.len() * params.d {
        return Err(InspiringError::LweShape(format!(
            "expected {} intermediate values for {} blocks of d={}, got {}",
            preprocessed.len() * params.d,
            preprocessed.len(),
            params.d,
            intermediate.len()
        )));
    }
    packing_keys.validate(params)?;
    top_key_images.validate(params)?;

    intermediate
        .par_chunks_exact(params.d)
        .zip(preprocessed.par_iter())
        .enumerate()
        .map(|(block_idx, (b_block, pre))| {
            if pre.params.d != params.d || pre.params.q != params.q {
                return Err(InspiringError::PreprocessMismatch(format!(
                    "preprocessing block {block_idx} uses mismatched RLWE parameters"
                )));
            }

            pre.pack_b_prevalidated(b_block, packing_keys, top_key_images)
        })
        .collect()
}

/// Extract one `d x d` InspiRING CRS block from `hint_0`.
///
/// `hint_0` is row-major as `hint_0[row * db_cols + col]`. For RLWE output
/// block `i`, column range `[i*d, (i+1)*d)` becomes the `d` CRS rows. This
/// keeps the single-CRT InspiRING modulus boundary explicit by reducing every
/// coefficient modulo `rlwe.q`.
#[must_use]
pub fn extract_crs_block(
    rlwe: &RlweParams,
    ypir: &YpirSchemeParams,
    hint_0: &[u64],
    block: usize,
) -> CrsBlock {
    assert_eq!(
        hint_0.len(),
        rlwe.d * ypir.db_cols,
        "hint_0 must be poly_len x db_cols"
    );
    assert!(block < ypir.db_cols / rlwe.d, "CRS block out of bounds");

    let col_start = block * rlwe.d;
    let mut rows = vec![vec![0u64; rlwe.d]; rlwe.d];
    for (crs_row, row) in rows.iter_mut().enumerate().take(rlwe.d) {
        let hint_col = col_start + crs_row;
        for coeff in 0..rlwe.d {
            row[coeff] = hint_0[coeff * ypir.db_cols + hint_col] % rlwe.q;
        }
    }

    CrsBlock { rows }
}

impl YpirSchemeParams {
    fn db_rows_padded_simplepir(&self) -> usize {
        self.db_rows
    }
}

#[cfg(test)]
mod tests {
    use inspiring::{GadgetParams, PackingKeys, RlweParams, TopKeyImages};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use simplepir_kernel::ScalarKernel;
    use spiral_rs::poly::{from_ntt_alloc, to_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw};

    use crate::client::IPIRSimpleQuery;
    use crate::modulus_switch::{recover_response_body, response_body_len};

    use super::*;

    fn tiny_rlwe() -> RlweParams {
        RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 3,
                ell: 5,
            },
        )
        .expect("valid params")
    }

    fn tiny_ypir(db_rows: usize, db_cols: usize) -> YpirSchemeParams {
        YpirSchemeParams {
            num_items: db_rows as u64,
            item_size_bits: (db_cols * 14) as u64,
            poly_len: 8,
            db_dim_1: 0,
            db_dim_2: 1,
            instances: db_cols / 8,
            db_rows,
            db_cols,
            p: 4,
            q_prime_1: 16,
            q_prime_2: 257,
            q2_bits: 8,
            t_exp_left: 3,
            t_exp_right: 2,
            // Tiny fixtures exercise exact arithmetic, so they transmit the
            // query at full precision.
            query_bits: 14,
        }
    }

    fn secret_ntt<'a>(params: &'a RlweParams) -> PolyMatrixNTT<'a> {
        let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
        raw.get_poly_mut(0, 0)
            .copy_from_slice(&[1, 0, params.q - 1, 1, 0, 1, 0, 0]);
        to_ntt_alloc(&raw)
    }

    fn scalar_hint_reference(
        server: &YServer<u16>,
        rlwe: &RlweParams,
        query_polys: &[Vec<u64>],
    ) -> Vec<u64> {
        let cols = server.db_cols();
        let rows = server.db_rows_padded();
        let mut hint_0 = vec![0u64; rlwe.d * cols];

        for col in 0..cols {
            let mut sum = vec![0u64; rlwe.d];
            for (block_idx, query) in query_polys.iter().enumerate() {
                let row_start = block_idx * rlwe.d;
                let db_poly: Vec<_> = (0..rlwe.d)
                    .map(|coeff| server.db()[col * rows + row_start + coeff].to_u64() % rlwe.q)
                    .collect();
                let prod = negacyclic_mul_mod(query, &db_poly, rlwe.q);
                add_assign_mod(&mut sum, &prod, rlwe.q);
            }

            for coeff in 0..rlwe.d {
                hint_0[coeff * cols + col] = sum[coeff];
            }
        }

        hint_0
    }

    #[test]
    fn server_stores_row_major_input_as_column_major() {
        let ypir = tiny_ypir(4, 3);
        let input = 0u16..12;
        let server = YServer::new(ypir, input, false, true);

        assert_eq!(server.db(), &[0, 3, 6, 9, 1, 4, 7, 10, 2, 5, 8, 11]);
        assert_eq!(server.get_row(2), vec![6, 7, 8]);
    }

    /// The blocked ingestion must produce byte-identical storage to the naive
    /// scatter it replaced, including at shapes that do not divide the tiles.
    #[test]
    fn ingest_row_major_matches_naive_scatter() {
        // Deliberately awkward shapes: smaller than a tile, straddling a tile,
        // and not a multiple of either tile dimension.
        for &(rows, cols, padded_rows) in &[
            (1usize, 1usize, 1usize),
            (3, 5, 3),
            (7, 1024, 9),
            (super::INGEST_ROW_TILE, 4, super::INGEST_ROW_TILE),
            (
                super::INGEST_ROW_TILE + 1,
                super::INGEST_COL_TILE + 3,
                super::INGEST_ROW_TILE + 5,
            ),
            (130, 1100, 160),
        ] {
            let values: Vec<u16> = (0..rows * cols).map(|i| (i % 16_384) as u16).collect();

            let mut naive = vec![0u16; padded_rows * cols];
            let mut naive_max = 0u64;
            let mut it = values.iter().copied();
            for row in 0..rows {
                for col in 0..cols {
                    let value = it.next().expect("input");
                    naive_max = naive_max.max(u64::from(value));
                    naive[col * padded_rows + row] = value;
                }
            }

            let mut blocked = vec![0u16; padded_rows * cols];
            let mut blocked_max = 0u64;
            let mut it = values.iter().copied();
            super::ingest_row_major(
                &mut it,
                &mut blocked,
                rows,
                cols,
                padded_rows,
                &mut blocked_max,
                |db: &mut std::iter::Copied<std::slice::Iter<'_, u16>>, m: &mut u64| {
                    let value = db.next().expect("input");
                    *m = (*m).max(u64::from(value));
                    value
                },
            );

            assert_eq!(
                blocked, naive,
                "layout differs at {rows}x{cols} pad {padded_rows}"
            );
            assert_eq!(
                blocked_max, naive_max,
                "element_max differs at {rows}x{cols}"
            );
        }
    }

    /// Both ingestion orders must agree, so a transposed input and its
    /// row-major twin land in the same storage.
    #[test]
    fn ingest_orders_agree_on_the_same_matrix() {
        let (rows, cols) = (37usize, 91usize);
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(rows, cols);
        let row_major: Vec<u16> = (0..rows * cols).map(|i| (i % 4) as u16).collect();
        let mut col_major: Vec<u16> = Vec::with_capacity(rows * cols);
        for c in 0..cols {
            for r in 0..rows {
                col_major.push(row_major[r * cols + c]);
            }
        }

        let a = YServer::new(ypir.clone(), row_major.iter().copied(), false, true);
        let b = YServer::new(ypir, col_major.into_iter(), true, true);
        let query: Vec<u64> = (0..rows).map(|i| (i as u64 * 7 + 1) % rlwe.q).collect();
        assert_eq!(
            a.multiply_query(&rlwe, &query),
            b.multiply_query(&rlwe, &query)
        );
    }

    #[test]
    fn multiply_query_matches_plain_matrix_vector_product_mod_q() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(4, 3);
        let server = YServer::new(ypir, 0u16..12, false, true);
        let query = [2, 3, 5, 7];

        let result = server.multiply_query(&rlwe, &query);

        assert_eq!(
            result,
            vec![
                102,
                2 + 3 * 4 + 5 * 7 + 7 * 10,
                2 * 2 + 3 * 5 + 5 * 8 + 7 * 11
            ]
        );
    }

    #[test]
    fn row_shard_intermediates_sum_to_monolithic_result() {
        let rlwe = tiny_rlwe();
        let global_params = tiny_ypir(16, 8);
        let shard_params = tiny_ypir(8, 8);
        let db: Vec<u16> = (0..128).map(|value| (value % 4) as u16).collect();
        let query: Vec<u64> = (0..16).map(|value| (value * 17 + 3) as u64).collect();

        let global = YServer::new(global_params, db.iter().copied(), false, true);
        let first = YServer::new(shard_params.clone(), db[..64].iter().copied(), false, true);
        let second = YServer::new(shard_params, db[64..].iter().copied(), false, true);

        let mut combined = first.multiply_query(&rlwe, &query[..8]);
        add_intermediate_assign_mod(
            &mut combined,
            &second.multiply_query(&rlwe, &query[8..]),
            rlwe.q,
        )
        .expect("matching shard output");

        assert_eq!(combined, global.multiply_query(&rlwe, &query));
    }

    #[test]
    fn row_shard_crs_contributions_sum_to_monolithic_crs() {
        let rlwe = tiny_rlwe();
        let global_params = tiny_ypir(16, 8);
        let shard_params = tiny_ypir(8, 8);
        let db: Vec<u16> = (0..128).map(|value| (value % 4) as u16).collect();
        let setup = vec![
            vec![1, 3, 5, 7, 9, 11, 13, 15],
            vec![2, 4, 6, 8, 10, 12, 14, 16],
        ];

        let global = YServer::new(global_params, db.iter().copied(), false, true);
        let first = YServer::new(shard_params.clone(), db[..64].iter().copied(), false, true);
        let second = YServer::new(shard_params, db[64..].iter().copied(), false, true);
        let expected = global.perform_offline_precomputation_simplepir(&rlwe, &setup);
        let mut combined = first
            .perform_offline_precomputation_simplepir(&rlwe, &setup[..1])
            .crs_blocks;
        let second = second
            .perform_offline_precomputation_simplepir(&rlwe, &setup[1..])
            .crs_blocks;

        add_crs_blocks_assign_mod(&mut combined, &second, &rlwe)
            .expect("matching CRS contribution");

        assert_eq!(combined, expected.crs_blocks);
    }

    #[test]
    fn distributed_combiners_reject_malformed_contributions() {
        let rlwe = tiny_rlwe();
        let mut intermediate = vec![0; 8];
        assert!(add_intermediate_assign_mod(&mut intermediate, &[0; 7], rlwe.q).is_err());
        let mut malformed = vec![CrsBlock { rows: vec![] }];
        assert!(
            add_crs_blocks_assign_mod(&mut malformed, &[CrsBlock { rows: vec![] }], &rlwe).is_err()
        );
        assert!(add_intermediate_assign_mod(&mut intermediate, &[rlwe.q; 8], rlwe.q).is_err());
    }

    #[test]
    fn public_setup_is_prefix_stable_when_global_capacity_grows() {
        let seed = [42; 32];
        let small = crate::IPIRClient::from_db_sz(8_192, 4_896 * 8);
        let large = crate::IPIRClient::from_db_sz(32_768, 4_896 * 8);
        let small_setup = small.generate_public_query_setup_simplepir_from_seed(seed);
        let large_setup = large.generate_public_query_setup_simplepir_from_seed(seed);

        assert_eq!(small_setup, large_setup[..small_setup.len()]);
    }

    #[test]
    fn default_kernel_matches_scalar_kernel() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(16, 5);
        let default_server = YServer::new(ypir.clone(), 0u16..80, false, true);
        let scalar_server =
            YServer::with_kernel(ypir, 0u16..80, false, true, Box::new(ScalarKernel));
        let query = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

        assert_eq!(
            default_server.multiply_query(&rlwe, &query),
            scalar_server.multiply_query(&rlwe, &query)
        );
    }

    #[test]
    fn polynomial_to_ntt_roundtrips_reduced_coefficients() {
        let rlwe = tiny_rlwe();
        let coeffs = vec![0, 1, rlwe.q + 2, 3, rlwe.q * 2 + 4, 5, 6, 7];

        let ntt = polynomial_to_ntt(&rlwe, &coeffs);
        let raw = from_ntt_alloc(&ntt);

        assert_eq!(raw.get_poly(0, 0), vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn generate_hint_column_from_query_ntts_matches_scalar_column_reference() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(16, 16);
        let server = YServer::new(ypir.clone(), 0u16..256, false, true);
        let query = vec![vec![3, 1, 4, 1, 5, 9, 2, 6], vec![5, 3, 5, 8, 9, 7, 9, 3]];
        let query_ntts: Vec<_> = query
            .iter()
            .map(|poly| polynomial_to_ntt(&rlwe, poly))
            .collect();
        let col = 5;

        let column = server.generate_hint_column_from_query_ntts(
            &rlwe,
            server.db_rows_padded(),
            col,
            &query_ntts,
        );
        let reference = scalar_hint_reference(&server, &rlwe, &query);
        let expected_column: Vec<_> = (0..rlwe.d)
            .map(|coeff| reference[coeff * ypir.db_cols + col])
            .collect();

        assert_eq!(column, expected_column);
    }

    #[test]
    fn generate_hint_from_query_polys_maps_single_block_to_hint_layout() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(8, 8);
        let server = YServer::new(ypir.clone(), 0u16..64, false, true);
        let query = vec![vec![1, 0, 0, 0, 0, 0, 0, 0]];

        let hint_0 = server.generate_hint_from_query_polys(&rlwe, &query);

        assert_eq!(hint_0.len(), rlwe.d * ypir.db_cols);
        for coeff in 0..rlwe.d {
            for col in 0..ypir.db_cols {
                assert_eq!(
                    hint_0[coeff * ypir.db_cols + col],
                    (coeff * ypir.db_cols + col) as u64
                );
            }
        }
    }

    #[test]
    fn generate_hint_from_query_polys_sums_multiple_row_blocks() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(16, 8);
        let server = YServer::new(ypir.clone(), 0u16..128, false, true);
        let query = vec![vec![1, 0, 0, 0, 0, 0, 0, 0], vec![1, 0, 0, 0, 0, 0, 0, 0]];

        let hint_0 = server.generate_hint_from_query_polys(&rlwe, &query);

        for coeff in 0..rlwe.d {
            for col in 0..ypir.db_cols {
                let first = coeff * ypir.db_cols + col;
                let second = (rlwe.d + coeff) * ypir.db_cols + col;
                assert_eq!(hint_0[coeff * ypir.db_cols + col], (first + second) as u64);
            }
        }
    }

    #[test]
    fn generate_hint_from_query_polys_matches_scalar_negacyclic_reference() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(16, 16);
        let server = YServer::new(ypir, 0u16..256, false, true);
        let query = vec![vec![3, 1, 4, 1, 5, 9, 2, 6], vec![5, 3, 5, 8, 9, 7, 9, 3]];

        let hint_0 = server.generate_hint_from_query_polys(&rlwe, &query);
        let expected = scalar_hint_reference(&server, &rlwe, &query);

        assert_eq!(hint_0, expected);
    }

    /// The direct column-to-CRS path must produce exactly the blocks the old
    /// `hint_0` materialize-then-extract route did. This is the pin for
    /// dropping the 537 MiB intermediate.
    #[test]
    fn crs_blocks_match_the_hint_materialize_and_extract_route() {
        for (rows, cols) in [(8usize, 8usize), (16, 16), (24, 32)] {
            let rlwe = tiny_rlwe();
            let ypir = tiny_ypir(rows, cols);
            let server = YServer::new(
                ypir.clone(),
                (0..rows * cols).map(|i| (i % 4) as u16),
                false,
                true,
            );
            let query: Vec<Vec<u64>> = (0..rows / rlwe.d)
                .map(|b| {
                    (0..rlwe.d)
                        .map(|i| ((i * 7 + b * 13 + 1) as u64) % rlwe.q)
                        .collect()
                })
                .collect();

            let direct = server.perform_offline_precomputation_simplepir(&rlwe, &query);
            let hint_0 = server.generate_hint_from_query_polys(&rlwe, &query);
            let viahint = offline_precompute_from_hint(&rlwe, &ypir, hint_0);

            assert_eq!(
                direct.crs_blocks, viahint.crs_blocks,
                "CRS blocks differ at {rows}x{cols}"
            );
            assert_eq!(direct.crs_blocks.len(), cols / rlwe.d);
        }
    }

    #[test]
    fn perform_offline_precomputation_simplepir_generates_blocks_from_db() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(8, 16);
        let server = YServer::new(ypir.clone(), 0u16..128, false, true);
        let query = vec![vec![1, 0, 0, 0, 0, 0, 0, 0]];

        let offline = server.perform_offline_precomputation_simplepir(&rlwe, &query);

        assert_eq!(offline.crs_blocks.len(), 2);
        assert_eq!(
            offline.crs_blocks[1].rows[0],
            vec![8, 24, 40, 56, 72, 88, 104, 120]
        );
    }

    #[test]
    fn extract_crs_block_maps_hint_columns_to_crs_rows() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(4, 16);
        let hint_0: Vec<_> = (0..rlwe.d)
            .flat_map(|row| (0..ypir.db_cols).map(move |col| (row * 100 + col) as u64))
            .collect();

        let block = extract_crs_block(&rlwe, &ypir, &hint_0, 1);

        assert_eq!(block.rows[0], vec![8, 108, 208, 308, 408, 508, 608, 708]);
        assert_eq!(block.rows[7], vec![15, 115, 215, 315, 415, 515, 615, 715]);
    }

    #[test]
    fn offline_precompute_splits_one_block_per_rlwe_output() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(4, 16);
        let hint_0 = vec![1u64; rlwe.d * ypir.db_cols];

        let offline = offline_precompute_from_hint(&rlwe, &ypir, hint_0);

        assert_eq!(offline.crs_blocks.len(), 2);
        assert_eq!(offline.crs_blocks[0].rows.len(), rlwe.d);
        assert_eq!(offline.crs_blocks[0].rows[0].len(), rlwe.d);
    }

    #[test]
    fn crs_block_converts_to_inspiring_ntt_shape() {
        let rlwe = tiny_rlwe();
        let block = CrsBlock {
            rows: (0..rlwe.d)
                .map(|row| {
                    (0..rlwe.d)
                        .map(|coeff| (row * 100 + coeff) as u64)
                        .collect()
                })
                .collect(),
        };

        let crs = block.to_ntt(&rlwe);
        let raw = from_ntt_alloc(&crs);

        assert_eq!(crs.rows, rlwe.d);
        assert_eq!(crs.cols, 1);
        assert_eq!(
            raw.get_poly(3, 0),
            vec![300, 301, 302, 303, 304, 305, 306, 307]
        );
    }

    #[test]
    fn pack_intermediate_blocks_routes_b_values_with_uploaded_packing_keys() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(4, 16);
        let hint_0 = vec![0u64; rlwe.d * ypir.db_cols];
        let offline = offline_precompute_from_hint(&rlwe, &ypir, hint_0);
        let pre = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks).expect("build");
        assert_eq!(
            pre.len(),
            2,
            "test fixture must exercise multi-block packing"
        );
        let mut rng = ChaCha20Rng::seed_from_u64(0x5155);
        let secret = secret_ntt(&rlwe);
        let keys = PackingKeys::generate_full(&rlwe, &secret, &mut rng);
        let top_keys = TopKeyImages::build(&rlwe);
        let intermediate: Vec<_> = (0..ypir.db_cols).map(|idx| idx as u64 + 10).collect();

        let packed = pack_intermediate_blocks(&intermediate, &keys, &top_keys, &pre).expect("pack");

        assert_eq!(packed.len(), 2);
        for (block_idx, ct) in packed.iter().enumerate() {
            let raw = from_ntt_alloc(&ct.inner);
            let expected = intermediate[block_idx * rlwe.d..(block_idx + 1) * rlwe.d].to_vec();
            assert_eq!(raw.get_poly(1, 0), expected);
        }
    }

    #[test]
    fn pack_intermediate_blocks_rejects_wrong_intermediate_length() {
        let rlwe = tiny_rlwe();
        let block = CrsBlock {
            rows: vec![vec![0; rlwe.d]; rlwe.d],
        };
        let pre = build_pack_preprocessed_blocks(&rlwe, &[block]).expect("build");
        let mut rng = ChaCha20Rng::seed_from_u64(0x5157);
        let secret = secret_ntt(&rlwe);
        let keys = PackingKeys::generate_full(&rlwe, &secret, &mut rng);
        let top_keys = TopKeyImages::build(&rlwe);

        let err = match pack_intermediate_blocks(&[1, 2, 3], &keys, &top_keys, &pre) {
            Ok(_) => panic!("wrong intermediate length must fail"),
            Err(err) => err,
        };

        assert!(matches!(err, InspiringError::LweShape(_)));
    }

    #[test]
    fn perform_online_computation_simplepir_with_uploaded_packing_keys_serializes_response() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(4, 8);
        let server = YServer::new(ypir.clone(), 0u16..32, false, true);
        let hint_0 = vec![0u64; rlwe.d * ypir.db_cols];
        let offline = offline_precompute_from_hint(&rlwe, &ypir, hint_0);
        let pre = build_pack_preprocessed_blocks(&rlwe, &offline.crs_blocks).expect("build");
        let mut rng = ChaCha20Rng::seed_from_u64(0x5156);
        let secret = secret_ntt(&rlwe);
        let keys = PackingKeys::generate_full(&rlwe, &secret, &mut rng);
        let top_keys = TopKeyImages::build(&rlwe);
        let query = IPIRSimpleQuery::new(vec![1, 0, 0, 0]).to_packed_bytes(rlwe.q);

        let (response, _timing) = server
            .perform_full_online_computation_simplepir_measured(
                &rlwe, &query, &keys, &top_keys, &pre,
            )
            .expect("online response");

        assert_eq!(response.len(), response_body_len(rlwe.d, ypir.q_prime_1));

        let row_1 = recover_response_body(&response, rlwe.d, ypir.q_prime_1, rlwe.q);
        let expected_intermediate = server.multiply_query(&rlwe, &[1, 0, 0, 0]);
        let expected_row_1: Vec<_> = expected_intermediate
            .iter()
            .map(|value| {
                crate::modulus_switch::rescale(
                    crate::modulus_switch::rescale(*value, rlwe.q, ypir.q_prime_1),
                    ypir.q_prime_1,
                    rlwe.q,
                )
            })
            .collect();

        assert_eq!(row_1, expected_row_1);
    }
}
