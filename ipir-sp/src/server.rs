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
use simplepir_kernel::{ChunkedSplitKernel, FirstDimKernel};
use spiral_rs::poly::{
    add_into, from_ntt_alloc, multiply, to_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw,
};
use std::time::Duration;

use crate::client::IPIRSimpleQuery;
use crate::modulus_switch::serialize_rlwe_response;
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

        if input_is_transposed {
            for col in 0..cols {
                for row in 0..rows {
                    stored[col * padded_rows + row] = db.next().expect("database is too short");
                }
            }
        } else {
            for row in 0..rows {
                for col in 0..cols {
                    stored[col * padded_rows + row] = db.next().expect("database is too short");
                }
            }
        }

        kernel.prepare(&stored, padded_rows, cols);

        Self {
            params,
            db: stored,
            pad_rows,
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
        self.kernel
            .multiply_query(rlwe, &self.db, rows, cols, query, &mut out);
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
    pub fn generate_hint_from_query_polys(
        &self,
        rlwe: &RlweParams,
        query_polys: &[Vec<u64>],
    ) -> Vec<u64>
    where
        T: Sync,
    {
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

        let cols = self.db_cols();
        let rows = self.db_rows_padded();
        // The offline query polynomials are reused for every DB column, so pay
        // the forward NTT cost once and keep the hot path in evaluation form.
        let query_ntts: Vec<_> = query_polys
            .iter()
            .map(|query| polynomial_to_ntt(rlwe, query))
            .collect();

        // Columns are independent. Each worker returns one coefficient-form
        // column so the final scatter can preserve YPIR's row-major hint layout.
        let columns: Vec<_> = (0..cols)
            .into_par_iter()
            .map(|col| self.generate_hint_column_from_query_ntts(rlwe, rows, col, &query_ntts))
            .collect();

        let mut hint_0 = vec![0u64; rlwe.d * cols];

        for (col, column) in columns.iter().enumerate() {
            for coeff in 0..rlwe.d {
                hint_0[coeff * cols + col] = column[coeff];
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
        let mut acc = PolyMatrixNTT::zero(&rlwe.spiral, 1, 1);

        for (block_idx, query_ntt) in query_ntts.iter().enumerate() {
            let row_start = block_idx * rlwe.d;
            let mut db_raw = PolyMatrixRaw::zero(&rlwe.spiral, 1, 1);
            {
                let db_poly = db_raw.get_poly_mut(0, 0);
                for (coeff_idx, coeff) in db_poly.iter_mut().enumerate() {
                    *coeff = self.db[col * rows + row_start + coeff_idx].to_u64() % rlwe.q;
                }
            }

            let db_ntt = to_ntt_alloc(&db_raw);
            let mut prod = PolyMatrixNTT::zero(&rlwe.spiral, 1, 1);
            multiply(&mut prod, query_ntt, &db_ntt);
            add_into(&mut acc, &prod);
        }

        from_ntt_alloc(&acc)
            .get_poly(0, 0)
            .iter()
            .map(|coeff| coeff % rlwe.q)
            .collect()
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
        let hint_0 = self.generate_hint_from_query_polys(rlwe, query_polys);
        offline_precompute_from_hint(rlwe, &self.params, hint_0)
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
        let first_dim_query = self.deserialize_first_dim_query(rlwe, query)?;
        let deserialize = deserialize_started.elapsed();

        let matrix_started = std::time::Instant::now();
        let intermediate = self.multiply_query(rlwe, &first_dim_query);
        let matrix_vector = matrix_started.elapsed();

        let packing_started = std::time::Instant::now();
        let packed =
            pack_intermediate_blocks(&intermediate, packing_keys, top_key_images, preprocessed)?;
        let packing = packing_started.elapsed();

        let serialization_started = std::time::Instant::now();
        let response =
            serialize_rlwe_response(&packed, self.params.q_prime_1, self.params.q_prime_2);
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

    fn deserialize_first_dim_query(
        &self,
        rlwe: &RlweParams,
        query: &[u8],
    ) -> Result<Vec<u64>, InspiringError> {
        let rows = self.db_rows_padded();
        let first_dim_query = IPIRSimpleQuery::from_packed_bytes(query, rows, rlwe.q)?
            .as_slice()
            .to_vec();

        if first_dim_query.len() != self.db_rows_padded() {
            return Err(InspiringError::LweShape(format!(
                "expected {} first-dimension query values, got {}",
                self.db_rows_padded(),
                first_dim_query.len()
            )));
        }

        Ok(first_dim_query)
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
    /// YPIR's `hint_0`, laid out as `poly_len x db_cols` in row-major order.
    pub hint_0: Vec<u64>,
    /// CRS blocks extracted from `hint_0`; one block per RLWE output.
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

    OfflinePrecomputedValues { hint_0, crs_blocks }
}

/// Build CRS/public preprocessing for uploaded packing-key queries.
pub fn build_pack_preprocessed_blocks<'a>(
    params: &'a RlweParams,
    crs_blocks: &[CrsBlock],
) -> Result<Vec<QueryPackPreprocessed<'a>>, InspiringError> {
    crs_blocks
        .iter()
        .map(|block| {
            let crs = block.to_ntt(params);
            QueryPackPreprocessed::build(params, &crs)
        })
        .collect()
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
    use crate::modulus_switch::{recover_rlwe_rows, switched_rlwe_response_len};

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

    #[test]
    fn perform_offline_precomputation_simplepir_generates_blocks_from_db() {
        let rlwe = tiny_rlwe();
        let ypir = tiny_ypir(8, 16);
        let server = YServer::new(ypir.clone(), 0u16..128, false, true);
        let query = vec![vec![1, 0, 0, 0, 0, 0, 0, 0]];

        let offline = server.perform_offline_precomputation_simplepir(&rlwe, &query);

        assert_eq!(offline.hint_0.len(), rlwe.d * ypir.db_cols);
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

        let offline = offline_precompute_from_hint(&rlwe, &ypir, hint_0.clone());

        assert_eq!(offline.hint_0, hint_0);
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

        assert_eq!(
            response.len(),
            switched_rlwe_response_len(rlwe.d, ypir.q_prime_1, ypir.q_prime_2)
        );

        let (_row_0, row_1) =
            recover_rlwe_rows(&response, rlwe.d, ypir.q_prime_1, ypir.q_prime_2, rlwe.q);
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
