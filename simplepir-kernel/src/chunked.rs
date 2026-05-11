use crate::{FirstDimKernel, ToU64};
use spiral_rs::arith::barrett_reduction_u128;

/// Default delayed-reduction window for the portable split kernel.
///
/// The value is chosen for the production IPIR-SP shape where query
/// coefficients are below a 56-bit modulus and database elements are 14-bit
/// plaintext values. For wider database scalar types, [`ChunkedSplitKernel`]
/// automatically clamps the effective window to a type-safe value.
pub const DEFAULT_CHUNK_ROWS: usize = 1 << 16;

/// Portable YPIR-style first-dimension kernel.
///
/// This kernel follows YPIR's first-pass loop structure: split each `u64` query
/// coefficient into low/high 32-bit limbs, sweep row chunks before columns,
/// accumulate products in `u64` over a bounded row window, and perform one
/// Barrett reduction per window instead of per database element.
///
/// The implementation is safe Rust and does not use rayon or architecture
/// intrinsics. For `u8`, `u16`, and `u32` databases it uses the chunked
/// split-accumulation path. For element types whose maximum value would make
/// one limb product overflow `u64` (currently `u64`), it conservatively falls
/// back to the scalar reference algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkedSplitKernel {
    /// Rows per delayed-reduction window.
    ///
    /// This is a requested maximum, not a guarantee. The kernel clamps it to the
    /// number of rows and to the largest value that cannot overflow the
    /// low/high `u64` limb accumulators for `T::MAX_VALUE`.
    pub chunk_rows: usize,
}

impl Default for ChunkedSplitKernel {
    fn default() -> Self {
        Self {
            chunk_rows: DEFAULT_CHUNK_ROWS,
        }
    }
}

impl ChunkedSplitKernel {
    /// Build a kernel with an explicit delayed-reduction window.
    ///
    /// `chunk_rows == 0` is accepted and behaves like `1`; oversized windows are
    /// clamped at execution time based on the input shape and database scalar
    /// type. Use [`Default::default`] for the production-oriented
    /// [`DEFAULT_CHUNK_ROWS`] setting.
    #[must_use]
    pub const fn new(chunk_rows: usize) -> Self {
        Self { chunk_rows }
    }
}

impl<T> FirstDimKernel<T> for ChunkedSplitKernel
where
    T: Copy + ToU64,
{
    fn multiply_query(
        &self,
        rlwe: &inspiring::RlweParams,
        db: &[T],
        rows_padded: usize,
        cols: usize,
        query: &[u64],
        out: &mut [u64],
    ) {
        assert_eq!(query.len(), rows_padded, "query length must match rows");
        assert_eq!(db.len(), rows_padded * cols, "database shape mismatch");
        assert_eq!(out.len(), cols, "output length must match cols");

        if needs_wide_products::<T>() {
            scalar_fallback(rlwe, db, rows_padded, cols, query, out);
            return;
        }

        let chunk_rows = self
            .chunk_rows
            .min(max_safe_chunk_rows::<T>())
            .min(rows_padded)
            .max(1);

        out.fill(0);

        let mut row_start = 0;
        while row_start < rows_padded {
            let row_end = (row_start + chunk_rows).min(rows_padded);

            for (col, out_col) in out.iter_mut().enumerate().take(cols) {
                let col_offset = col * rows_padded;
                let mut total_lo = 0u64;
                let mut total_hi = 0u64;

                for row in row_start..row_end {
                    let query_val = query[row];
                    let db_val = db[col_offset + row].to_u64();
                    total_lo += ((query_val as u32) as u64) * db_val;
                    total_hi += (query_val >> 32) * db_val;
                }

                let chunk_sum = (total_lo as u128) + ((total_hi as u128) << 32);
                let chunk_reduced = barrett_reduction_u128(&rlwe.spiral, chunk_sum);
                *out_col = add_mod(*out_col, chunk_reduced, rlwe.q);
            }

            row_start = row_end;
        }
    }
}

fn add_mod(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    debug_assert!(lhs < modulus);
    debug_assert!(rhs < modulus);

    let sum = u128::from(lhs) + u128::from(rhs);
    let modulus = u128::from(modulus);
    if sum >= modulus {
        (sum - modulus) as u64
    } else {
        sum as u64
    }
}

fn needs_wide_products<T>() -> bool
where
    T: ToU64,
{
    u128::from(u32::MAX) * u128::from(T::MAX_VALUE) > u128::from(u64::MAX)
}

fn max_safe_chunk_rows<T>() -> usize
where
    T: ToU64,
{
    if T::MAX_VALUE == 0 {
        return usize::MAX;
    }

    let max_term = u128::from(u32::MAX) * u128::from(T::MAX_VALUE);
    if max_term > u128::from(u64::MAX) {
        1
    } else {
        (u128::from(u64::MAX) / max_term) as usize
    }
}

fn scalar_fallback<T>(
    rlwe: &inspiring::RlweParams,
    db: &[T],
    rows_padded: usize,
    cols: usize,
    query: &[u64],
    out: &mut [u64],
) where
    T: Copy + ToU64,
{
    let modulus = rlwe.q as u128;
    for (col, out_col) in out.iter_mut().enumerate().take(cols) {
        let col_offset = col * rows_padded;
        let mut acc = 0u128;
        for (row, query_val) in query.iter().enumerate() {
            acc += (*query_val as u128) * (db[col_offset + row].to_u64() as u128);
            acc %= modulus;
        }
        *out_col = acc as u64;
    }
}

#[cfg(test)]
mod tests {
    use inspiring::{GadgetParams, RlweParams};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::{FirstDimKernel, ScalarKernel, ToU64};

    use super::ChunkedSplitKernel;

    const PRODUCTION_Q: u64 = 72_057_594_037_641_217;

    fn production_like_rlwe() -> RlweParams {
        RlweParams::new(
            2048,
            PRODUCTION_Q,
            1 << 14,
            6.4,
            GadgetParams {
                bits_per: 19,
                ell: 3,
            },
        )
        .expect("valid production-like params")
    }

    fn compare<T, F>(rows: usize, cols: usize, chunk_rows: usize, mut sample_db: F)
    where
        T: Copy + Default + PartialEq + std::fmt::Debug + ToU64,
        F: FnMut(&mut ChaCha20Rng) -> T,
    {
        let rlwe = production_like_rlwe();
        let mut rng = ChaCha20Rng::seed_from_u64(0x5950_4952_5350);
        let db: Vec<_> = (0..rows * cols).map(|_| sample_db(&mut rng)).collect();
        let query: Vec<_> = (0..rows).map(|_| rng.gen_range(0..rlwe.q)).collect();
        let mut scalar = vec![0u64; cols];
        let mut chunked = vec![0u64; cols];

        ScalarKernel.multiply_query(&rlwe, &db, rows, cols, &query, &mut scalar);
        ChunkedSplitKernel::new(chunk_rows).multiply_query(
            &rlwe,
            &db,
            rows,
            cols,
            &query,
            &mut chunked,
        );

        assert_eq!(chunked, scalar);
    }

    #[test]
    fn chunked_split_matches_scalar_on_random_u16_inputs() {
        for (rows, cols) in [(1, 1), (7, 3), (31, 5), (65, 4), (129, 2)] {
            compare::<u16, _>(rows, cols, 16, |rng| rng.gen_range(0..(1 << 14)));
        }
    }

    #[test]
    fn chunked_split_handles_chunk_boundaries() {
        for rows in [15, 16, 17, 31, 32, 33] {
            compare::<u16, _>(rows, 3, 16, |rng| rng.gen_range(0..(1 << 14)));
        }
    }

    #[test]
    fn chunked_split_matches_scalar_for_u8_u16_u32() {
        compare::<u8, _>(41, 4, 16, |rng| rng.gen());
        compare::<u16, _>(41, 4, 16, |rng| rng.gen());
        compare::<u32, _>(41, 4, 16, |rng| rng.gen());
    }

    #[test]
    fn chunked_split_overwrites_reused_output_buffers() {
        let rlwe = production_like_rlwe();
        let rows = 33;
        let cols = 5;
        let mut rng = ChaCha20Rng::seed_from_u64(0x4f55_5450_5554);
        let db: Vec<u16> = (0..rows * cols)
            .map(|_| rng.gen_range(0..(1 << 14)))
            .collect();
        let query: Vec<_> = (0..rows).map(|_| rng.gen_range(0..rlwe.q)).collect();
        let mut scalar = vec![0u64; cols];
        let mut chunked = vec![rlwe.q - 1; cols];

        ScalarKernel.multiply_query(&rlwe, &db, rows, cols, &query, &mut scalar);
        ChunkedSplitKernel::new(16).multiply_query(&rlwe, &db, rows, cols, &query, &mut chunked);

        assert_eq!(chunked, scalar);
    }

    #[test]
    fn chunked_split_falls_back_for_wide_u64_database_values() {
        compare::<u64, _>(19, 2, 16, |rng| rng.gen());
    }
}
