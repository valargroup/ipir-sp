use crate::FirstDimKernel;
use spiral_rs::arith::barrett_reduction_u128;

/// AVX512 first-dimension kernel specialized for `u16` database columns.
///
/// This mirrors YPIR's explicit first-pass shape for the production nullifier
/// database: process eight rows per vector, split each `u64` query coefficient
/// into 32-bit limbs, multiply by widened `u16` plaintexts, and reduce once per
/// row chunk. Call [`Self::is_supported`] before using it on arbitrary hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U16Avx512Kernel {
    /// Rows per delayed-reduction window. Rounded down to a multiple of eight
    /// for the vector body; any tail rows are handled scalarly.
    pub chunk_rows: usize,
}

impl Default for U16Avx512Kernel {
    fn default() -> Self {
        Self {
            chunk_rows: crate::chunked::DEFAULT_CHUNK_ROWS,
        }
    }
}

impl U16Avx512Kernel {
    #[must_use]
    pub const fn new(chunk_rows: usize) -> Self {
        Self { chunk_rows }
    }

    /// Return whether this process can execute the AVX512 implementation.
    #[must_use]
    pub fn is_supported() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            std::is_x86_feature_detected!("avx512f")
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }
}

impl FirstDimKernel<u16> for U16Avx512Kernel {
    fn multiply_query(
        &self,
        rlwe: &inspiring::RlweParams,
        db: &[u16],
        rows_padded: usize,
        cols: usize,
        query: &[u64],
        out: &mut [u64],
    ) {
        assert_eq!(query.len(), rows_padded, "query length must match rows");
        assert_eq!(db.len(), rows_padded * cols, "database shape mismatch");
        assert_eq!(out.len(), cols, "output length must match cols");
        assert!(
            Self::is_supported(),
            "U16Avx512Kernel requires AVX512F CPU support"
        );

        let chunk_rows = self.chunk_rows.min(rows_padded).max(8);

        // SAFETY: CPU support is checked above, and all slices/shapes have been
        // validated. The implementation uses unaligned vector loads/stores.
        unsafe {
            multiply_query_avx512_u16(rlwe, db, rows_padded, cols, query, out, chunk_rows);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn multiply_query_avx512_u16(
    rlwe: &inspiring::RlweParams,
    db: &[u16],
    rows_padded: usize,
    cols: usize,
    query: &[u64],
    out: &mut [u64],
    chunk_rows: usize,
) {
    use std::arch::x86_64::{
        __m512i, _mm512_add_epi64, _mm512_cvtepu16_epi64, _mm512_loadu_si512, _mm512_mul_epu32,
        _mm512_setzero_si512, _mm512_srli_epi64, _mm512_storeu_si512, _mm_loadu_si128,
    };

    out.fill(0);

    let vector_rows = 8;
    let chunk_rows = chunk_rows.max(vector_rows);
    let chunk_rows = chunk_rows - (chunk_rows % vector_rows);
    let chunk_rows = chunk_rows.max(vector_rows);

    let mut row_start = 0;
    while row_start < rows_padded {
        let row_end = (row_start + chunk_rows).min(rows_padded);
        let vector_end = row_start + ((row_end - row_start) / vector_rows) * vector_rows;

        for (col, out_col) in out.iter_mut().enumerate().take(cols) {
            let col_offset = col * rows_padded;
            let mut total_lo = _mm512_setzero_si512();
            let mut total_hi = _mm512_setzero_si512();

            let mut row = row_start;
            while row < vector_end {
                let query_vec =
                    unsafe { _mm512_loadu_si512(query.as_ptr().add(row).cast::<__m512i>()) };
                let db_chunk = unsafe { _mm_loadu_si128(db.as_ptr().add(col_offset + row).cast()) };
                let db_vec = _mm512_cvtepu16_epi64(db_chunk);

                total_lo = _mm512_add_epi64(total_lo, _mm512_mul_epu32(query_vec, db_vec));
                total_hi = _mm512_add_epi64(
                    total_hi,
                    _mm512_mul_epu32(_mm512_srli_epi64(query_vec, 32), db_vec),
                );

                row += vector_rows;
            }

            let mut values_lo = [0u64; 8];
            let mut values_hi = [0u64; 8];
            unsafe {
                _mm512_storeu_si512(values_lo.as_mut_ptr().cast::<__m512i>(), total_lo);
                _mm512_storeu_si512(values_hi.as_mut_ptr().cast::<__m512i>(), total_hi);
            }

            let mut res_lo = values_lo.iter().copied().sum::<u64>();
            let mut res_hi = values_hi.iter().copied().sum::<u64>();

            for row in vector_end..row_end {
                let query_val = query[row];
                let db_val = u64::from(db[col_offset + row]);
                res_lo += u64::from(query_val as u32) * db_val;
                res_hi += (query_val >> 32) * db_val;
            }

            let chunk_sum = u128::from(res_lo) + (u128::from(res_hi) << 32);
            let chunk_reduced = barrett_reduction_u128(&rlwe.spiral, chunk_sum);
            *out_col = add_mod(*out_col, chunk_reduced, rlwe.q);
        }

        row_start = row_end;
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn multiply_query_avx512_u16(
    _rlwe: &inspiring::RlweParams,
    _db: &[u16],
    _rows_padded: usize,
    _cols: usize,
    _query: &[u64],
    _out: &mut [u64],
    _chunk_rows: usize,
) {
    unreachable!("U16Avx512Kernel is only available on x86_64");
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

#[cfg(test)]
mod tests {
    use super::U16Avx512Kernel;
    use crate::{ChunkedSplitKernel, FirstDimKernel};
    use inspiring::{GadgetParams, RlweParams};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

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

    #[test]
    fn avx512_u16_matches_chunked_when_supported() {
        if !U16Avx512Kernel::is_supported() {
            return;
        }

        let rlwe = production_like_rlwe();
        let rows = 129;
        let cols = 5;
        let mut rng = ChaCha20Rng::seed_from_u64(0x4156_5835_3132);
        let db: Vec<u16> = (0..rows * cols)
            .map(|_| rng.gen_range(0..(1 << 14)))
            .collect();
        let query: Vec<_> = (0..rows).map(|_| rng.gen_range(0..rlwe.q)).collect();
        let mut chunked = vec![0u64; cols];
        let mut avx512 = vec![rlwe.q - 1; cols];

        ChunkedSplitKernel::new(16).multiply_query(&rlwe, &db, rows, cols, &query, &mut chunked);
        U16Avx512Kernel::new(16).multiply_query(&rlwe, &db, rows, cols, &query, &mut avx512);

        assert_eq!(avx512, chunked);
    }
}
