use crate::{FirstDimKernel, ToU64};

/// Straightforward reference implementation of [`FirstDimKernel`].
///
/// `ScalarKernel` performs one `u128` multiply-add and one `% rlwe.q` reduction
/// for every `(row, col)` pair. It is intentionally simple and slow; use it as
/// a correctness oracle in tests, benchmarks, and when validating optimized
/// backends. Production servers should normally use [`crate::ChunkedSplitKernel`]
/// or another optimized implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScalarKernel;

impl<T> FirstDimKernel<T> for ScalarKernel
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

        let modulus = rlwe.q as u128;
        for (col, out_col) in out.iter_mut().enumerate().take(cols) {
            let mut acc = 0u128;
            let col_offset = col * rows_padded;
            for (row, query_val) in query.iter().enumerate() {
                let db_val = db[col_offset + row].to_u64();
                acc += (*query_val as u128) * (db_val as u128);
                acc %= modulus;
            }
            *out_col = acc as u64;
        }
    }
}
