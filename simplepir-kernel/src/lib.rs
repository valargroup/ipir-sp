//! Backend-agnostic first-dimension SimplePIR kernels.
//!
//! A first-dimension kernel computes the online SimplePIR matrix-vector product
//! over a transposed, column-major database:
//!
//! `out[col] = sum_row query[row] * db[col * rows_padded + row] mod q`.
//!
//! The crate exposes a small object-safe [`FirstDimKernel`] trait so callers can
//! swap between CPU and future accelerator backends without changing the
//! surrounding PIR server code. The default portable backend,
//! [`ChunkedSplitKernel`], follows YPIR's online first-pass shape: split 64-bit
//! query coefficients into low/high 32-bit limbs, accumulate over bounded row
//! chunks, and reduce only at chunk boundaries. [`ScalarKernel`] is retained as
//! the simple reference implementation for tests and comparisons.

#![deny(rust_2018_idioms)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod avx512;
pub mod backend;
pub mod chunked;
pub mod scalar;

pub use avx512::U16Avx512Kernel;
pub use backend::{FirstDimKernel, ToU64};
pub use chunked::ChunkedSplitKernel;
pub use scalar::ScalarKernel;

/// Choose how many columns each parallel task owns.
///
/// The kernels are DRAM-bandwidth bound, so the goal is one contiguous stripe
/// of at least [`chunked::MIN_BAND_BYTES`] per task while still producing at
/// least one band per thread. Returns a value in `1..=cols`, so callers can pass
/// it straight to `par_chunks_mut` without further clamping.
#[must_use]
pub fn band_cols<T>(rows_padded: usize, cols: usize) -> usize {
    if cols == 0 || rows_padded == 0 {
        return 1;
    }

    let col_bytes = rows_padded.saturating_mul(std::mem::size_of::<T>()).max(1);
    let by_size = chunked::MIN_BAND_BYTES.div_ceil(col_bytes).max(1);
    let by_threads = cols.div_ceil(rayon::current_num_threads().max(1)).max(1);

    by_size.min(by_threads).clamp(1, cols)
}
