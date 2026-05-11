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
