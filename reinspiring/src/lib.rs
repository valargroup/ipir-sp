//! # `reinspiring` — ReinspiRING packing crate
//!
//! Coefficient-domain compilation of InspiRING's online packing sum
//! ([eprint 2026/1934](https://eprint.iacr.org/2026/1934), Algorithm 2).
//!
//! For odd NTT-friendly moduli, [`pack`] is an exact rewrite of
//! [`inspiring::QueryPackPreprocessed::pack_b`].
//!
//! See [`SPEC.md`](../SPEC.md) for the paper-to-code contract.

#![deny(missing_docs)]
#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod compile;
pub mod error;
pub mod lift_ntt;
pub mod matrix;
pub mod modswitch;
pub mod pack;
pub mod params;
pub mod preprocess;

pub use error::ReinspiringError;
pub use pack::pack;
pub use params::{GadgetParams, ReinspiringParams};
pub use preprocess::{preprocess_from_inspiring, CompileAlgo, ReinspiringPreprocessed};
