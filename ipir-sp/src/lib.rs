//! IPIR-SP integration layer over `inspiring`.
//!
//! This crate keeps YPIR's u32/SimplePIR-facing surface separate from
//! `inspiring`, and uses `inspiring::pack` as the only LWE-to-RLWE packing
//! primitive.

#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod bits;
pub mod client;
pub mod modulus_switch;
pub mod params;
pub mod serialize;
pub mod server;

pub use client::{IPIRClient, IPIRSeed, IPIRSimpleQuery, IPIRSimpleQuerySetup};
pub use params::{params_for_simplepir, YpirSchemeParams};
pub use server::IPIRServer;
/// Plaintext database element trait used by `IPIRServer` first-dimension kernels.
pub use simplepir_kernel::ToU64;
