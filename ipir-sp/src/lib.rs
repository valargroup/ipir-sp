//! IPIR-SP integration layer over `inspiring` (default) and optional `reinspiring`.
//!
//! This crate keeps YPIR's u32/SimplePIR-facing surface separate from the packing
//! crates, and uses [`inspiring::QueryPackPreprocessed::pack_b`] as the default
//! LWE-to-RLWE packing primitive. Select [`crate::PackBackend::Reinspiring`] for
//! the coefficient-domain Algorithm 2 path (ePrint 2026/1934).
//! CI covers this crate through the workspace-level Rust workflow.

#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod bits;
pub mod client;
pub mod modulus_switch;
#[cfg(feature = "native-reinspiring")]
pub mod native;
pub mod pack_backend;
pub mod params;
pub mod sampling;
pub mod serialize;
pub mod server;

pub use client::{IPIRClient, IPIRSeed, IPIRSimpleQuery, PublicQuerySetup};
pub use pack_backend::{
    build_reinspiring_blocks, pack_intermediate_blocks_reinspiring,
    pack_intermediate_blocks_with_backend, PackBackend,
};
pub use params::{
    params_for_simplepir, params_for_simplepir_profile, ProductionSimplePirParams,
    SimplePirProfile, YpirSchemeParams,
};
pub use server::IPIRServer;
/// Plaintext database element trait used by `IPIRServer` first-dimension kernels.
pub use simplepir_kernel::ToU64;
