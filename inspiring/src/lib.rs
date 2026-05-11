//! # `inspiring` — InspiRING.Pack ring-packing crate
//!
//! A standalone Rust implementation of **Algorithm 1 ([`InspiRING.Pack`])
//! from the InsPIRe paper** (eprint 2025/1352, Mahdavi–Patel–Seo–Yeo, 2025).
//! The crate exposes a single primitive:
//!
//! ```ignore
//! pub fn pack(lwe_b: LweBatch, pre: &PackPreprocessed) -> RlweCiphertext
//! ```
//!
//! which compresses `d` LWE ciphertexts (each of LWE dimension `d`) into a
//! single RLWE ciphertext of degree `d`, using exactly **two** key-switching
//! matrices `K_g` and `K_h`. See [`SPEC.md`] for the mathematical contract
//! and [`docs/spiral-rs-mapping.md`] for the spiral-rs primitive audit.
//!
//! ## Locked-in scope
//!
//! - Algorithm 1 only. No `PartialPack`, no PIR layers.
//! - Built on Valar's [`spiral-rs`](https://github.com/valargroup/spiral-rs)
//!   fork pinned to `rev = 6f5b66c6a5a639827c6486c59d31c7ec2d4399a8`.
//! - Production posture: offline/online split (CRS model), full unit and
//!   integration tests, statistical noise validation against Theorem 2,
//!   benchmarks reproducing paper Table 5, CI, rustdoc.
//!
//! ## Crate map
//!
//! | Module | Concept (paper §) | Phase |
//! |---|---|---|
//! | [`params`] | `RlweParams`, `GadgetParams`, validators | Phase 4 |
//! | [`lwe`] | `LweCiphertext`, batch type, embedding (Eq. 1) | Phase 4 / 5 |
//! | [`automorph`] | `τ_g`, `τ_h`, `τ_g^j` (§2 + Lemma 1) | Phase 4 / 5 |
//! | [`intermediate`] | `IRCtx`, Stage 1 `transform`, Stage 2 `aggregate` | Phase 5 / 6 |
//! | [`collapse`] | `collapse_one`, `collapse_half`, `collapse` (Stage 3) | Phase 7 |
//! | [`key_switching`] | `KS.Setup`, `KS.Switch`, automorphic images | Phase 7 |
//! | [`preprocess`] | `PackPreprocessed` (CRS-model offline cache) | Phase 8 |
//! | [`mod@pack`] | top-level `pack` (Algorithm 1) | Phase 8 |
//! | [`error`] | `InspiringError` | Phase 4 |
//!
//! [`SPEC.md`]: https://github.com/<TBD>/inspiring/blob/main/SPEC.md
//! [`docs/spiral-rs-mapping.md`]: https://github.com/<TBD>/inspiring/blob/main/docs/spiral-rs-mapping.md
//! [`InspiRING.Pack`]: https://eprint.iacr.org/2025/1352
//!
//! ## Public API invariants
//!
//! These are also asserted by tests (`tests/inspiring_vs_cdks_recursion.rs`):
//!
//! 1. [`PackPreprocessed::build`](preprocess::PackPreprocessed::build) accepts
//!    **exactly two** key-switching matrices, `kg` and `kh`.
//! 2. A single call to [`pack::pack`] invokes `KS.Switch` exactly `d − 1` times.
//! 3. [`pack::pack`] is a deterministic function of `(lwe_b, pre)` —
//!    no fresh randomness is sampled in the online path.
//!
//! ## Toolchain & platform
//!
//! Valar's fork removes the old `#![feature(stdarch_x86_avx512)]` dependency
//! and fixes the scalar `multiply_add_modular` accumulator bug for
//! `crt_count == 1`, so `inspiring` no longer gates correctness on AVX-512.
//! CI still runs on `x86_64-unknown-linux-gnu`; other targets depend on the
//! upstream fork's portability.
//!
//! See [`docs/spiral-rs-mapping.md`] for the full audit of inherited
//! constraints.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod automorph;
pub mod collapse;
pub mod error;
pub mod intermediate;
pub mod key_switching;
pub mod lwe;
pub mod pack;
pub mod params;
pub mod preprocess;

pub use error::InspiringError;
pub use lwe::{LweBatch, LweCiphertext};
pub use pack::{pack, RlweCiphertext};
pub use params::{GadgetParams, RlweParams};
pub use preprocess::{
    PackPreprocessed, PackPublicPreprocessed, PackingKeys, QueryPackPreprocessed, TopKeyImages,
    REFERENCE_V_SEED, REFERENCE_W_SEED,
};
