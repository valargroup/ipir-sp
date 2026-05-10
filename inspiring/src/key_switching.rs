//! Key-switching primitives `KS.Setup` and `KS.Switch`, plus helpers to
//! compute automorphic images `τ_g^{k-1}(K_g)` of a base matrix locally
//! (without extra key material). See SPEC.md §6 (Stage 3) and §9.b
//! (the structural reason InspiRING needs only two base KS matrices vs.
//! CDKS's `lg d`).
//!
//! The implementation patterns `KS.Switch` on the inline KS body of
//! `spiral_rs::server::coefficient_expansion` (lines 80–103 of
//! `spiral-rs/src/server.rs` at the pinned revision); we cannot call
//! `coefficient_expansion` directly because it is fused with
//! Spiral-PIR's expansion loop. See `docs/spiral-rs-mapping.md` §3.

use rand_chacha::ChaCha20Rng;
use spiral_rs::discrete_gaussian::DiscreteGaussian;
use spiral_rs::gadget::{build_gadget, gadget_invert_alloc};
use spiral_rs::params::Params as SpiralParams;
use spiral_rs::poly::{
    add_into, from_ntt_alloc, multiply, scalar_multiply_alloc, stack_ntt, to_ntt_alloc, PolyMatrix,
    PolyMatrixNTT, PolyMatrixRaw,
};

use crate::automorph::tau_ntt;
use crate::params::RlweParams;

/// A single key-switching matrix `K`. Internally a `[2, ℓ]` `PolyMatrixNTT`
/// (the row-2-by-cols-ℓ shape used by spiral-rs's gadget machinery).
///
/// `K = KS.Setup(s', s)` lets one transform a ciphertext under `s'`
/// (one of `τ_g(s̃)`, `τ_h(s̃)`, …) into one under `s = s̃`. SPEC.md §6.
///
/// Note: `Debug` / `Clone` are not derived because [`PolyMatrixNTT`] does
/// not implement them upstream; Phase 7 adds hand-written impls if needed.
pub struct KeySwitchingMatrix<'a> {
    /// The encrypted gadget-scaled secret. Shape `[2, ℓ]`.
    pub mat: PolyMatrixNTT<'a>,
}

/// `KS.Setup(s_from, s_to)` — encrypt the gadget-scaled `s_from` under
/// `s_to` to produce a key-switching matrix, per SPEC.md §6 / paper §2.
///
pub fn ks_setup<'a>(
    _params: &'a RlweParams,
    spiral: &'a SpiralParams,
    s_from_ntt: &PolyMatrixNTT<'a>,
    s_to_ntt: &PolyMatrixNTT<'a>,
    rng: &mut ChaCha20Rng,
) -> KeySwitchingMatrix<'a> {
    assert_eq!(s_from_ntt.rows, 1);
    assert_eq!(s_from_ntt.cols, 1);
    assert_eq!(s_to_ntt.rows, 1);
    assert_eq!(s_to_ntt.cols, 1);

    let gadget = build_gadget(spiral, 1, _params.gadget.ell);
    let scaled = scalar_multiply_alloc(s_from_ntt, &to_ntt_alloc(&gadget));

    let dg = DiscreteGaussian::init(_params.sigma_chi * std::f64::consts::TAU.sqrt());
    let a = PolyMatrixRaw::random_rng(spiral, 1, _params.gadget.ell, rng);
    let e = PolyMatrixRaw::noise(spiral, 1, _params.gadget.ell, &dg, rng);
    let a_ntt = to_ntt_alloc(&a);
    let w = (-&a).ntt();
    let mut y = PolyMatrixNTT::zero(spiral, 1, _params.gadget.ell);
    multiply(&mut y, s_to_ntt, &a_ntt);
    add_into(&mut y, &to_ntt_alloc(&e));
    add_into(&mut y, &scaled);

    KeySwitchingMatrix {
        mat: stack_ntt(&w, &y),
    }
}

/// `KS.Switch(K, c)` — apply a key-switching matrix to an RLWE
/// ciphertext `c = (c1, c2)`. Returns a new ciphertext under `s_to`.
///
/// The body mirrors the inline KS pattern in `spiral-rs/src/server.rs`
/// lines 80–103: gadget-invert `c1` (raw), NTT-forward, multiply by
/// `K.mat`, add `(0, c2)`. See SPEC.md §6.
///
/// **Test-only instrumentation**: in `cfg(test)` builds a thread-local
/// counter is incremented on every call. `tests/inspiring_vs_cdks_recursion.rs`
/// asserts the counter equals exactly `d − 1` per call to
/// [`crate::pack::pack`]. Tampering with this is a production-blocker.
///
pub fn ks_switch<'a>(
    k: &KeySwitchingMatrix<'_>,
    c1: &PolyMatrixNTT<'a>,
    c2: &PolyMatrixNTT<'a>,
) -> (PolyMatrixNTT<'a>, PolyMatrixNTT<'a>) {
    ks_call_count::inc();

    assert_eq!(k.mat.rows, 2);
    assert_eq!(k.mat.cols, c1.params.t_exp_left);
    assert_eq!(c1.rows, 1);
    assert_eq!(c1.cols, 1);
    assert_eq!(c2.rows, 1);
    assert_eq!(c2.cols, 1);

    let digits_raw = gadget_invert_alloc(k.mat.cols, &from_ntt_alloc(c1));
    let digits_ntt = to_ntt_alloc(&digits_raw);
    let mut switched = PolyMatrixNTT::zero(c1.params, 2, 1);
    multiply(&mut switched, &k.mat, &digits_ntt);

    let delta_a = switched.submatrix(0, 0, 1, 1);
    let mut delta_b = switched.submatrix(1, 0, 1, 1);
    add_into(&mut delta_b, c2);
    (delta_a, delta_b)
}

/// Compute `τ_g^{k-1}(K_g)` from `K_g` without any extra key material.
/// The image is just `K_g` with `τ_g^{k-1}` applied component-wise to
/// each polynomial of the matrix. SPEC.md §6 / Appendix C.
///
#[must_use]
pub fn automorphic_image<'a>(k: &KeySwitchingMatrix<'a>, t: u64) -> KeySwitchingMatrix<'a> {
    KeySwitchingMatrix {
        mat: tau_ntt(&k.mat, t),
    }
}

/// Test/diagnostic thread-local counter for `KS.Switch` calls. Used by
/// `tests/inspiring_vs_cdks_recursion.rs` to assert the linear-cascade
/// `KS.Switch` count of exactly `d − 1` per pack — the runtime structural
/// guard against accidental CDKS-style implementation drift (SPEC.md §9.h).
#[doc(hidden)]
pub mod ks_call_count {
    use std::cell::Cell;

    thread_local! {
        static COUNTER: Cell<u64> = const { Cell::new(0) };
    }

    /// Reset to 0. Call before a measured `pack`.
    pub fn reset() {
        COUNTER.with(|c| c.set(0));
    }

    /// Increment by one. Called from inside `ks_switch`.
    pub fn inc() {
        COUNTER.with(|c| c.set(c.get() + 1));
    }

    /// Read the current count.
    #[must_use]
    pub fn get() -> u64 {
        COUNTER.with(Cell::get)
    }
}
