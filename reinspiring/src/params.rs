//! ReinspiRING parameters and lift-modulus helpers.
//!
//! See SPEC.md §2 and §7.

use crate::error::ReinspiringError;

/// Gadget `(z, ℓ)` mirrored from inspiring for limb stacking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GadgetParams {
    /// `bits_per = log₂(z)`.
    pub bits_per: u32,
    /// Number of gadget limbs `ℓ`.
    pub ell: usize,
}

impl GadgetParams {
    /// `z = 2^bits_per`.
    #[must_use]
    pub const fn z(self) -> u64 {
        1u64 << self.bits_per
    }
}

/// Public parameters for ReinspiRING.
///
/// Unlike [`inspiring::RlweParams`], `q` **may be even** (power-of-two native
/// moduli). The odd-`q` byte-equal path still uses inspiring's NTT substrate
/// for `ã` / leftover convenience; even-`q` owns coefficient arithmetic and
/// only uses spiral-rs at the auxiliary lift modulus `Q`.
#[derive(Debug, Clone)]
pub struct ReinspiringParams {
    /// Ring degree `d` (power of two).
    pub d: usize,
    /// Ciphertext modulus `q` (odd or `2^k`).
    pub q: u64,
    /// Plaintext modulus.
    pub p: u64,
    /// Gadget parameters.
    pub gadget: GadgetParams,
    /// Cached `⌊q / p⌋`.
    pub delta: u64,
    /// Auxiliary NTT modulus for leftover `t''·y'` (SPEC.md §7).
    ///
    /// Must satisfy `Q > d · q²` when used for exact recovery. For the odd-`q`
    /// equivalence path we may multiply directly mod `q` instead.
    pub lift_q: u64,
}

impl ReinspiringParams {
    /// Construct and validate parameters.
    pub fn new(
        d: usize,
        q: u64,
        p: u64,
        gadget: GadgetParams,
        lift_q: u64,
    ) -> Result<Self, ReinspiringError> {
        if d < 2 || !d.is_power_of_two() {
            return Err(ReinspiringError::InvalidParams(format!(
                "d must be a power of two ≥ 2, got {d}"
            )));
        }
        if q < 2 {
            return Err(ReinspiringError::InvalidParams(format!(
                "q must be ≥ 2, got {q}"
            )));
        }
        if p < 2 || p > q {
            return Err(ReinspiringError::InvalidParams(format!(
                "p must satisfy 2 ≤ p ≤ q, got p={p}, q={q}"
            )));
        }
        if gadget.bits_per == 0 || gadget.bits_per >= 63 {
            return Err(ReinspiringError::InvalidParams(format!(
                "gadget.bits_per out of range: {}",
                gadget.bits_per
            )));
        }
        if gadget.ell == 0 {
            return Err(ReinspiringError::InvalidParams(
                "gadget.ell must be non-zero".into(),
            ));
        }
        let z = gadget.z();
        // Odd-q byte-equal path: require full gadget coverage (`z^ℓ ≥ q`).
        // Power-of-two / paper eval path: approximate gadget is intentional
        // (ReinsPIRe §E.1; eval set `q=2^54`, `ℓ=2`, `z=2^19` has `z^ℓ ≪ q`).
        if self_is_odd_q(q) && z.saturating_pow(gadget.ell as u32) < q {
            return Err(ReinspiringError::InvalidParams(format!(
                "gadget z^ell = {z}^{} < q = {q}",
                gadget.ell
            )));
        }
        if lift_q < 3 || lift_q % 2 == 0 {
            return Err(ReinspiringError::InvalidParams(format!(
                "lift_q must be an odd NTT-friendly modulus, got {lift_q}"
            )));
        }
        Ok(Self {
            d,
            q,
            p,
            gadget,
            delta: q / p,
            lift_q,
        })
    }

    /// Whether `q` is odd (byte-equal inspiring path is available).
    #[must_use]
    pub const fn is_odd_q(&self) -> bool {
        self.q % 2 == 1
    }

    /// Mirror an [`inspiring::RlweParams`] set (odd `q` only).
    pub fn from_inspiring(
        params: &inspiring::RlweParams,
        lift_q: u64,
    ) -> Result<Self, ReinspiringError> {
        Self::new(
            params.d,
            params.q,
            params.p,
            GadgetParams {
                bits_per: params.gadget.bits_per,
                ell: params.gadget.ell,
            },
            lift_q,
        )
    }
}

fn self_is_odd_q(q: u64) -> bool {
    q % 2 == 1
}
