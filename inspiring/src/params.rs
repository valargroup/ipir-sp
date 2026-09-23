//! Parameter sets for `inspiring`.
//!
//! See [SPEC.md §1](../../SPEC.md) for the symbol table this module mirrors.
//! Every public field is paper-named, every constraint is paper-justified.
//!
//! Stage 1 status: validators, cached arithmetic constants, and backing
//! [`spiral_rs::params::Params`] construction are implemented.

use spiral_rs::gadget::get_bits_per;
use spiral_rs::params::{Params as SpiralParams, MIN_Q2_BITS};

use crate::error::InspiringError;

/// Gadget-decomposition parameters `(z, ℓ)` used by `KS.Setup` /
/// `KS.Switch`.
///
/// Per SPEC.md §1:
///
/// > `g_z = [1, z, z², …, z^{ℓ-1}]^⊤ ∈ Z_q^ℓ`,
/// > `ℓ = ⌈log q / log z⌉`,
/// > `g_z^{-1}: Z_q → Z^{1×ℓ}` returns digit decomposition.
///
/// This implementation balances the lower `ℓ-1` digits and leaves the full
/// quotient in the top digit (at most `z`) so reconstruction is exact modulo
/// `q`, including a carry out of the nominal balanced width.
///
/// We require `z = 2^bits_per` (a power of two) so that the underlying
/// `spiral-rs` gadget — whose digit width is fixed at *bit-decomposition*
/// granularity — agrees with InspiRING's specification. See
/// [`docs/spiral-rs-mapping.md` §2](../../docs/spiral-rs-mapping.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GadgetParams {
    /// `bits_per = log₂(z)`. Must equal what
    /// [`spiral_rs::gadget::get_bits_per`] would return for `(modulus, ℓ)`.
    pub bits_per: u32,
    /// Number of digits `ℓ`. Must satisfy `z^ℓ ≥ q`; the top digit may be `z`.
    pub ell: usize,
}

impl GadgetParams {
    /// `z = 2^bits_per`.
    #[must_use]
    pub const fn z(self) -> u64 {
        1u64 << self.bits_per
    }
}

/// Public parameters for the `inspiring` ring-packing scheme.
///
/// Naming follows SPEC.md §1 exactly. Where this differs from
/// [`spiral_rs::params::Params`] (which is tailored to Spiral-PIR), the
/// helper [`RlweParams::to_spiral_params`] (added in Phase 5) does the
/// translation.
#[derive(Debug, Clone)]
pub struct RlweParams {
    /// Ring degree `d`. Power of two. Both the LWE dim and the RLWE degree.
    pub d: usize,
    /// Modulus `q`. Must be **odd** (so that `d^{-1} mod q` exists; see
    /// SPEC.md §1 and Lemma 1 in §3).
    pub q: u64,
    /// Plaintext modulus `p`. Messages live in `Z_p`.
    pub p: u64,
    /// Subgaussian parameter `σ_χ` of the noise distribution.
    pub sigma_chi: f64,
    /// Gadget-decomposition `(z, ℓ)`.
    pub gadget: GadgetParams,
    /// Cached `Δ = ⌊q / p⌋`.
    pub delta: u64,
    /// Cached `d^{-1} mod q`.
    pub d_inv: u64,
    /// Backing `spiral-rs` parameters used by polynomial allocators.
    pub spiral: SpiralParams,
}

impl RlweParams {
    /// Construct an [`RlweParams`] and validate the constraints from
    /// [SPEC.md §1](../../SPEC.md):
    ///
    /// - `d` is a power of two.
    /// - `q` is odd (required for `d^{-1} mod q`).
    /// - `p ≥ 2` and `p ≤ q`.
    /// - `gadget.z()^ell ≥ q` (gadget covers the modulus).
    /// - `gadget.bits_per` matches what `spiral_rs::gadget::get_bits_per`
    ///   would return — see `docs/spiral-rs-mapping.md` §2.
    ///
    pub fn new(
        d: usize,
        q: u64,
        p: u64,
        sigma_chi: f64,
        gadget: GadgetParams,
    ) -> Result<Self, InspiringError> {
        if d < 2 || !d.is_power_of_two() {
            return Err(InspiringError::InvalidParams(format!(
                "d must be a power of two greater than 1, got {d}"
            )));
        }
        if q < 3 || q % 2 == 0 {
            return Err(InspiringError::InvalidParams(format!(
                "q must be odd and at least 3, got {q}"
            )));
        }
        if p < 2 || p > q {
            return Err(InspiringError::InvalidParams(format!(
                "p must satisfy 2 <= p <= q, got p={p}, q={q}"
            )));
        }
        if !sigma_chi.is_finite() || sigma_chi <= 0.0 {
            return Err(InspiringError::InvalidParams(format!(
                "sigma_chi must be positive and finite, got {sigma_chi}"
            )));
        }
        if gadget.bits_per == 0 || gadget.bits_per >= u64::BITS {
            return Err(InspiringError::InvalidParams(format!(
                "gadget.bits_per must be in [1, 63], got {}",
                gadget.bits_per
            )));
        }
        if gadget.ell == 0 {
            return Err(InspiringError::InvalidParams(
                "gadget.ell must be non-zero".to_string(),
            ));
        }

        let coverage = (1u128 << gadget.bits_per).saturating_pow(gadget.ell as u32);
        if coverage < u128::from(q) {
            return Err(InspiringError::InvalidParams(format!(
                "gadget base z={} with ell={} does not cover q={q}",
                gadget.z(),
                gadget.ell
            )));
        }

        let d_inv = mod_inverse(d as u64, q).ok_or_else(|| {
            InspiringError::InvalidParams(format!("d={d} is not invertible modulo q={q}"))
        })?;
        let delta = q / p;
        let noise_width = sigma_chi * std::f64::consts::TAU.sqrt();
        let spiral = SpiralParams::init(
            d,
            &[q],
            noise_width,
            1,
            p,
            MIN_Q2_BITS,
            gadget.ell,
            gadget.ell,
            gadget.ell,
            gadget.ell,
            false,
            0,
            0,
            1,
            d,
            0,
        );
        let spiral_bits_per = get_bits_per(&spiral, gadget.ell) as u32;
        if spiral_bits_per != gadget.bits_per {
            return Err(InspiringError::InvalidParams(format!(
                "gadget.bits_per={} does not match spiral-rs bits_per={} for q={} and ell={}",
                gadget.bits_per, spiral_bits_per, q, gadget.ell
            )));
        }

        Ok(Self {
            d,
            q,
            p,
            sigma_chi,
            gadget,
            delta,
            d_inv,
            spiral,
        })
    }

    /// Convert to a [`spiral_rs::params::Params`] suitable for passing into
    /// the underlying NTT/poly stack. Spiral-PIR-specific fields
    /// (`t_conv`, `t_gsw`, `db_dim_*`, …) are filled with safe no-op
    /// defaults documented in [`docs/spiral-rs-mapping.md` §4](../../docs/spiral-rs-mapping.md).
    ///
    #[must_use = "the spiral-rs Params must be plumbed into PolyMatrix* allocators"]
    pub fn to_spiral_params(&self) -> SpiralParams {
        self.spiral.clone()
    }
}

fn mod_inverse(a: u64, modulus: u64) -> Option<u64> {
    let (mut old_r, mut r) = (i128::from(modulus), i128::from(a % modulus));
    let (mut old_s, mut s) = (0_i128, 1_i128);

    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_s, s) = (s, old_s - quotient * s);
    }

    (old_r == 1).then(|| old_s.rem_euclid(i128::from(modulus)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gadget() -> GadgetParams {
        GadgetParams {
            bits_per: 3,
            ell: 5,
        }
    }

    #[test]
    fn gadget_params_z_returns_power_of_two_base() {
        assert_eq!(gadget().z(), 8);
    }

    #[test]
    fn new_accepts_valid_parameters_and_caches_derived_values() {
        let params = RlweParams::new(8, 12289, 4, 3.2, gadget()).expect("valid params");

        assert_eq!(params.d, 8);
        assert_eq!(params.q, 12289);
        assert_eq!(params.p, 4);
        assert_eq!(params.delta, 3072);
        assert_eq!((params.d as u64 * params.d_inv) % params.q, 1);
        assert_eq!(params.spiral.poly_len, params.d);
        assert_eq!(params.spiral.modulus, params.q);
        assert_eq!(params.spiral.pt_modulus, params.p);
    }

    #[test]
    fn new_rejects_invalid_parameters() {
        assert!(RlweParams::new(7, 12289, 4, 3.2, gadget()).is_err());
        assert!(RlweParams::new(8, 12288, 4, 3.2, gadget()).is_err());
        assert!(RlweParams::new(8, 12289, 1, 3.2, gadget()).is_err());
        assert!(RlweParams::new(8, 12289, 12290, 3.2, gadget()).is_err());
        assert!(RlweParams::new(8, 12289, 4, 0.0, gadget()).is_err());
        assert!(RlweParams::new(8, 12289, 4, f64::NAN, gadget()).is_err());
        assert!(RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 0,
                ell: 5,
            },
        )
        .is_err());
        assert!(RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 3,
                ell: 0,
            },
        )
        .is_err());
        assert!(RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 2,
                ell: 5,
            },
        )
        .is_err());
    }

    #[test]
    fn to_spiral_params_returns_matching_backing_params() {
        let params = RlweParams::new(8, 12289, 4, 3.2, gadget()).expect("valid params");
        let spiral = params.to_spiral_params();

        assert_eq!(spiral.poly_len, 8);
        assert_eq!(spiral.modulus, 12289);
        assert_eq!(spiral.pt_modulus, 4);
    }

    #[test]
    fn mod_inverse_returns_inverse_when_it_exists() {
        assert_eq!(mod_inverse(8, 12289), Some(10753));
        assert_eq!((8 * mod_inverse(8, 12289).unwrap()) % 12289, 1);
    }

    #[test]
    fn mod_inverse_returns_none_when_not_coprime() {
        assert_eq!(mod_inverse(8, 12288), None);
    }
}
