//! Parameter mapping from YPIR's SimplePIR scenarios to `inspiring`.

use inspiring::{GadgetParams, InspiringError, RlweParams};
use serde::{Deserialize, Serialize};

/// Table-5 row-2 ring degree.
pub const POLY_LEN: usize = 2048;
/// IPIR-SP row-2 plaintext modulus (`log p = 14`).
pub const PLAINTEXT_MODULUS: u64 = 1 << 14;
/// Plaintext modulus for the capacity-expanded profile.
pub const PLAINTEXT_MODULUS_16: u64 = 1 << 16;
/// One 56-bit NTT-friendly prime with `q = 1 mod 2d`.
pub const SINGLE_CRT_Q: u64 = 72_057_594_037_641_217;
/// YPIR's first transport modulus for packed response bytes.
pub const Q_PRIME_1: u64 = 1 << 20;
/// `spiral-rs` `Q2_VALUES[28]`, used by YPIR for the larger reduced modulus.
pub const Q_PRIME_2: u64 = 268_369_921;
/// YPIR's `q2_bits` for the initial SimplePIR target.
pub const Q2_BITS: usize = 28;
/// YPIR's left expansion gadget width for the SimplePIR scenario.
pub const T_EXP_LEFT: usize = 3;
/// YPIR's right expansion gadget width for the SimplePIR scenario.
pub const T_EXP_RIGHT: usize = 2;
/// IPIR-SP Table-5 row-2 gadget base exponent (`z = 2^19`).
pub const GADGET_BITS_PER: u32 = 19;
/// IPIR-SP Table-5 row-2 gadget length.
pub const GADGET_ELL: usize = 3;

/// Versioned SimplePIR plaintext and query-transport profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SimplePirProfile {
    /// Upstream-compatible 14-bit plaintexts with derived query precision.
    P14,
    /// Full `u16` plaintexts with at least 46 query bits for dense snapshots.
    P16Q46,
    /// Full `u16` plaintexts with at least 49 query bits; qualify each deployment.
    P16Q49,
}

impl SimplePirProfile {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::P14 => "simplepir-p14-v1",
            Self::P16Q46 => "simplepir-p16-q46-v1",
            Self::P16Q49 => "simplepir-p16-q49-v1",
        }
    }

    #[must_use]
    pub const fn plaintext_bits(self) -> usize {
        match self {
            Self::P14 => 14,
            Self::P16Q46 | Self::P16Q49 => 16,
        }
    }

    #[must_use]
    pub const fn plaintext_modulus(self) -> u64 {
        1 << self.plaintext_bits()
    }

    #[must_use]
    pub const fn minimum_query_bits(self) -> usize {
        match self {
            Self::P14 => 1,
            Self::P16Q46 => 46,
            Self::P16Q49 => 49,
        }
    }
}

/// A pinned SimplePIR profile and its validated database shape.
///
/// Its fields cannot be replaced independently after construction. This is the
/// parameter type accepted by the production client.
#[derive(Debug, Clone)]
pub struct ProductionSimplePirParams {
    profile: SimplePirProfile,
    rlwe: RlweParams,
    ypir: YpirSchemeParams,
}

impl ProductionSimplePirParams {
    /// Construct one of the versioned IPIR-SP profiles for a database shape.
    pub fn new(
        num_items: u64,
        item_size_bits: u64,
        profile: SimplePirProfile,
    ) -> Result<Self, InspiringError> {
        let (rlwe, ypir) = build_simplepir_params(num_items, item_size_bits, profile)?;
        validate_profile_parts(&rlwe, &ypir, profile)?;
        Ok(Self {
            profile,
            rlwe,
            ypir,
        })
    }

    /// Versioned profile identifier.
    #[must_use]
    pub const fn profile(&self) -> SimplePirProfile {
        self.profile
    }

    /// Read-only RLWE parameters.
    #[must_use]
    pub fn rlwe(&self) -> &RlweParams {
        &self.rlwe
    }

    /// Read-only transport and database parameters.
    #[must_use]
    pub fn ypir(&self) -> &YpirSchemeParams {
        &self.ypir
    }
}

/// YPIR-specific knobs that live outside `inspiring::RlweParams`.
///
/// This mirrors the JSON-derived `spiral_rs::params::Params` fields used by
/// `/root/ypir/src/params.rs::params_for_scenario_simplepir`:
///
/// - `poly_len = 2048`
/// - `p = 1 << 14`
/// - `q2_bits = 28`, giving `q_prime_2 = 268369921`
/// - `t_exp_left = 3`, `t_exp_right = 2`
/// - `nu_1 = log2(num_items.next_power_of_two()) - 11`
/// - `instances = ceil(item_size_bits / (2048 * 14))`
///
/// Unlike YPIR's original two-CRT RLWE side, `inspiring` receives a separate
/// single-CRT [`RlweParams`] with the 56-bit modulus in [`SINGLE_CRT_Q`].
/// Public fields and deserialization support low-level research and transport
/// inspection. Production clients accept [`ProductionSimplePirParams`] only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YpirSchemeParams {
    /// Requested logical database rows.
    pub num_items: u64,
    /// Requested item size in bits.
    pub item_size_bits: u64,
    /// YPIR `poly_len`.
    pub poly_len: usize,
    /// YPIR `nu_1`.
    pub db_dim_1: usize,
    /// YPIR `nu_2`; fixed to 1 for the SimplePIR port.
    pub db_dim_2: usize,
    /// Number of packed item chunks, YPIR's `instances`.
    pub instances: usize,
    /// Logical rows after YPIR's power-of-two padding.
    pub db_rows: usize,
    /// SimplePIR column count, `instances * poly_len`.
    pub db_cols: usize,
    /// Plaintext modulus.
    pub p: u64,
    /// Smaller reduced response modulus.
    pub q_prime_1: u64,
    /// Larger reduced response modulus.
    pub q_prime_2: u64,
    /// Bit index used to select `q_prime_2`.
    pub q2_bits: usize,
    /// Left expansion gadget width retained for wire compatibility notes.
    pub t_exp_left: usize,
    /// Right expansion gadget width retained for wire compatibility notes.
    pub t_exp_right: usize,
    /// Bit width the first-dimension query is transmitted at.
    ///
    /// Derived from `(q, p, db_rows)` by
    /// [`crate::modulus_switch::query_modulus_bits`] and raised to the selected
    /// profile's conservative floor. It must be recomputed whenever the shape
    /// or profile changes, never copied across parameter sets.
    pub query_bits: usize,
}

/// Return `(inspiring::RlweParams, YpirSchemeParams)` for YPIR's SimplePIR scenario.
///
/// The backward-compatible default is IPIR-SP Table 5 row 2:
/// `(log d, log q, log p, ell, z) = (11, 56, 14, 3, 2^19)`.
pub fn params_for_simplepir(
    num_items: u64,
    item_size_bits: u64,
) -> Result<(RlweParams, YpirSchemeParams), inspiring::InspiringError> {
    params_for_simplepir_profile(num_items, item_size_bits, SimplePirProfile::P14)
}

/// Return SimplePIR parameters for an explicit, versioned profile.
pub fn params_for_simplepir_profile(
    num_items: u64,
    item_size_bits: u64,
    profile: SimplePirProfile,
) -> Result<(RlweParams, YpirSchemeParams), inspiring::InspiringError> {
    let params = ProductionSimplePirParams::new(num_items, item_size_bits, profile)?;
    Ok((params.rlwe, params.ypir))
}

fn build_simplepir_params(
    num_items: u64,
    item_size_bits: u64,
    profile: SimplePirProfile,
) -> Result<(RlweParams, YpirSchemeParams), InspiringError> {
    let plaintext_bits = profile.plaintext_bits();
    let plaintext_modulus = profile.plaintext_modulus();
    if item_size_bits < (POLY_LEN * plaintext_bits) as u64 || num_items < POLY_LEN as u64 {
        return Err(InspiringError::InvalidParams(
            "SimplePIR requires at least one polynomial of rows and item bits".into(),
        ));
    }

    // The first dimension only needs a whole number of RLWE blocks; YPIR's
    // power-of-two padding costs up to 2x of both the database and the upload
    // for no benefit here. At the production nullifier shape it was 15%.
    let db_rows = num_items
        .checked_add(POLY_LEN as u64 - 1)
        .and_then(|n| n.checked_div(POLY_LEN as u64))
        .and_then(|n| n.checked_mul(POLY_LEN as u64))
        .ok_or_else(|| InspiringError::InvalidParams("database row count overflows".into()))?;
    let db_rows_usize = usize::try_from(db_rows)
        .map_err(|_| InspiringError::InvalidParams("database rows exceed usize".into()))?;
    // Retained for YPIR wire-compatibility reporting only; nothing on the IPIR
    // path consumes it, so it is derived from the padded power of two.
    let db_dim_1 = db_rows
        .checked_next_power_of_two()
        .ok_or_else(|| InspiringError::InvalidParams("database dimension overflows".into()))?
        .trailing_zeros() as usize
        - 11;
    let chunk_bits = (POLY_LEN * plaintext_bits) as u64;
    let instances_u64 = item_size_bits / chunk_bits + u64::from(item_size_bits % chunk_bits != 0);
    let instances = usize::try_from(instances_u64)
        .map_err(|_| InspiringError::InvalidParams("instance count exceeds usize".into()))?;
    let db_cols = instances
        .checked_mul(POLY_LEN)
        .ok_or_else(|| InspiringError::InvalidParams("database column count overflows".into()))?;
    db_rows_usize
        .checked_mul(db_cols)
        .ok_or_else(|| InspiringError::InvalidParams("database element count overflows".into()))?;

    let rlwe = RlweParams::new(
        POLY_LEN,
        SINGLE_CRT_Q,
        plaintext_modulus,
        6.4,
        GadgetParams {
            bits_per: GADGET_BITS_PER,
            ell: GADGET_ELL,
        },
    )?;

    let ypir = YpirSchemeParams {
        num_items,
        item_size_bits,
        poly_len: POLY_LEN,
        db_dim_1,
        db_dim_2: 1,
        instances,
        db_rows: db_rows_usize,
        db_cols,
        p: plaintext_modulus,
        q_prime_1: Q_PRIME_1,
        q_prime_2: Q_PRIME_2,
        q2_bits: Q2_BITS,
        t_exp_left: T_EXP_LEFT,
        t_exp_right: T_EXP_RIGHT,
        query_bits: crate::modulus_switch::query_modulus_bits(
            SINGLE_CRT_Q,
            plaintext_modulus,
            db_rows_usize,
        )
        .max(profile.minimum_query_bits()),
    };

    Ok((rlwe, ypir))
}

pub(crate) fn validate_profile_parts(
    rlwe: &RlweParams,
    ypir: &YpirSchemeParams,
    profile: SimplePirProfile,
) -> Result<(), InspiringError> {
    let invalid =
        || InspiringError::InvalidParams("inconsistent SimplePIR profile parameters".into());
    let expected_rows = ypir
        .num_items
        .checked_add(POLY_LEN as u64 - 1)
        .map(|n| n / POLY_LEN as u64 * POLY_LEN as u64)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(invalid)?;
    if expected_rows < POLY_LEN {
        return Err(invalid());
    }
    let chunk_bits = (POLY_LEN * profile.plaintext_bits()) as u64;
    let instances =
        ypir.item_size_bits / chunk_bits + u64::from(ypir.item_size_bits % chunk_bits != 0);
    let instances = usize::try_from(instances).map_err(|_| invalid())?;
    let expected_cols = instances.checked_mul(POLY_LEN).ok_or_else(invalid)?;
    let expected_dim = expected_rows
        .checked_next_power_of_two()
        .ok_or_else(invalid)?
        .trailing_zeros() as usize
        - 11;
    let expected_bits = crate::modulus_switch::query_modulus_bits(
        SINGLE_CRT_Q,
        profile.plaintext_modulus(),
        expected_rows,
    )
    .max(profile.minimum_query_bits());
    if rlwe.d != POLY_LEN
        || rlwe.q != SINGLE_CRT_Q
        || rlwe.p != profile.plaintext_modulus()
        || rlwe.sigma_chi.to_bits() != 6.4f64.to_bits()
        || rlwe.gadget.bits_per != GADGET_BITS_PER
        || rlwe.gadget.ell != GADGET_ELL
        || rlwe.delta != rlwe.q / rlwe.p
        || (u128::from(rlwe.d as u64) * u128::from(rlwe.d_inv)) % u128::from(rlwe.q) != 1
        || rlwe.spiral.poly_len != rlwe.d
        || rlwe.spiral.modulus != rlwe.q
        || rlwe.spiral.pt_modulus != rlwe.p
        || rlwe.spiral.noise_width.to_bits()
            != (rlwe.sigma_chi * std::f64::consts::TAU.sqrt()).to_bits()
        || ypir.num_items < POLY_LEN as u64
        || ypir.item_size_bits < chunk_bits
        || ypir.poly_len != rlwe.d
        || ypir.p != rlwe.p
        || ypir.db_dim_1 != expected_dim
        || ypir.db_dim_2 != 1
        || ypir.instances != instances
        || ypir.db_rows != expected_rows
        || ypir.db_cols != expected_cols
        || ypir.db_rows % rlwe.d != 0
        || ypir.db_cols % rlwe.d != 0
        || ypir.q_prime_1 != Q_PRIME_1
        || ypir.q_prime_2 != Q_PRIME_2
        || ypir.q2_bits != Q2_BITS
        || ypir.t_exp_left != T_EXP_LEFT
        || ypir.t_exp_right != T_EXP_RIGHT
        || ypir.query_bits != expected_bits
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simplepir_params_match_ypir_scenario_shape() {
        let (rlwe, ypir) = params_for_simplepir(1 << 14, 16_384 * 8).expect("valid params");

        assert_eq!(rlwe.d, 2048);
        assert_eq!(rlwe.q, SINGLE_CRT_Q);
        assert_eq!(rlwe.p, 1 << 14);
        assert_eq!(rlwe.gadget.bits_per, 19);
        assert_eq!(rlwe.gadget.ell, 3);
        assert_eq!(rlwe.q % (2 * rlwe.d as u64), 1);
        assert_eq!((rlwe.d as u128 * rlwe.d_inv as u128) % rlwe.q as u128, 1);

        assert_eq!(ypir.db_dim_1, 3);
        assert_eq!(ypir.instances, 5);
        assert_eq!(ypir.db_rows, 1 << 14);
        assert_eq!(ypir.db_cols, 5 * 2048);
        assert_eq!(ypir.db_rows % rlwe.d, 0);
        assert_eq!(ypir.q_prime_1, 1 << 20);
        assert_eq!(ypir.q_prime_2, 268_369_921);
    }

    #[test]
    fn ypir_params_serialize_stably() {
        let (_, ypir) = params_for_simplepir(1 << 15, 32_768 * 8).expect("valid params");
        let encoded = serde_json::to_string(&ypir).expect("serialize");
        let decoded: YpirSchemeParams = serde_json::from_str(&encoded).expect("deserialize");

        assert_eq!(decoded, ypir);
        assert_eq!(decoded.db_dim_1, 4);
        assert_eq!(decoded.instances, 10);
    }

    #[test]
    fn p16_q46_profile_has_six_instances_and_33_record_capacity() {
        const RECORD_BYTES: u64 = 737;
        const RECORDS_PER_ROW: u64 = 33;
        let (rlwe, ypir) = params_for_simplepir_profile(
            8_192,
            RECORD_BYTES * RECORDS_PER_ROW * 8,
            SimplePirProfile::P16Q46,
        )
        .expect("valid capacity-expanded profile");

        assert_eq!(SimplePirProfile::P16Q46.id(), "simplepir-p16-q46-v1");
        assert_eq!(rlwe.p, PLAINTEXT_MODULUS_16);
        assert_eq!(ypir.p, PLAINTEXT_MODULUS_16);
        assert_eq!(ypir.instances, 6);
        assert_eq!(ypir.db_cols, 12_288);
        assert_eq!(ypir.query_bits, 46);
        assert_eq!(ypir.q_prime_1, 1 << 20);
    }

    #[test]
    fn q49_changes_only_transport_and_rejects_downgrade() {
        assert_eq!(SimplePirProfile::P16Q49.id(), "simplepir-p16-q49-v1");
        for rows in [2048, 4096, 8192, 16384, 32768] {
            let old = ProductionSimplePirParams::new(rows, 653 * 33 * 8, SimplePirProfile::P16Q46)
                .unwrap();
            let new = ProductionSimplePirParams::new(rows, 653 * 33 * 8, SimplePirProfile::P16Q49)
                .unwrap();
            assert_eq!(new.ypir().query_bits, 49);
            assert_eq!(new.ypir().instances, 6);
            let mut expected = old.ypir().clone();
            expected.query_bits = 49;
            assert_eq!(new.ypir(), &expected);
            assert!(
                validate_profile_parts(old.rlwe(), new.ypir(), SimplePirProfile::P16Q49).is_ok()
            );
            for bits in [0, 46, 47, 48, 50, 57] {
                let mut changed = new.ypir().clone();
                changed.query_bits = bits;
                assert!(
                    validate_profile_parts(new.rlwe(), &changed, SimplePirProfile::P16Q49).is_err()
                );
            }
            assert!(
                validate_profile_parts(new.rlwe(), new.ypir(), SimplePirProfile::P16Q46).is_err()
            );
        }
    }

    #[test]
    fn production_profiles_reject_weak_and_inconsistent_parts() {
        for profile in [
            SimplePirProfile::P14,
            SimplePirProfile::P16Q46,
            SimplePirProfile::P16Q49,
        ] {
            let params =
                ProductionSimplePirParams::new(8_192, 2048 * 16, profile).expect("pinned profile");
            assert_eq!(params.profile(), profile);
            let mut rlwe = params.rlwe().clone();
            let mut ypir = params.ypir().clone();

            rlwe.sigma_chi = 0.01;
            assert!(validate_profile_parts(&rlwe, &ypir, profile).is_err());
            rlwe = params.rlwe().clone();
            rlwe.delta += 1;
            assert!(validate_profile_parts(&rlwe, &ypir, profile).is_err());
            rlwe = params.rlwe().clone();
            rlwe.spiral.noise_width = 0.01;
            assert!(validate_profile_parts(&rlwe, &ypir, profile).is_err());
            rlwe = params.rlwe().clone();
            ypir.query_bits -= 1;
            assert!(validate_profile_parts(&rlwe, &ypir, profile).is_err());
            ypir = params.ypir().clone();
            ypir.db_cols += POLY_LEN;
            assert!(validate_profile_parts(&rlwe, &ypir, profile).is_err());
            ypir = params.ypir().clone();
            ypir.p = 4;
            assert!(validate_profile_parts(&rlwe, &ypir, profile).is_err());
        }
    }

    #[test]
    fn production_profile_rejects_bad_shapes_without_panicking() {
        for (rows, bits) in [(0, 2048 * 14), (2048, 1), (u64::MAX, 2048 * 14)] {
            assert!(ProductionSimplePirParams::new(rows, bits, SimplePirProfile::P14).is_err());
        }
        assert!(ProductionSimplePirParams::new(2048, u64::MAX, SimplePirProfile::P14).is_err());
    }
}
