//! Parameter mapping from YPIR's SimplePIR scenarios to `inspiring`.

use inspiring::{GadgetParams, RlweParams};
use serde::{Deserialize, Serialize};

/// Table-5 row-2 ring degree.
pub const POLY_LEN: usize = 2048;
/// YPIR-SP row-2 plaintext modulus (`log p = 14`).
pub const PLAINTEXT_MODULUS: u64 = 1 << 14;
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
/// YPIR-SP Table-5 row-2 gadget base exponent (`z = 2^19`).
pub const GADGET_BITS_PER: u32 = 19;
/// YPIR-SP Table-5 row-2 gadget length.
pub const GADGET_ELL: usize = 3;

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
}

/// Return `(inspiring::RlweParams, YpirSchemeParams)` for YPIR's SimplePIR scenario.
///
/// The initial target is YPIR-SP Table 5 row 2:
/// `(log d, log q, log p, ell, z) = (11, 56, 14, 3, 2^19)`.
pub fn params_for_simplepir(
    num_items: u64,
    item_size_bits: u64,
) -> Result<(RlweParams, YpirSchemeParams), inspiring::InspiringError> {
    assert!(
        item_size_bits >= (POLY_LEN as u64 * 14),
        "YPIR SimplePIR expects items at least one 2048x14-bit chunk"
    );
    assert!(
        num_items >= POLY_LEN as u64,
        "YPIR SimplePIR expects at least poly_len rows"
    );

    let db_rows = num_items.next_power_of_two();
    let db_dim_1 = db_rows.trailing_zeros() as usize - 11;
    let instances = item_size_bits.div_ceil(POLY_LEN as u64 * 14) as usize;

    let rlwe = RlweParams::new(
        POLY_LEN,
        SINGLE_CRT_Q,
        PLAINTEXT_MODULUS,
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
        db_rows: db_rows as usize,
        db_cols: instances * POLY_LEN,
        p: PLAINTEXT_MODULUS,
        q_prime_1: Q_PRIME_1,
        q_prime_2: Q_PRIME_2,
        q2_bits: Q2_BITS,
        t_exp_left: T_EXP_LEFT,
        t_exp_right: T_EXP_RIGHT,
    };

    Ok((rlwe, ypir))
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
}
