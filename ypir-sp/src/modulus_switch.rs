//! Single-CRT modulus-switch helpers for YPIR-SP response transport.

use crate::bits::{read_bits, write_bits};

/// Round `value mod q_in` into `q_out`, matching `spiral-rs::arith::rescale`.
#[must_use]
pub fn rescale(value: u64, q_in: u64, q_out: u64) -> u64 {
    assert!(q_in > 0, "input modulus must be non-zero");
    assert!(q_out > 0, "output modulus must be non-zero");

    let q_in_i64 = q_in as i64;
    let q_out_i128 = q_out as i128;
    let mut centered = (value % q_in) as i64;
    if centered >= q_in_i64 / 2 {
        centered -= q_in_i64;
    }

    let sign = if centered >= 0 { 1_i128 } else { -1_i128 };
    let numerator = centered as i128 * q_out as i128 + sign * (q_in_i64 / 2) as i128;
    let mut result = numerator / q_in as i128;
    result = (result + ((q_in / q_out) * q_out) as i128 + 2 * q_out_i128) % q_out_i128;

    ((result + q_out_i128) % q_out_i128) as u64
}

/// Bit width required to represent values modulo `modulus`.
#[must_use]
pub fn modulus_bits(modulus: u64) -> usize {
    assert!(modulus > 1, "modulus must be at least 2");
    (u64::BITS - (modulus - 1).leading_zeros()) as usize
}

/// Switch a single-CRT coefficient vector from `q_in` to `q_out` and pack it.
#[must_use]
pub fn switch_coeffs_single_crt(coeffs: &[u64], q_in: u64, q_out: u64) -> Vec<u8> {
    let bits = modulus_bits(q_out);
    let mut out = vec![0u8; (coeffs.len() * bits + 7) / 8];
    let mut bit_offs = 0;
    for coeff in coeffs {
        write_bits(&mut out, rescale(*coeff, q_in, q_out), bit_offs, bits);
        bit_offs += bits;
    }
    out
}

/// Recover a coefficient vector packed by [`switch_coeffs_single_crt`].
#[must_use]
pub fn recover_coeffs_single_crt(
    ciphertext: &[u8],
    coeff_count: usize,
    q_in: u64,
    q_out: u64,
) -> Vec<u64> {
    let bits = modulus_bits(q_in);
    let expected_len = (coeff_count * bits + 7) / 8;
    assert_eq!(
        ciphertext.len(),
        expected_len,
        "single-CRT ciphertext length mismatch"
    );

    let mut out = vec![0u64; coeff_count];
    let mut bit_offs = 0;
    for coeff in &mut out {
        let switched = read_bits(ciphertext, bit_offs, bits);
        *coeff = rescale(switched, q_in, q_out);
        bit_offs += bits;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rescale_matches_expected_rounding() {
        assert_eq!(rescale(0, 97, 13), 0);
        assert_eq!(rescale(1, 97, 13), 0);
        assert_eq!(rescale(4, 97, 13), 1);
        assert_eq!(rescale(96, 97, 13), 0);
        assert_eq!(rescale(93, 97, 13), 12);
    }

    #[test]
    fn switch_and_recover_roundtrip_with_expected_quantization() {
        let q_in = 97;
        let q_mid = 17;
        let coeffs = [0, 1, 7, 48, 49, 90, 96];

        let packed = switch_coeffs_single_crt(&coeffs, q_in, q_mid);
        let recovered = recover_coeffs_single_crt(&packed, coeffs.len(), q_mid, q_in);
        let expected: Vec<_> = coeffs
            .iter()
            .map(|coeff| rescale(rescale(*coeff, q_in, q_mid), q_mid, q_in))
            .collect();

        assert_eq!(recovered, expected);
    }
}
