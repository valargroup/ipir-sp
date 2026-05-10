//! Single-CRT modulus-switch helpers for IPIR-SP response transport.

use inspiring::RlweCiphertext;
use spiral_rs::poly::{from_ntt_alloc, PolyMatrix};

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
    let mut out = vec![0u8; (coeffs.len() * bits).div_ceil(8)];
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
    let expected_len = (coeff_count * bits).div_ceil(8);
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

/// Number of bytes in one serialized RLWE response ciphertext.
#[must_use]
pub fn switched_rlwe_response_len(degree: usize, q_prime_1: u64, q_prime_2: u64) -> usize {
    let total_bits = degree * (modulus_bits(q_prime_2) + modulus_bits(q_prime_1));
    total_bits.div_ceil(8)
}

/// Switch and serialize a raw two-row RLWE ciphertext.
///
/// This preserves YPIR's response layout: row 0 is switched to the larger
/// `q_prime_2`, then row 1 is switched to the smaller `q_prime_1`, packed
/// contiguously bit-by-bit. The RLWE arithmetic that produced these rows is
/// still InspiRING's single-CRT arithmetic under `q_in`.
#[must_use]
pub fn switch_rlwe_rows(
    row_0: &[u64],
    row_1: &[u64],
    q_in: u64,
    q_prime_1: u64,
    q_prime_2: u64,
) -> Vec<u8> {
    assert_eq!(row_0.len(), row_1.len(), "RLWE rows must have same degree");

    let row_0_bits = modulus_bits(q_prime_2);
    let row_1_bits = modulus_bits(q_prime_1);
    let mut out = vec![0u8; switched_rlwe_response_len(row_0.len(), q_prime_1, q_prime_2)];
    let mut bit_offs = 0;

    for coeff in row_0 {
        write_bits(
            &mut out,
            rescale(*coeff, q_in, q_prime_2),
            bit_offs,
            row_0_bits,
        );
        bit_offs += row_0_bits;
    }
    for coeff in row_1 {
        write_bits(
            &mut out,
            rescale(*coeff, q_in, q_prime_1),
            bit_offs,
            row_1_bits,
        );
        bit_offs += row_1_bits;
    }

    out
}

/// Recover two raw RLWE rows from [`switch_rlwe_rows`] output, rescaled into `q_out`.
#[must_use]
pub fn recover_rlwe_rows(
    ciphertext: &[u8],
    degree: usize,
    q_prime_1: u64,
    q_prime_2: u64,
    q_out: u64,
) -> (Vec<u64>, Vec<u64>) {
    assert_eq!(
        ciphertext.len(),
        switched_rlwe_response_len(degree, q_prime_1, q_prime_2),
        "serialized RLWE response length mismatch"
    );

    let row_0_bits = modulus_bits(q_prime_2);
    let row_1_bits = modulus_bits(q_prime_1);
    let mut bit_offs = 0;
    let mut row_0 = vec![0u64; degree];
    let mut row_1 = vec![0u64; degree];

    for coeff in &mut row_0 {
        let switched = read_bits(ciphertext, bit_offs, row_0_bits);
        *coeff = rescale(switched, q_prime_2, q_out);
        bit_offs += row_0_bits;
    }
    for coeff in &mut row_1 {
        let switched = read_bits(ciphertext, bit_offs, row_1_bits);
        *coeff = rescale(switched, q_prime_1, q_out);
        bit_offs += row_1_bits;
    }

    (row_0, row_1)
}

/// Switch and serialize one InspiRING packed RLWE ciphertext for transport.
#[must_use]
pub fn switch_rlwe_ciphertext(ct: &RlweCiphertext<'_>, q_prime_1: u64, q_prime_2: u64) -> Vec<u8> {
    assert_eq!(ct.inner.rows, 2, "packed RLWE ciphertext must have 2 rows");
    assert_eq!(
        ct.inner.cols, 1,
        "packed RLWE ciphertext must have 1 column"
    );

    let raw = from_ntt_alloc(&ct.inner);
    switch_rlwe_rows(
        raw.get_poly(0, 0),
        raw.get_poly(1, 0),
        raw.params.modulus,
        q_prime_1,
        q_prime_2,
    )
}

/// Serialize a vector of packed RLWE ciphertexts into a single response blob.
#[must_use]
pub fn serialize_rlwe_response(
    cts: &[RlweCiphertext<'_>],
    q_prime_1: u64,
    q_prime_2: u64,
) -> Vec<u8> {
    cts.iter()
        .flat_map(|ct| switch_rlwe_ciphertext(ct, q_prime_1, q_prime_2))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use inspiring::{GadgetParams, RlweCiphertext, RlweParams};
    use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};

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

    #[test]
    fn switch_rlwe_rows_uses_ypir_row_order_and_moduli() {
        let q_in = 97;
        let q_prime_1 = 17;
        let q_prime_2 = 257;
        let row_0 = [0, 5, 48, 96];
        let row_1 = [3, 49, 90, 1];

        let packed = switch_rlwe_rows(&row_0, &row_1, q_in, q_prime_1, q_prime_2);

        assert_eq!(
            packed.len(),
            switched_rlwe_response_len(4, q_prime_1, q_prime_2)
        );

        let mut bit_offs = 0;
        for coeff in row_0 {
            assert_eq!(
                read_bits(&packed, bit_offs, modulus_bits(q_prime_2)),
                rescale(coeff, q_in, q_prime_2)
            );
            bit_offs += modulus_bits(q_prime_2);
        }
        for coeff in row_1 {
            assert_eq!(
                read_bits(&packed, bit_offs, modulus_bits(q_prime_1)),
                rescale(coeff, q_in, q_prime_1)
            );
            bit_offs += modulus_bits(q_prime_1);
        }
    }

    #[test]
    fn recover_rlwe_rows_matches_expected_quantization() {
        let q_in = 97;
        let q_prime_1 = 17;
        let q_prime_2 = 257;
        let row_0 = [0, 5, 48, 96];
        let row_1 = [3, 49, 90, 1];

        let packed = switch_rlwe_rows(&row_0, &row_1, q_in, q_prime_1, q_prime_2);
        let (recovered_0, recovered_1) =
            recover_rlwe_rows(&packed, row_0.len(), q_prime_1, q_prime_2, q_in);

        let expected_0: Vec<_> = row_0
            .iter()
            .map(|coeff| rescale(rescale(*coeff, q_in, q_prime_2), q_prime_2, q_in))
            .collect();
        let expected_1: Vec<_> = row_1
            .iter()
            .map(|coeff| rescale(rescale(*coeff, q_in, q_prime_1), q_prime_1, q_in))
            .collect();

        assert_eq!(recovered_0, expected_0);
        assert_eq!(recovered_1, expected_1);
    }

    fn test_params() -> RlweParams {
        RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 3,
                ell: 5,
            },
        )
        .expect("valid params")
    }

    fn test_ct<'a>(params: &'a RlweParams, offset: u64) -> RlweCiphertext<'a> {
        let mut raw = PolyMatrixRaw::zero(&params.spiral, 2, 1);
        for coeff in 0..params.d {
            raw.get_poly_mut(0, 0)[coeff] = offset + coeff as u64;
            raw.get_poly_mut(1, 0)[coeff] = offset + 100 + coeff as u64;
        }
        RlweCiphertext {
            inner: to_ntt_alloc(&raw),
        }
    }

    #[test]
    fn switch_rlwe_ciphertext_reads_two_raw_rows() {
        let params = test_params();
        let ct = test_ct(&params, 10);

        let packed = switch_rlwe_ciphertext(&ct, 17, 257);
        let (row_0, row_1) = recover_rlwe_rows(&packed, params.d, 17, 257, params.q);

        assert_eq!(row_0[0], rescale(rescale(10, params.q, 257), 257, params.q));
        assert_eq!(row_1[0], rescale(rescale(110, params.q, 17), 17, params.q));
    }

    #[test]
    fn serialize_rlwe_response_concatenates_ciphertexts() {
        let params = test_params();
        let ct_0 = test_ct(&params, 10);
        let ct_1 = test_ct(&params, 20);
        let one_len = switched_rlwe_response_len(params.d, 17, 257);

        let response = serialize_rlwe_response(&[ct_0, ct_1], 17, 257);

        assert_eq!(response.len(), 2 * one_len);
    }
}
