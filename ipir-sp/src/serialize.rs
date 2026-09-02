//! Wire serialization helpers for IPIR-SP key material.
//!
//! The stable local-IPIR upload format is the little-endian `u64` coefficient
//! stream for the secret-dependent `K_g` and `K_h` packing-key bodies. Public
//! top rows are derived from fixed CRS seeds by the client and server.

use inspiring::{InspiringError, PackingKeys, RlweParams};

use crate::bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes};
use crate::modulus_switch::modulus_bits;
use spiral_rs::poly::{PolyMatrix, PolyMatrixNTT};

/// Number of bytes used by uploaded full packing-key bodies.
///
/// Coefficients are packed at exactly `ceil(log2 q)` bits. At the production
/// modulus that is 56 of every 64 bits, so the previous raw-`u64` stream spent
/// 12.5% of the key upload on zero padding.
#[must_use]
pub fn serialized_packing_keys_len(params: &RlweParams) -> usize {
    let bits = modulus_bits(params.q);
    (2 * packing_key_body_u64_len(params) * bits).div_ceil(8)
}

/// Serialize uploaded packing-key bodies.
pub fn serialize_packing_keys(
    params: &RlweParams,
    keys: &PackingKeys<'_>,
) -> Result<Vec<u8>, InspiringError> {
    validate_packing_key_body(params, &keys.kg_body, "packing key K_g body")?;
    validate_packing_key_body(params, &keys.kh_body, "packing key K_h body")?;

    let mut coeffs = Vec::with_capacity(2 * packing_key_body_u64_len(params));
    coeffs.extend_from_slice(keys.kg_body.as_slice());
    coeffs.extend_from_slice(keys.kh_body.as_slice());
    Ok(u64s_to_contiguous_bytes(&coeffs, modulus_bits(params.q)))
}

/// Deserialize uploaded full packing-key bodies.
pub fn deserialize_packing_keys<'a>(
    params: &'a RlweParams,
    data: &[u8],
) -> Result<PackingKeys<'a>, InspiringError> {
    if data.len() != serialized_packing_keys_len(params) {
        return Err(InspiringError::PreprocessMismatch(format!(
            "serialized packing keys must be {} bytes, got {}",
            serialized_packing_keys_len(params),
            data.len()
        )));
    }

    let coeffs = contiguous_bytes_to_u64s(data, modulus_bits(params.q));
    let body_len = packing_key_body_u64_len(params);
    if coeffs.len() < 2 * body_len {
        return Err(InspiringError::PreprocessMismatch(format!(
            "serialized packing keys hold {} coefficients, expected {}",
            coeffs.len(),
            2 * body_len
        )));
    }
    let kg_body =
        packing_key_body_from_coeffs(params, &coeffs[..body_len], "packing key K_g body")?;
    let kh_body = packing_key_body_from_coeffs(
        params,
        &coeffs[body_len..2 * body_len],
        "packing key K_h body",
    )?;
    Ok(PackingKeys { kg_body, kh_body })
}

/// Serialize a sequence of `u64` values as little-endian bytes.
#[must_use]
pub fn serialize_u64s_le(data: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(std::mem::size_of_val(data));
    write_u64s_le(&mut out, data);
    out
}

/// Deserialize little-endian `u64` bytes.
pub fn deserialize_u64s_le(data: &[u8]) -> Result<Vec<u64>, InspiringError> {
    if data.len() % std::mem::size_of::<u64>() != 0 {
        return Err(InspiringError::PreprocessMismatch(format!(
            "u64 byte stream length must be a multiple of 8, got {}",
            data.len()
        )));
    }

    Ok(data
        .chunks_exact(std::mem::size_of::<u64>())
        .map(|chunk| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            u64::from_le_bytes(bytes)
        })
        .collect())
}

fn packing_key_body_u64_len(params: &RlweParams) -> usize {
    params.gadget.ell * params.d
}

fn packing_key_body_from_coeffs<'a>(
    params: &'a RlweParams,
    coeffs: &[u64],
    label: &'static str,
) -> Result<PolyMatrixNTT<'a>, InspiringError> {
    if coeffs.len() != packing_key_body_u64_len(params) {
        return Err(InspiringError::PreprocessMismatch(format!(
            "{label} coefficient length must be {}, got {}",
            packing_key_body_u64_len(params),
            coeffs.len()
        )));
    }

    let mut body = PolyMatrixNTT::zero(&params.spiral, 1, params.gadget.ell);
    body.as_mut_slice().copy_from_slice(coeffs);
    validate_packing_key_body(params, &body, label)?;
    Ok(body)
}

fn validate_packing_key_body(
    params: &RlweParams,
    body: &PolyMatrixNTT<'_>,
    label: &'static str,
) -> Result<(), InspiringError> {
    if body.rows != 1 || body.cols != params.gadget.ell {
        return Err(InspiringError::PreprocessMismatch(format!(
            "{label} must have shape 1x{}, got {}x{}",
            params.gadget.ell, body.rows, body.cols
        )));
    }

    if body.as_slice().len() != packing_key_body_u64_len(params) {
        return Err(InspiringError::PreprocessMismatch(format!(
            "{label} coefficient length must be {}, got {}",
            packing_key_body_u64_len(params),
            body.as_slice().len()
        )));
    }

    // Key bodies come from the client, and the fused collapse bounds its
    // accumulator by `(d-1) * ell * (q-1)^2`. Bit-packing at `ceil(log2 q)`
    // bits still admits values in `[q, 2^ceil(log2 q))`, so the range has to be
    // checked rather than assumed from the wire width.
    if let Some(bad) = body.as_slice().iter().find(|coeff| **coeff >= params.q) {
        return Err(InspiringError::PreprocessMismatch(format!(
            "{label} contains coefficient {bad} which is not reduced modulo q={}",
            params.q
        )));
    }

    Ok(())
}

fn write_u64s_le(out: &mut Vec<u8>, data: &[u64]) {
    out.reserve(std::mem::size_of_val(data));
    for coeff in data {
        out.extend_from_slice(&coeff.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use inspiring::{GadgetParams, PackingKeys, RlweParams};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::client::ClientSecret;

    use super::*;

    fn params() -> RlweParams {
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

    fn secret(params: &RlweParams) -> ClientSecret {
        ClientSecret::from_coeffs(params, vec![1, 0, params.q - 1, 1, 0, 1, 0, 0])
    }

    #[test]
    fn serialized_packing_keys_len_packs_two_body_rows_at_modulus_width() {
        let params = params();

        assert_eq!(
            serialized_packing_keys_len(&params),
            (2 * params.gadget.ell * params.d * modulus_bits(params.q)).div_ceil(8)
        );
        // The whole point: strictly smaller than the raw `u64` stream.
        assert!(serialized_packing_keys_len(&params) < 2 * params.gadget.ell * params.d * 8);
    }

    #[test]
    fn packing_keys_roundtrip_kg_then_kh_bodies() {
        let params = params();
        let secret = secret(&params);
        let secret_ntt = secret.to_ntt(&params);
        let mut rng = ChaCha20Rng::seed_from_u64(0x5154);
        let keys = PackingKeys::generate_full(&params, &secret_ntt, &mut rng);
        let bytes = serialize_packing_keys(&params, &keys).expect("serialize");
        let body_len = packing_key_body_u64_len(&params);
        let unpacked = contiguous_bytes_to_u64s(&bytes, modulus_bits(params.q));

        assert_eq!(bytes.len(), serialized_packing_keys_len(&params));
        assert_eq!(
            &unpacked[..body_len],
            keys.kg_body.as_slice(),
            "K_g body is serialized first"
        );
        assert_eq!(
            &unpacked[body_len..2 * body_len],
            keys.kh_body.as_slice(),
            "K_h body follows K_g body"
        );

        let decoded = deserialize_packing_keys(&params, &bytes).expect("deserialize");
        assert_eq!(decoded.kg_body.as_slice(), keys.kg_body.as_slice());
        assert_eq!(decoded.kh_body.as_slice(), keys.kh_body.as_slice());
    }

    #[test]
    fn deserialize_packing_keys_rejects_unreduced_coefficients() {
        let params = params();
        let body_len = packing_key_body_u64_len(&params);
        let bits = modulus_bits(params.q);
        // `q = 12289` needs 14 bits, so 12289..16384 is representable on the
        // wire but not a valid reduced coefficient.
        let mut coeffs = vec![0u64; 2 * body_len];
        coeffs[3] = params.q;
        let bytes = u64s_to_contiguous_bytes(&coeffs, bits);

        let err = match deserialize_packing_keys(&params, &bytes) {
            Ok(_) => panic!("unreduced coefficient must be rejected"),
            Err(err) => err,
        };
        assert!(
            format!("{err}").contains("not reduced"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn deserialize_u64s_le_rejects_truncated_value() {
        let err = deserialize_u64s_le(&[1, 2, 3]).expect_err("truncated u64 must fail");

        assert!(matches!(err, InspiringError::PreprocessMismatch(_)));
    }
}
