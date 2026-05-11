//! Wire serialization helpers for IPIR-SP key material.
//!
//! The stable local-IPIR upload format is the little-endian `u64` coefficient
//! stream for the secret-dependent `K_g` and `K_h` packing-key bodies. Public
//! top rows are derived from fixed CRS seeds by the client and server.

use inspiring::{InspiringError, PackingKeys, RlweParams};
use spiral_rs::poly::{PolyMatrix, PolyMatrixNTT};

/// Number of bytes used by uploaded full packing-key bodies.
#[must_use]
pub fn serialized_packing_keys_len(params: &RlweParams) -> usize {
    2 * packing_key_body_u64_len(params) * std::mem::size_of::<u64>()
}

/// Serialize uploaded packing-key bodies.
pub fn serialize_packing_keys(
    params: &RlweParams,
    keys: &PackingKeys<'_>,
) -> Result<Vec<u8>, InspiringError> {
    validate_packing_key_body(params, &keys.kg_body, "packing key K_g body")?;
    validate_packing_key_body(params, &keys.kh_body, "packing key K_h body")?;

    let mut out = Vec::with_capacity(serialized_packing_keys_len(params));
    write_u64s_le(&mut out, keys.kg_body.as_slice());
    write_u64s_le(&mut out, keys.kh_body.as_slice());
    Ok(out)
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

    let coeffs = deserialize_u64s_le(data)?;
    let body_len = packing_key_body_u64_len(params);
    let kg_body =
        packing_key_body_from_coeffs(params, &coeffs[..body_len], "packing key K_g body")?;
    let kh_body =
        packing_key_body_from_coeffs(params, &coeffs[body_len..], "packing key K_h body")?;
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
    fn serialized_packing_keys_len_matches_two_body_rows() {
        let params = params();

        assert_eq!(
            serialized_packing_keys_len(&params),
            2 * params.gadget.ell * params.d * 8
        );
    }

    #[test]
    fn packing_keys_roundtrip_kg_then_kh_bodies() {
        let params = params();
        let secret = secret(&params);
        let secret_ntt = secret.to_ntt(&params);
        let mut rng = ChaCha20Rng::seed_from_u64(0x5154);
        let keys = PackingKeys::generate_full(&params, &secret_ntt, &mut rng);
        let bytes = serialize_packing_keys(&params, &keys).expect("serialize");
        let body_len = packing_key_body_u64_len(&params) * 8;

        assert_eq!(bytes.len(), serialized_packing_keys_len(&params));
        assert_eq!(
            &bytes[..8],
            &keys.kg_body.as_slice()[0].to_le_bytes(),
            "K_g body is serialized first"
        );
        assert_eq!(
            &bytes[body_len..body_len + 8],
            &keys.kh_body.as_slice()[0].to_le_bytes(),
            "K_h body follows K_g body"
        );

        let decoded = deserialize_packing_keys(&params, &bytes).expect("deserialize");
        assert_eq!(decoded.kg_body.as_slice(), keys.kg_body.as_slice());
        assert_eq!(decoded.kh_body.as_slice(), keys.kh_body.as_slice());
    }

    #[test]
    fn deserialize_u64s_le_rejects_truncated_value() {
        let err = deserialize_u64s_le(&[1, 2, 3]).expect_err("truncated u64 must fail");

        assert!(matches!(err, InspiringError::PreprocessMismatch(_)));
    }
}
