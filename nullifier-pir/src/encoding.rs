//! Packing 32-byte nullifiers into one SimplePIR plaintext item.

pub const NULLIFIER_BYTES: usize = 32;
pub const SIMPLEPIR_COEFF_BITS: usize = 14;

/// RLWE output blocks per PIR row, i.e. YPIR's `instances`.
///
/// Upload scales with the row count and download with the column count, while
/// their product — the plaintext coefficient count — is fixed by the dataset.
/// One instance per row leaves the 49.9M-nullifier snapshot at 524288x2048, a
/// 256:1 upload skew that put 3.5 MB of first-dimension query on the wire. Four
/// instances rebalance that to 112640x8192: 770 KB up, 48 KB down, same
/// database size and (slightly less) matrix-vector work. It also gives
/// `pack_intermediate_blocks` four blocks to spread across cores instead of one.
pub const SIMPLEPIR_INSTANCES_PER_ITEM: usize = 4;

/// Plaintext coefficients per PIR row: `instances * poly_len`.
pub const SIMPLEPIR_COEFFS_PER_ITEM: usize = SIMPLEPIR_INSTANCES_PER_ITEM * 2048;
pub const ITEM_BYTES: usize = SIMPLEPIR_COEFF_BITS * SIMPLEPIR_COEFFS_PER_ITEM / 8;
pub const NULLIFIERS_PER_ITEM: usize = ITEM_BYTES / NULLIFIER_BYTES;
pub const ITEM_SIZE_BITS: u64 = (ITEM_BYTES * 8) as u64;

#[must_use]
pub fn pir_row_count(record_count: usize) -> usize {
    record_count.div_ceil(NULLIFIERS_PER_ITEM)
}

#[must_use]
pub fn encode_item_bytes(item: &[u8]) -> [u16; SIMPLEPIR_COEFFS_PER_ITEM] {
    assert!(
        item.len() <= ITEM_BYTES,
        "item must fit in one SimplePIR plaintext item"
    );

    let mut padded = [0u8; ITEM_BYTES];
    padded[..item.len()].copy_from_slice(item);

    let mut out = [0u16; SIMPLEPIR_COEFFS_PER_ITEM];
    for (idx, coeff) in out.iter_mut().enumerate() {
        *coeff = read_bits_le(&padded, idx * SIMPLEPIR_COEFF_BITS, SIMPLEPIR_COEFF_BITS) as u16;
    }
    out
}

#[must_use]
pub fn decode_item_coefficients(coefficients: &[u64]) -> Vec<u8> {
    assert!(
        coefficients.len() >= SIMPLEPIR_COEFFS_PER_ITEM,
        "decoded row must contain at least one SimplePIR item"
    );

    let mut out = vec![0u8; ITEM_BYTES];
    for (idx, coeff) in coefficients
        .iter()
        .take(SIMPLEPIR_COEFFS_PER_ITEM)
        .enumerate()
    {
        write_bits_le(
            &mut out,
            *coeff,
            idx * SIMPLEPIR_COEFF_BITS,
            SIMPLEPIR_COEFF_BITS,
        );
    }
    out
}

#[must_use]
pub fn nullifier_offset(global_index: usize) -> (usize, usize) {
    (
        global_index / NULLIFIERS_PER_ITEM,
        global_index % NULLIFIERS_PER_ITEM,
    )
}

#[must_use]
pub fn extract_nullifier(item: &[u8], offset_in_item: usize) -> Option<[u8; NULLIFIER_BYTES]> {
    if offset_in_item >= NULLIFIERS_PER_ITEM {
        return None;
    }

    let start = offset_in_item * NULLIFIER_BYTES;
    let end = start + NULLIFIER_BYTES;
    let mut out = [0u8; NULLIFIER_BYTES];
    out.copy_from_slice(item.get(start..end)?);
    Some(out)
}

fn read_bits_le(data: &[u8], bit_offset: usize, bit_count: usize) -> u64 {
    debug_assert!(bit_count <= 64);
    let mut out = 0u64;
    for bit in 0..bit_count {
        let source_bit = bit_offset + bit;
        let byte = data[source_bit / 8];
        let value = (byte >> (source_bit % 8)) & 1;
        out |= u64::from(value) << bit;
    }
    out
}

fn write_bits_le(data: &mut [u8], value: u64, bit_offset: usize, bit_count: usize) {
    debug_assert!(bit_count <= 64);
    for bit in 0..bit_count {
        let target_bit = bit_offset + bit;
        let byte = &mut data[target_bit / 8];
        let mask = 1u8 << (target_bit % 8);
        if ((value >> bit) & 1) == 1 {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_pack_exactly_one_simplepir_item() {
        assert_eq!(SIMPLEPIR_COEFFS_PER_ITEM, 8192);
        assert_eq!(ITEM_BYTES, 14_336);
        assert_eq!(NULLIFIERS_PER_ITEM, 448);
        assert_eq!(ITEM_SIZE_BITS, 114_688);
        // The row must fill whole plaintext coefficients exactly, otherwise the
        // tail coefficient is partially populated and `instances` is wrong.
        assert_eq!(SIMPLEPIR_COEFF_BITS * SIMPLEPIR_COEFFS_PER_ITEM % 8, 0);
    }

    #[test]
    fn row_count_rounds_up_to_nullifier_group() {
        assert_eq!(pir_row_count(0), 0);
        assert_eq!(pir_row_count(1), 1);
        assert_eq!(pir_row_count(NULLIFIERS_PER_ITEM), 1);
        assert_eq!(pir_row_count(NULLIFIERS_PER_ITEM + 1), 2);
    }

    #[test]
    fn coefficients_roundtrip_a_full_item() {
        let mut item = vec![0u8; ITEM_BYTES];
        for (idx, byte) in item.iter_mut().enumerate() {
            *byte = (idx.wrapping_mul(31) ^ 0x5a) as u8;
        }

        let coeffs = encode_item_bytes(&item);
        assert!(coeffs.iter().all(|coeff| u64::from(*coeff) < (1 << 14)));

        let decoded_coeffs: Vec<_> = coeffs.iter().map(|coeff| u64::from(*coeff)).collect();
        assert_eq!(decode_item_coefficients(&decoded_coeffs), item);
    }

    #[test]
    fn extracts_nullifier_by_global_index_mapping() {
        // Expressed in terms of the packing constant so the mapping stays
        // pinned when the instance count is re-tuned.
        let (row, offset) = nullifier_offset(NULLIFIERS_PER_ITEM + 1);
        assert_eq!((row, offset), (1, 1));
        assert_eq!(
            nullifier_offset(NULLIFIERS_PER_ITEM - 1),
            (0, NULLIFIERS_PER_ITEM - 1)
        );
        assert_eq!(nullifier_offset(NULLIFIERS_PER_ITEM), (1, 0));

        let mut item = vec![0u8; ITEM_BYTES];
        item[32..64].copy_from_slice(&[7u8; 32]);
        assert_eq!(extract_nullifier(&item, 1), Some([7u8; 32]));
    }
}
