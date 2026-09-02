//! Packing 32-byte nullifiers into one SimplePIR plaintext item.

pub const NULLIFIER_BYTES: usize = 32;
pub const SIMPLEPIR_COEFF_BITS: usize = 14;

/// RLWE output blocks per PIR row, i.e. YPIR's `instances`.
///
/// Upload scales with the row count and download with the column count, while
/// their product — the plaintext coefficient count — is fixed by the dataset.
/// One instance per row left the 49.9M-nullifier snapshot at 524288x2048, a
/// 256:1 upload skew that put 3.5 MB of first-dimension query on the wire; four
/// rebalanced that to 112640x8192.
///
/// Four was as far as it could go while packing and offline preprocessing both
/// cost a fixed amount per output block: each extra instance is another block.
/// With the fused collapse and the NTT-domain aggregate those per-block costs
/// dropped enough to move further out. At the current per-byte costs — a
/// 42-bit query coefficient per row up, 20 bits per column down — total wire is
/// minimized around 21 instances, but the curve is flat from 16 to 28 while
/// packing work, offline work, and the resident `digits_ntt` cache all grow
/// linearly in the block count. Sixteen sits at the near-flat end: 2% more wire
/// than the true optimum for 24% less packing work and 24% less memory.
///
/// Resulting shape: 28672x32768, 1792 nullifiers per row, 2.9% row padding.
pub const SIMPLEPIR_INSTANCES_PER_ITEM: usize = 16;

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
    let mut out = [0u16; SIMPLEPIR_COEFFS_PER_ITEM];
    encode_item_into(item, &mut out);
    out
}

/// Encode one item's bytes into a caller-supplied coefficient buffer.
///
/// Prefer this over [`encode_item_bytes`] on any hot path. That function has to
/// materialize a `[u16; SIMPLEPIR_COEFFS_PER_ITEM]` — 64 KiB — as a stack
/// temporary, and the older implementation also built a zero-padded `[u8;
/// ITEM_BYTES]` copy of the input. 121 KiB of stack locals is enough that, once
/// inlined into a caller, every entry to that caller pays frame setup and stack
/// probing. Snapshot ingestion hit exactly that: the encode was inlined up
/// through `load_next_row` into `Iterator::next`, so all 9.4e8 per-element calls
/// paid a 121 KiB frame for a branch taken once every 32,768 of them — 147.6 ns
/// per element against 5.7 ns once the frame was gone.
///
/// Bytes past the end of `item` read as zero, so a short final item does not
/// need a padded copy.
pub fn encode_item_into(item: &[u8], out: &mut [u16]) {
    assert!(
        item.len() <= ITEM_BYTES,
        "item must fit in one SimplePIR plaintext item"
    );
    assert_eq!(
        out.len(),
        SIMPLEPIR_COEFFS_PER_ITEM,
        "output must hold exactly one SimplePIR item"
    );

    for (idx, coeff) in out.iter_mut().enumerate() {
        *coeff = read_bits_le(item, idx * SIMPLEPIR_COEFF_BITS, SIMPLEPIR_COEFF_BITS) as u16;
    }
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

/// Read `bit_count` bits at `bit_offset`, little-endian within bytes.
///
/// One unaligned `u64` load, a shift and a mask, rather than a loop over bits.
/// Snapshot ingestion calls this once per plaintext coefficient — 32,768 per
/// row across every row of the database — so the bit-at-a-time version ran into
/// the billions of iterations, single-threaded, at load.
///
/// `bit_count` is capped at 57 so a load starting at the containing byte always
/// covers the field: the intra-byte shift is at most 7.
fn read_bits_le(data: &[u8], bit_offset: usize, bit_count: usize) -> u64 {
    debug_assert!((1..=57).contains(&bit_count));
    let byte = bit_offset / 8;
    if byte >= data.len() {
        // Past the end of a short item: those bits are zero by definition.
        return 0;
    }
    let shift = bit_offset % 8;
    let end = (byte + 8).min(data.len());
    let mut word = [0u8; 8];
    word[..end - byte].copy_from_slice(&data[byte..end]);
    (u64::from_le_bytes(word) >> shift) & ((1u64 << bit_count) - 1)
}

/// Write the low `bit_count` bits of `value` at `bit_offset`.
///
/// Mirrors [`read_bits_le`]: read the containing word, splice the field in,
/// write it back. Bits outside the field are preserved, so callers may write
/// into a partially populated buffer.
fn write_bits_le(data: &mut [u8], value: u64, bit_offset: usize, bit_count: usize) {
    debug_assert!((1..=57).contains(&bit_count));
    let byte = bit_offset / 8;
    let shift = bit_offset % 8;
    let end = (byte + 8).min(data.len());
    let mut word = [0u8; 8];
    word[..end - byte].copy_from_slice(&data[byte..end]);

    let mask = ((1u64 << bit_count) - 1) << shift;
    let spliced = (u64::from_le_bytes(word) & !mask) | ((value << shift) & mask);
    data[byte..end].copy_from_slice(&spliced.to_le_bytes()[..end - byte]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_pack_exactly_one_simplepir_item() {
        assert_eq!(SIMPLEPIR_COEFFS_PER_ITEM, 32_768);
        assert_eq!(ITEM_BYTES, 57_344);
        assert_eq!(NULLIFIERS_PER_ITEM, 1_792);
        assert_eq!(ITEM_SIZE_BITS, 458_752);
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

    /// The word-at-a-time splice must not disturb neighbouring fields, and must
    /// stay in bounds when fewer than eight bytes remain after the offset.
    #[test]
    fn bit_splice_preserves_neighbours_including_at_the_buffer_tail() {
        for len in [8usize, 9, 15, 16] {
            let mut buf = vec![0xA5u8; len];
            let reference = buf.clone();
            let fields = (len * 8) / SIMPLEPIR_COEFF_BITS;

            // Write a distinct value into every field, then read them all back.
            for idx in 0..fields {
                let value = (idx as u64 * 2731 + 17) % (1 << SIMPLEPIR_COEFF_BITS);
                write_bits_le(
                    &mut buf,
                    value,
                    idx * SIMPLEPIR_COEFF_BITS,
                    SIMPLEPIR_COEFF_BITS,
                );
            }
            for idx in 0..fields {
                let expected = (idx as u64 * 2731 + 17) % (1 << SIMPLEPIR_COEFF_BITS);
                assert_eq!(
                    read_bits_le(&buf, idx * SIMPLEPIR_COEFF_BITS, SIMPLEPIR_COEFF_BITS),
                    expected,
                    "len={len} idx={idx}"
                );
            }

            // Bits past the last written field are untouched.
            let tail_start = fields * SIMPLEPIR_COEFF_BITS;
            for bit in tail_start..len * 8 {
                let got = (buf[bit / 8] >> (bit % 8)) & 1;
                let want = (reference[bit / 8] >> (bit % 8)) & 1;
                assert_eq!(got, want, "len={len} bit={bit} outside written fields");
            }
        }
    }

    /// The padded copy is gone: a short item must encode exactly as the
    /// zero-padded full-width item it used to be expanded into. The final row
    /// of a snapshot is always short, so this is the production path.
    #[test]
    fn short_item_encodes_as_if_zero_padded() {
        for len in [
            0usize,
            1,
            31,
            32,
            NULLIFIER_BYTES * 3,
            ITEM_BYTES - 1,
            ITEM_BYTES,
        ] {
            let short: Vec<u8> = (0..len).map(|i| ((i * 37) ^ 0xc3) as u8).collect();
            let mut padded = vec![0u8; ITEM_BYTES];
            padded[..len].copy_from_slice(&short);

            let mut from_short = vec![0u16; SIMPLEPIR_COEFFS_PER_ITEM];
            encode_item_into(&short, &mut from_short);
            let from_padded = encode_item_bytes(&padded);

            assert_eq!(
                from_short.as_slice(),
                from_padded.as_slice(),
                "short item of {len} bytes must match its zero-padded form"
            );
        }
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
