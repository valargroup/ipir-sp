//! Coefficient codecs shared by native clients and evaluators.

use crate::{
    bits::{contiguous_bytes_to_u64s, u64s_to_contiguous_bytes},
    err,
};
use rand_chacha::{rand_core::RngCore, ChaCha20Rng};
use reinspiring::ReinspiringError;

/// Byte length of a fixed-width coefficient payload.
pub fn packed_len(n: usize, bits: usize) -> usize {
    (n * bits).div_ceil(8)
}
/// Encode fixed-width coefficients in the native little-endian wire format.
pub fn encode(words: &[u64], bits: usize) -> Vec<u8> {
    u64s_to_contiguous_bytes(words, bits)
}
/// Decode exactly the expected coefficients, rejecting length and padding mismatches.
pub fn decode(bytes: &[u8], n: usize, bits: usize) -> Result<Vec<u64>, ReinspiringError> {
    if bytes.len() != packed_len(n, bits) {
        return Err(err("invalid payload length"));
    }
    // Widths below 8 bits can unpack more than n words from the padding.
    let mut words = contiguous_bytes_to_u64s(bytes, bits);
    words.truncate(n);
    if encode(&words, bits) != bytes {
        return Err(err("noncanonical padding"));
    }
    Ok(words)
}
/// Round canonical ring coefficients to the selected transport width.
pub fn down(words: &[u64], q: u64, bits: usize) -> Vec<u64> {
    let shift = q.trailing_zeros() as usize - bits;
    words
        .iter()
        .map(|&x| {
            if shift == 0 {
                x
            } else {
                ((x + (1 << (shift - 1))) >> shift) & ((1 << bits) - 1)
            }
        })
        .collect()
}
/// Unbiased randomized rounding: round up with probability `dropped / 2^shift`,
/// exactly, by comparing the dropped bits with a fresh uniform integer.
/// Branch-free in the coefficient values.
pub(crate) fn down_dithered(words: &[u64], q: u64, bits: usize, rng: &mut ChaCha20Rng) -> Vec<u64> {
    let shift = q.trailing_zeros() as usize - bits;
    let low = (1u64 << shift) - 1;
    words
        .iter()
        .map(|&x| {
            let up = u64::from((rng.next_u64() & low) < (x & low));
            ((x >> shift) + up) & ((1 << bits) - 1)
        })
        .collect()
}
/// Lift transport coefficients into the ring without changing their encoded precision.
pub fn up(words: &[u64], q: u64, bits: usize) -> Vec<u64> {
    let shift = q.trailing_zeros() as usize - bits;
    words.iter().map(|&x| x << shift).collect()
}
