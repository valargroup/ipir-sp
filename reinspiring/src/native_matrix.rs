//! Compact signed matrix storage with power-of-two and exact odd-modulus kernels.
use crate::{error::ReinspiringError, lift_ntt::centered, matrix::PackingMatrix};
use rayon::prelude::*;

const PACKED_TILE_ROWS: usize = 8;

pub(crate) enum Words {
    Narrow(crate::prepared_native::Storage<i32>),
    Packed {
        bits: usize,
        data: crate::prepared_native::Storage<u8>,
    },
    Wide(crate::prepared_native::Storage<i64>),
}

/// Validated row-major matrix with private dimensions and canonical storage.
pub struct NativeMatrix {
    pub(crate) rows: usize,
    pub(crate) cols: usize,
    pub(crate) q: u64,
    pub(crate) words: Words,
}
impl NativeMatrix {
    /// Convert a compiled matrix, choosing native signed words by its actual bound.
    pub fn from_compiled(m: PackingMatrix) -> Result<Self, ReinspiringError> {
        Self::from_blocks(vec![m])
    }
    /// Concatenate compiled limb matrices directly into compact row-major
    /// storage, avoiding a full-width intermediate H-stack allocation.
    pub fn from_blocks(blocks: Vec<PackingMatrix>) -> Result<Self, ReinspiringError> {
        let first = blocks
            .first()
            .ok_or_else(|| ReinspiringError::InvalidParams("empty native matrix blocks".into()))?;
        let rows = first.rows;
        let q = first.q;
        if !(2..=1 << 56).contains(&q) || rows == 0 {
            return Err(ReinspiringError::InvalidParams(
                "invalid native matrix".into(),
            ));
        }
        let mut cols = 0usize;
        let mut narrow = true;
        let mut fits27 = true;
        let mut packed28 =
            q.is_power_of_two() && rows % 4 == 0 && crate::native_kernel::supports_packed();
        for block in &blocks {
            if block.rows != rows
                || block.q != q
                || block.cols == 0
                || block.rows.checked_mul(block.cols) != Some(block.data.len())
            {
                return Err(ReinspiringError::InvalidParams(
                    "native matrix block mismatch".into(),
                ));
            }
            cols = cols
                .checked_add(block.cols)
                .filter(|&x| x <= 32768)
                .ok_or_else(|| ReinspiringError::InvalidParams("native matrix too wide".into()))?;
            for &x in &block.data {
                if x >= q {
                    return Err(ReinspiringError::InvalidParams(
                        "noncanonical native matrix".into(),
                    ));
                }
                let signed = centered(x, q);
                narrow &= i32::try_from(signed).is_ok();
                fits27 &= (-(1i128 << 26)..(1i128 << 26)).contains(&signed);
                packed28 &= (-(1i128 << 27)..(1i128 << 27)).contains(&signed);
            }
        }
        let count = rows
            .checked_mul(cols)
            .ok_or_else(|| ReinspiringError::InvalidParams("native matrix size overflow".into()))?;
        let words = if packed28 && cols % 8 == 0 {
            let bits = if fits27 { 27 } else { 28 };
            let stride = cols / 8 * bits;
            let size = rows
                .checked_mul(stride)
                .and_then(|n| n.checked_add(8))
                .ok_or_else(|| {
                    ReinspiringError::InvalidParams("packed matrix size overflow".into())
                })?;
            let mut out = vec![0u8; size];
            out[..rows * stride]
                .par_chunks_mut(stride)
                .enumerate()
                .for_each(|(r, row)| {
                    let mut col = 0;
                    for block in &blocks {
                        for &x in &block.data[r * block.cols..(r + 1) * block.cols] {
                            let value = (centered(x, q) as u64) & ((1 << bits) - 1);
                            let offset = col * bits / 8;
                            let shifted = value << (col * bits % 8);
                            for byte in 0..(bits + col * bits % 8).div_ceil(8) {
                                row[offset + byte] |= (shifted >> (8 * byte)) as u8;
                            }
                            col += 1;
                        }
                    }
                });
            Words::Packed {
                bits,
                data: out.into(),
            }
        } else if narrow {
            let mut out = vec![0i32; count];
            out.par_chunks_mut(cols).enumerate().for_each(|(r, row)| {
                let mut start = 0;
                for block in &blocks {
                    for (dst, &x) in row[start..start + block.cols]
                        .iter_mut()
                        .zip(&block.data[r * block.cols..(r + 1) * block.cols])
                    {
                        *dst = centered(x, q) as i32;
                    }
                    start += block.cols;
                }
            });
            Words::Narrow(out.into())
        } else {
            let mut out = vec![0i64; count];
            out.par_chunks_mut(cols).enumerate().for_each(|(r, row)| {
                let mut start = 0;
                for block in &blocks {
                    for (dst, &x) in row[start..start + block.cols]
                        .iter_mut()
                        .zip(&block.data[r * block.cols..(r + 1) * block.cols])
                    {
                        *dst = centered(x, q) as i64;
                    }
                    start += block.cols;
                }
            });
            Words::Wide(out.into())
        };
        Ok(Self {
            rows,
            cols,
            q,
            words,
        })
    }
    /// Bytes retained for coefficient words (excluding the small object header).
    pub fn storage_bytes(&self) -> usize {
        match &self.words {
            Words::Narrow(x) => x.len() * 4,
            Words::Packed { data: x, .. } => x.len(),
            Words::Wide(x) => x.len() * 8,
        }
    }
    /// Diagnostic read/XOR of the resident coefficient payload. This measures
    /// an optimistic memory-traffic baseline, not a cryptographic checksum.
    pub fn read_checksum(&self) -> u64 {
        match &self.words {
            Words::Packed { data: x, .. } => x
                .par_chunks(65536)
                .map(|part| part.iter().fold(0u8, |s, &x| s ^ x) as u64)
                .reduce(|| 0, |a, b| a ^ b),
            Words::Narrow(x) => x
                .par_chunks(65536)
                .map(|part| part.iter().fold(0i32, |s, &x| s ^ x) as u32 as u64)
                .reduce(|| 0, |a, b| a ^ b),
            Words::Wide(x) => x
                .par_chunks(65536)
                .map(|part| part.iter().fold(0i64, |s, &x| s ^ x) as u64)
                .reduce(|| 0, |a, b| a ^ b),
        }
    }
    /// Materialize canonical u64 coefficients for diagnostics, outside hot paths.
    pub fn to_compiled(&self) -> PackingMatrix {
        let mut m = PackingMatrix::zero(self.rows, self.cols, self.q);
        match &self.words {
            Words::Packed { bits, data: x } => {
                for (i, dst) in m.data.iter_mut().enumerate() {
                    *dst = (if *bits == 27 {
                        crate::native_kernel::read_packed::<27>(x, i)
                    } else {
                        crate::native_kernel::read_packed::<28>(x, i)
                    } as i128)
                        .rem_euclid(self.q as i128) as u64;
                }
            }
            Words::Narrow(x) => {
                for (dst, &v) in m.data.iter_mut().zip(x) {
                    *dst = (v as i128).rem_euclid(self.q as i128) as u64;
                }
            }
            Words::Wide(x) => {
                for (dst, &v) in m.data.iter_mut().zip(x) {
                    *dst = (v as i128).rem_euclid(self.q as i128) as u64;
                }
            }
        }
        m
    }
    /// Multiply using the current Rayon pool. Integer wrapping is exact mod 2^k.
    pub fn multiply(&self, y: &[u64]) -> Result<Vec<u64>, ReinspiringError> {
        if y.len() != self.cols || y.iter().any(|&x| x >= self.q) {
            return Err(ReinspiringError::LweShape(
                "invalid native matrix operand".into(),
            ));
        }
        if !self.q.is_power_of_two() {
            return self.multiply_odd(y);
        }
        let mut out = vec![0; self.rows];
        if let Words::Packed { bits, data: x } = &self.words {
            let stride = self.cols / 8 * bits;
            let tile_rows = if self.rows % PACKED_TILE_ROWS == 0 {
                PACKED_TILE_ROWS
            } else {
                4
            };
            out.par_chunks_mut(tile_rows)
                .enumerate()
                .for_each(|(tile, dst)| {
                    let bytes = &x[tile * tile_rows * stride
                        ..tile * tile_rows * stride + tile_rows * stride + 8];
                    match (*bits, tile_rows) {
                        (27, 4) => packed_tile::<27, 4, 4>(bytes, stride, y, dst, self.q - 1),
                        (28, 4) => packed_tile::<28, 4, 4>(bytes, stride, y, dst, self.q - 1),
                        (27, 8) => packed_tile::<27, 8, 2>(bytes, stride, y, dst, self.q - 1),
                        (28, 8) => packed_tile::<28, 8, 2>(bytes, stride, y, dst, self.q - 1),
                        (27, 16) => packed_tile::<27, 16, 1>(bytes, stride, y, dst, self.q - 1),
                        (28, 16) => packed_tile::<28, 16, 1>(bytes, stride, y, dst, self.q - 1),
                        _ => unreachable!("validated packed width and row tile"),
                    }
                });
            return Ok(out);
        }
        if let Words::Narrow(x) = &self.words {
            out.par_chunks_mut(4).enumerate().for_each(|(tile, dst)| {
                let start = tile * 4 * self.cols;
                if dst.len() == 4 {
                    let sums =
                        crate::native_kernel::dot_i32_rows4(&x[start..start + 4 * self.cols], y);
                    for (dst, sum) in dst.iter_mut().zip(sums) {
                        *dst = sum & (self.q - 1);
                    }
                } else {
                    for (r, dst) in dst.iter_mut().enumerate() {
                        *dst = crate::native_kernel::dot_i32(
                            &x[start + r * self.cols..start + (r + 1) * self.cols],
                            y,
                        ) & (self.q - 1);
                    }
                }
            });
            return Ok(out);
        }
        out.par_iter_mut().enumerate().for_each(|(r, dst)| {
            *dst = match &self.words {
                Words::Packed { .. } => unreachable!("packed path handled above"),
                Words::Narrow(x) => {
                    crate::native_kernel::dot_i32(&x[r * self.cols..(r + 1) * self.cols], y)
                }
                Words::Wide(x) => x[r * self.cols..(r + 1) * self.cols]
                    .iter()
                    .zip(y)
                    .fold(0u64, |s, (&a, &b)| {
                        s.wrapping_add((a as u64).wrapping_mul(b))
                    }),
            } & (self.q - 1);
        });
        Ok(out)
    }
    fn multiply_odd(&self, y: &[u64]) -> Result<Vec<u64>, ReinspiringError> {
        let mut out = vec![0; self.rows];
        match &self.words {
            Words::Packed { .. } => unreachable!("packed storage requires power-of-two modulus"),
            Words::Narrow(x) => {
                // Each partial signed sum is at most 2^31*(2^16-1)*32768
                // in magnitude, strictly below 2^63. Reinterpret the low-word
                // SIMD result as i64, then assemble the exact i128 sum.
                let limbs: Vec<Vec<_>> = (0..4)
                    .map(|j| y.iter().map(|&v| (v >> (j * 16)) & 65535).collect())
                    .collect();
                out.par_iter_mut().enumerate().for_each(|(r, dst)| {
                    let row = &x[r * self.cols..(r + 1) * self.cols];
                    let sum = limbs.iter().enumerate().fold(0i128, |s, (j, limb)| {
                        s + ((crate::native_kernel::dot_i32(row, limb) as i64 as i128) << (j * 16))
                    });
                    *dst = sum.rem_euclid(self.q as i128) as u64;
                });
            }
            Words::Wide(x) => out.par_iter_mut().enumerate().for_each(|(r, dst)| {
                // q<=2^56 and cols<=2^15 bound |sum| below 2^126.
                let sum = x[r * self.cols..(r + 1) * self.cols]
                    .iter()
                    .zip(y)
                    .fold(0i128, |s, (&a, &b)| s + (a as i128) * (b as i128));
                *dst = sum.rem_euclid(self.q as i128) as u64;
            }),
        }
        Ok(out)
    }
}

fn packed_tile<const BITS: usize, const ROWS: usize, const GROUPS: usize>(
    x: &[u8],
    stride: usize,
    y: &[u64],
    out: &mut [u64],
    mask: u64,
) {
    for (dst, sum) in
        out.iter_mut()
            .zip(crate::native_kernel::dot_packed_rows::<BITS, ROWS, GROUPS>(
                x, stride, y,
            ))
    {
        *dst = sum & mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocks_roundtrip_and_multiply_at_storage_boundaries() {
        let q = 1u64 << 54;
        for rows in [4, 8, 12, 16, 20, 32] {
            for bound in [
                1i64 << 26,
                (1 << 26) + 1,
                1i64 << 27,
                (1 << 27) + 1,
                1 << 31,
                (1 << 31) + 1,
            ] {
                let mut blocks = vec![];
                for cols in [3, 5, 8] {
                    let mut m = PackingMatrix::zero(rows, cols, q);
                    for (i, x) in m.data.iter_mut().enumerate() {
                        *x = ([bound - 1, -bound, 0, 1, -1][i % 5] as i128).rem_euclid(q as i128)
                            as u64;
                    }
                    blocks.push(m);
                }
                let expected: Vec<_> = (0..rows)
                    .flat_map(|r| {
                        blocks
                            .iter()
                            .flat_map(move |m| m.data[r * m.cols..(r + 1) * m.cols].iter().copied())
                    })
                    .collect();
                let m = NativeMatrix::from_blocks(blocks).unwrap();
                assert_eq!(m.to_compiled().data, expected);
                let y: Vec<_> = (0..16)
                    .map(|i| [q - 1, 0, q / 2, 12345678][i % 4])
                    .collect();
                let sums: Vec<_> = expected
                    .chunks(16)
                    .map(|row| {
                        row.iter()
                            .zip(&y)
                            .fold(0u64, |s, (&a, &b)| s.wrapping_add(a.wrapping_mul(b)))
                            & (q - 1)
                    })
                    .collect();
                assert_eq!(m.multiply(&y).unwrap(), sums);
                if bound > (1 << 27) {
                    assert!(!matches!(m.words, Words::Packed { .. }));
                } else if crate::native_kernel::supports_packed() {
                    let expected_bits = if bound <= (1 << 26) { 27 } else { 28 };
                    assert!(matches!(m.words, Words::Packed {bits,..} if bits==expected_bits));
                    assert_eq!(m.storage_bytes(), rows * 16 * expected_bits / 8 + 8);
                }
            }
        }
    }

    #[test]
    fn blocks_reject_malformed_and_mismatched_shapes() {
        assert!(NativeMatrix::from_blocks(vec![]).is_err());
        let a = PackingMatrix::zero(4, 8, 256);
        for b in [
            PackingMatrix::zero(3, 8, 256),
            PackingMatrix::zero(4, 8, 512),
            PackingMatrix::zero(4, 0, 256),
        ] {
            assert!(NativeMatrix::from_blocks(vec![a.clone(), b]).is_err());
        }
        let mut bad = a.clone();
        bad.data.pop();
        assert!(NativeMatrix::from_blocks(vec![a.clone(), bad]).is_err());
        let mut bad = a.clone();
        bad.data[0] = 256;
        assert!(NativeMatrix::from_blocks(vec![a, bad]).is_err());
    }
}
