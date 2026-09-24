//! Compact signed matrix storage with power-of-two and exact odd-modulus kernels.
use crate::{error::ReinspiringError, lift_ntt::centered, matrix::PackingMatrix};
use rayon::prelude::*;

enum Words {
    Narrow(Vec<i32>),
    Wide(Vec<i64>),
}

/// Validated row-major matrix with private dimensions and canonical storage.
pub struct NativeMatrix {
    rows: usize,
    cols: usize,
    q: u64,
    words: Words,
}
impl NativeMatrix {
    /// Convert a compiled matrix, choosing native signed words by its actual bound.
    pub fn from_compiled(m: PackingMatrix) -> Result<Self, ReinspiringError> {
        if m.q > 1 << 56
            || m.q < 2
            || m.rows == 0
            || m.cols == 0
            || m.cols > 32768
            || m.rows.checked_mul(m.cols) != Some(m.data.len())
            || m.data.iter().any(|&x| x >= m.q)
        {
            return Err(ReinspiringError::InvalidParams(
                "invalid native matrix".into(),
            ));
        }
        let narrow = m
            .data
            .iter()
            .all(|&x| i32::try_from(centered(x, m.q)).is_ok());
        let words = if narrow {
            Words::Narrow(m.data.iter().map(|&x| centered(x, m.q) as i32).collect())
        } else {
            Words::Wide(m.data.iter().map(|&x| centered(x, m.q) as i64).collect())
        };
        Ok(Self {
            rows: m.rows,
            cols: m.cols,
            q: m.q,
            words,
        })
    }
    /// Bytes retained for coefficient words (excluding the small object header).
    pub fn storage_bytes(&self) -> usize {
        match &self.words {
            Words::Narrow(x) => x.len() * 4,
            Words::Wide(x) => x.len() * 8,
        }
    }
    /// Materialize canonical u64 coefficients for diagnostics, outside hot paths.
    pub fn to_compiled(&self) -> PackingMatrix {
        let mut m = PackingMatrix::zero(self.rows, self.cols, self.q);
        match &self.words {
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
        out.par_iter_mut().enumerate().for_each(|(r, dst)| {
            *dst = match &self.words {
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
