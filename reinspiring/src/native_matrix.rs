//! Compact signed matrix storage for the power-of-two online kernel.
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
        if !m.q.is_power_of_two()
            || m.q > 1 << 56
            || m.q < 2
            || m.rows == 0
            || m.cols == 0
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
    /// Multiply using the current Rayon pool. Integer wrapping is exact mod 2^k.
    pub fn multiply(&self, y: &[u64]) -> Result<Vec<u64>, ReinspiringError> {
        if y.len() != self.cols || y.iter().any(|&x| x >= self.q) {
            return Err(ReinspiringError::LweShape(
                "invalid native matrix operand".into(),
            ));
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
}
