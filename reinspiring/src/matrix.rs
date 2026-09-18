//! Packing matrix `H'` storage and matvec.
//!
//! Entries are native `u64` words (SPEC.md §9); we do not bit-pack.

use rayon::prelude::*;

use crate::error::ReinspiringError;

/// Row-major `d × (ℓ · d)` packing matrix over `Z_q`.
#[derive(Clone, Debug)]
pub struct PackingMatrix {
    /// Rows (= `d`).
    pub rows: usize,
    /// Columns (= `ℓ · d`).
    pub cols: usize,
    /// Modulus.
    pub q: u64,
    /// Row-major entries in `[0, q)`.
    pub data: Vec<u64>,
}

impl PackingMatrix {
    /// Allocate a zero matrix.
    #[must_use]
    pub fn zero(rows: usize, cols: usize, q: u64) -> Self {
        Self {
            rows,
            cols,
            q,
            data: vec![0; rows * cols],
        }
    }

    /// Element at `(r, c)`.
    #[must_use]
    pub fn get(&self, r: usize, c: usize) -> u64 {
        self.data[r * self.cols + c]
    }

    /// Mutable element at `(r, c)`.
    pub fn get_mut(&mut self, r: usize, c: usize) -> &mut u64 {
        &mut self.data[r * self.cols + c]
    }

    /// Infinity norm (max centered absolute value).
    #[must_use]
    pub fn infinity_norm_centered(&self) -> u64 {
        let half = self.q / 2;
        self.data
            .iter()
            .map(|&x| {
                let c = x % self.q;
                if c > half {
                    self.q - c
                } else {
                    c
                }
            })
            .max()
            .unwrap_or(0)
    }

    /// `out = self · v mod q` with `v.len() == cols`, `out.len() == rows`.
    pub fn matvec(&self, v: &[u64], out: &mut [u64]) -> Result<(), ReinspiringError> {
        if v.len() != self.cols {
            return Err(ReinspiringError::LweShape(format!(
                "matvec expected {} entries, got {}",
                self.cols,
                v.len()
            )));
        }
        if out.len() != self.rows {
            return Err(ReinspiringError::LweShape(format!(
                "matvec output expected {} entries, got {}",
                self.rows,
                out.len()
            )));
        }
        let q = self.q;
        let cols = self.cols;
        out.par_iter_mut()
            .enumerate()
            .for_each(|(r, slot)| {
                let row = &self.data[r * cols..(r + 1) * cols];
                let mut acc = 0_u128;
                for (a, &b) in row.iter().zip(v.iter()) {
                    acc += u128::from(*a) * u128::from(b % q);
                }
                *slot = (acc % u128::from(q)) as u64;
            });
        Ok(())
    }

    /// Horizontal concatenation of square `d × d` blocks.
    pub fn hstack(blocks: &[PackingMatrix]) -> Result<Self, ReinspiringError> {
        if blocks.is_empty() {
            return Err(ReinspiringError::InvalidParams(
                "hstack requires at least one block".into(),
            ));
        }
        let rows = blocks[0].rows;
        let q = blocks[0].q;
        let mut cols = 0usize;
        for b in blocks {
            if b.rows != rows || b.q != q {
                return Err(ReinspiringError::PreprocessMismatch(
                    "hstack block shape/modulus mismatch".into(),
                ));
            }
            if b.cols != rows {
                return Err(ReinspiringError::PreprocessMismatch(
                    "hstack expects square d×d blocks".into(),
                ));
            }
            cols += b.cols;
        }
        let mut out = Self::zero(rows, cols, q);
        let mut col_base = 0usize;
        for b in blocks {
            for r in 0..rows {
                for c in 0..b.cols {
                    *out.get_mut(r, col_base + c) = b.get(r, c);
                }
            }
            col_base += b.cols;
        }
        Ok(out)
    }
}
