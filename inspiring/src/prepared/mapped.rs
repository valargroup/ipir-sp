//! Immutable file-backed public matrices. Only the compact permutation tables
//! and offsets are owned; digit/top matrices are never copied onto the heap.
use super::*;
use crate::{
    pack::RlweCiphertext,
    preprocess::{mapped_accumulator_supported, pack_mapped_block, DigitView},
    PackingKeys,
};
use rayon::prelude::*;
use std::{io::Cursor, ops::Range};

struct Block {
    c1: Range<usize>,
    digits: Vec<Range<usize>>,
}

/// Validated public packing state backed by an immutable mapping.
pub struct MappedPrepared<'a> {
    map: memmap2::Mmap,
    params: &'a RlweParams,
    prefix: usize,
    blocks: Vec<Block>,
    left: Vec<NttAutomorphTable>,
    right: Vec<NttAutomorphTable>,
}

/// All u64 patterns are valid; reject unaligned and non-native-endian storage.
fn words(bytes: &[u8]) -> io::Result<&[u64]> {
    if !cfg!(target_endian = "little") {
        return Err(invalid());
    }
    bytemuck::try_cast_slice(bytes).map_err(|_| invalid())
}

impl<'a> MappedPrepared<'a> {
    /// Map a complete, authenticated v1 artifact after a caller-defined prefix.
    /// Shapes and every residue/permutation are validated before returning.
    ///
    /// The caller must authenticate the complete mapping and bind its prefix
    /// to the published session. The immutable-inode safety contract of Mmap
    /// continues to apply while this object owns it.
    pub fn new(
        map: memmap2::Mmap,
        params: &'a RlweParams,
        blocks: usize,
        prefix: usize,
    ) -> io::Result<Self> {
        if !mapped_accumulator_supported(params) {
            return Err(invalid());
        }
        let expected = encoded_len(params, blocks)?
            .checked_add(prefix as u64)
            .ok_or_else(invalid)?;
        if map.len() as u64 != expected {
            return Err(invalid());
        }
        let bytes = map.get(prefix..).ok_or_else(invalid)?;
        let mut cursor = Cursor::new(bytes);
        let mut magic = [0; 16];
        cursor.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(invalid());
        }
        for n in header(params, blocks) {
            if get(&mut cursor)? != n {
                return Err(invalid());
            }
        }
        let lanes = params
            .d
            .checked_mul(params.spiral.crt_count)
            .ok_or_else(invalid)?;
        let mut poly = |rows: usize, cols: usize| -> io::Result<Range<usize>> {
            let len = rows
                .checked_mul(cols)
                .and_then(|n| n.checked_mul(lanes))
                .and_then(|n| n.checked_mul(8))
                .ok_or_else(invalid)?;
            let start = usize::try_from(cursor.position()).map_err(|_| invalid())?;
            let end = start.checked_add(len).ok_or_else(invalid)?;
            let data = words(bytes.get(start..end).ok_or_else(invalid)?)?;
            for (i, &n) in data.iter().enumerate() {
                if n >= params.spiral.moduli[(i / params.d) % params.spiral.crt_count] {
                    return Err(invalid());
                }
            }
            cursor.set_position(end as u64);
            Ok(prefix + start..prefix + end)
        };
        let mut layout = Vec::with_capacity(blocks);
        for _ in 0..blocks {
            let c1 = poly(1, 1)?;
            let digits = (0..params.d - 1)
                .map(|_| poly(params.gadget.ell, 1))
                .collect::<io::Result<Vec<_>>>()?;
            layout.push(Block { c1, digits });
        }
        // Top matrices are authenticated and checked for canonical residues,
        // but the fused online kernel only needs their permutation tables.
        for _ in 0..params.d - 1 {
            poly(1, params.gadget.ell)?;
        }
        let mut tables = || -> io::Result<Vec<NttAutomorphTable>> {
            (0..params.d / 2 - 1)
                .map(|_| {
                    let exponent = get(&mut cursor)?;
                    if exponent >= 2 * params.d as u64 || exponent % 2 == 0 {
                        return Err(invalid());
                    }
                    let indices = (0..params.d)
                        .map(|_| u32::try_from(get(&mut cursor)?).map_err(|_| invalid()))
                        .collect::<io::Result<Vec<_>>>()?;
                    NttAutomorphTable::from_prepared(exponent, indices.into_boxed_slice(), params.d)
                        .ok_or_else(invalid)
                })
                .collect()
        };
        let left = tables()?;
        let right = tables()?;
        if cursor.position() as usize != bytes.len() {
            return Err(invalid());
        }
        Ok(Self {
            map,
            params,
            prefix,
            blocks: layout,
            left,
            right,
        })
    }
    /// Caller-defined bytes preceding the prepared stream.
    pub fn prefix(&self) -> &[u8] {
        &self.map[..self.prefix]
    }
    /// Total mapped bytes, including the caller-defined prefix.
    pub fn mapped_bytes(&self) -> usize {
        self.map.len()
    }

    /// Pack using authenticated public slices and the existing fused kernel.
    pub fn pack(
        &self,
        intermediate: &[u64],
        keys: &PackingKeys<'a>,
    ) -> Result<Vec<RlweCiphertext<'a>>, crate::error::InspiringError> {
        use crate::error::InspiringError;
        if intermediate.len() != self.blocks.len() * self.params.d
            || intermediate.iter().any(|&n| n >= self.params.q)
        {
            return Err(InspiringError::LweShape(
                "invalid mapped packing intermediate".into(),
            ));
        }
        keys.validate(self.params)?;
        for body in [&keys.kg_body, &keys.kh_body] {
            let expected = self.params.gadget.ell * self.params.d * self.params.spiral.crt_count;
            if body.as_slice().len() != expected
                || body.as_slice().iter().enumerate().any(|(i, &n)| {
                    n >= self.params.spiral.moduli
                        [(i / self.params.d) % self.params.spiral.crt_count]
                })
            {
                return Err(InspiringError::PreprocessMismatch(
                    "noncanonical mapped packing key".into(),
                ));
            }
        }

        let lanes = self.params.d * self.params.spiral.crt_count;
        self.blocks
            .par_iter()
            .zip(intermediate.par_chunks_exact(self.params.d))
            .map(|(block, b)| {
                // Constructor checked all ranges, alignment and residues. The mmap
                // is immutable and owned for this entire call, including Rayon tasks.
                let digits: Vec<_> = block
                    .digits
                    .iter()
                    .map(|r| {
                        DigitView::new(
                            words(&self.map[r.clone()]).expect("validated mapped digits"),
                            self.params.gadget.ell,
                            lanes,
                        )
                    })
                    .collect();
                Ok(pack_mapped_block(
                    self.params,
                    b,
                    keys,
                    &self.left,
                    &self.right,
                    &digits,
                    words(&self.map[block.c1.clone()]).expect("validated mapped c1"),
                ))
            })
            .collect()
    }
}
