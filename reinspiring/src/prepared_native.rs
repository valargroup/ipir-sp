//! Immutable file-backed native preprocessing for a separated packing service.
use crate::{
    lift_ntt::{LiftContext, PreparedLiftOperand},
    native::{NativeParams, NativePreprocessed, NativeSetup},
    native_matrix::{NativeMatrix, Words},
    ReinspiringError,
};
use bytemuck::Pod;
use memmap2::Mmap;
use std::{
    io::{self, Write},
    ops::Deref,
    sync::Arc,
};

pub(crate) enum Storage<T: Pod> {
    Owned(Vec<T>),
    Mapped {
        file: Arc<Mmap>,
        start: usize,
        end: usize,
        marker: std::marker::PhantomData<T>,
    },
}
impl<T: Pod> From<Vec<T>> for Storage<T> {
    fn from(x: Vec<T>) -> Self {
        Self::Owned(x)
    }
}
impl<T: Pod> Deref for Storage<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        match self {
            Self::Owned(x) => x,
            Self::Mapped {
                file, start, end, ..
            } => bytemuck::cast_slice(&file[*start..*end]),
        }
    }
}
impl<'a, T: Pod> IntoIterator for &'a Storage<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
fn bad() -> ReinspiringError {
    ReinspiringError::InvalidParams("invalid native prepared artifact".into())
}
fn word(w: &mut impl Write, n: u64) -> io::Result<()> {
    w.write_all(&n.to_le_bytes())
}

/// Write validated preprocessing in a CPU-independent, aligned format.
/// Matrices use signed 32/64-bit words, so readers need no VBMI capability.
pub fn write(w: &mut impl Write, blocks: &[NativePreprocessed]) -> io::Result<()> {
    w.write_all(b"RNMAP001")?;
    word(w, blocks.len() as u64)?;
    for block in blocks {
        w.write_all(&block.id)?;
        for &x in &block.a {
            word(w, x)?;
        }
        // A packed compiler result is converted offline, never on the router.
        let h = block.h.to_compiled();
        let narrow = h
            .data
            .iter()
            .all(|&x| i32::try_from(crate::lift_ntt::centered(x, h.q)).is_ok());
        word(w, if narrow { 4 } else { 8 })?;
        for x in h.data {
            let x = crate::lift_ntt::centered(x, h.q) as i64;
            if narrow {
                w.write_all(&(x as i32).to_le_bytes())?;
            } else {
                w.write_all(&x.to_le_bytes())?;
            }
        }
        word(w, block.leftover.transforms.len() as u64)?;
        word(w, u64::from(block.leftover.sum_fits_two))?;
        for limb in &block.leftover.transforms {
            word(w, limb.len() as u64)?;
            for prime in limb {
                for &x in prime {
                    word(w, x)?;
                }
            }
        }
    }
    Ok(())
}

struct Reader {
    file: Arc<Mmap>,
    at: usize,
}
impl Reader {
    fn take(&mut self, n: usize) -> Result<&[u8], ReinspiringError> {
        let end = self.at.checked_add(n).ok_or_else(bad)?;
        let out = self.file.get(self.at..end).ok_or_else(bad)?;
        self.at = end;
        Ok(out)
    }
    fn word(&mut self) -> Result<u64, ReinspiringError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| bad())?,
        ))
    }
    fn storage<T: Pod>(&mut self, n: usize) -> Result<Storage<T>, ReinspiringError> {
        let start = self.at;
        let bytes = n.checked_mul(std::mem::size_of::<T>()).ok_or_else(bad)?;
        bytemuck::try_cast_slice::<u8, T>(self.take(bytes)?).map_err(|_| bad())?;
        Ok(Storage::Mapped {
            file: self.file.clone(),
            start,
            end: self.at,
            marker: std::marker::PhantomData,
        })
    }
}

/// Read an authenticated immutable mapping. The caller must never mutate its inode.
/// `offset` must be eight-byte aligned. The trusted setup fixes all large shapes.
pub fn read(
    file: Mmap,
    offset: usize,
    setup: &NativeSetup,
    count: usize,
) -> Result<Vec<NativePreprocessed>, ReinspiringError> {
    if !cfg!(target_endian = "little") || offset % 8 != 0 || count == 0 || count > 16 {
        return Err(bad());
    }
    let mut r = Reader {
        file: Arc::new(file),
        at: offset,
    };
    if r.take(8)? != b"RNMAP001" || r.word()? != count as u64 {
        return Err(bad());
    }
    let p: NativeParams = setup.params().clone();
    let d = p.d();
    let q = p.q();
    let ell = p.ell();
    let primes = [4398046568449u64, 4398046666753, 4398046781441];
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let id: [u8; 32] = r.take(32)?.try_into().map_err(|_| bad())?;
        if id != setup.id() {
            return Err(bad());
        }
        let a = (0..d).map(|_| r.word()).collect::<Result<Vec<_>, _>>()?;
        if a.iter().any(|&x| x >= q) {
            return Err(bad());
        }
        let words = match r.word()? {
            4 => Words::Narrow(r.storage::<i32>(d * d * ell)?),
            8 => {
                let x = r.storage::<i64>(d * d * ell)?;
                if x.iter().any(|&x| (x as i128).abs() > q as i128 / 2) {
                    return Err(bad());
                }
                Words::Wide(x)
            }
            _ => return Err(bad()),
        };
        if r.word()? != ell as u64 {
            return Err(bad());
        }
        let sum_fits_two = match r.word()? {
            0 => false,
            1 => true,
            _ => return Err(bad()),
        };
        let mut transforms = Vec::with_capacity(ell);
        for _ in 0..ell {
            let n = r.word()? as usize;
            if !(2..=3).contains(&n) {
                return Err(bad());
            }
            let mut limb = Vec::with_capacity(n);
            for &prime in &primes[..n] {
                let values = (0..d).map(|_| r.word()).collect::<Result<Vec<_>, _>>()?;
                if values.iter().any(|&x| x >= prime) {
                    return Err(bad());
                }
                limb.push(values);
            }
            transforms.push(limb);
        }
        result.push(NativePreprocessed {
            params: p.clone(),
            id,
            a,
            h: NativeMatrix {
                rows: d,
                cols: d * ell,
                q,
                words,
            },
            leftover: PreparedLiftOperand {
                d,
                q,
                transforms,
                sum_fits_two,
            },
            lift: LiftContext::new(d, q)?,
        });
    }
    if r.at != r.file.len() {
        return Err(bad());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{NativeKeys, SecretDistribution};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    fn mapping(bytes: &[u8]) -> Mmap {
        let mut out = memmap2::MmapMut::map_anon(bytes.len()).unwrap();
        out.copy_from_slice(bytes);
        out.make_read_only().unwrap()
    }
    #[test]
    fn mapped_native_matches_owned_and_rejects_corruption() {
        let params = NativeParams::new(8, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
        let setup = NativeSetup::new(params.clone(), [42; 32]);
        let masks = (0..8)
            .map(|r| {
                (0..8)
                    .map(|c| ((r * 29 + c * 41 + 1) as u64 * 123456789) % params.q())
                    .collect()
            })
            .collect::<Vec<Vec<_>>>();
        let pre = NativePreprocessed::build(&setup, &masks).unwrap();
        let mut bytes = Vec::new();
        write(&mut bytes, std::slice::from_ref(&pre)).unwrap();
        let mapped = read(mapping(&bytes), 0, &setup, 1).unwrap();
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let secret = crate::native::NativeSecret::sample(&params, &mut rng);
        let keys = NativeKeys::generate(&setup, &secret, &mut rng).unwrap();
        for value in [0, params.q() - 1, 123456789] {
            let input = vec![value; 8];
            let a = pre.pack(&input, &keys).unwrap();
            let b = mapped[0].pack(&input, &keys).unwrap();
            assert_eq!(a.rows(), b.rows());
        }
        assert!(read(mapping(&bytes), 0, &NativeSetup::new(params, [1; 32]), 1).is_err());
        assert!(read(mapping(&bytes[..bytes.len() - 1]), 0, &setup, 1).is_err());
        bytes.push(0);
        assert!(read(mapping(&bytes), 0, &setup, 1).is_err());
        bytes.pop();
        bytes[0] ^= 1;
        assert!(read(mapping(&bytes), 0, &setup, 1).is_err());
    }
}
