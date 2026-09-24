//! Versioned public packing state. Callers must authenticate the complete file
//! digest and bind it to their published session before serving with this state.
//! Shapes come from trusted parameters, never allocation lengths in the stream.
use crate::{automorph::NttAutomorphTable, QueryPackPreprocessed, RlweParams, TopKeyImages};
use spiral_rs::poly::{PolyMatrix, PolyMatrixNTT};
use std::io::{self, Read, Write};
const MAGIC: &[u8; 16] = b"INSP-PREP-v1\0\0\0\0";
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "incompatible or malformed prepared packing state",
    )
}
fn put(w: &mut impl Write, n: u64) -> io::Result<()> {
    w.write_all(&n.to_le_bytes())
}
fn get(r: &mut impl Read) -> io::Result<u64> {
    let mut b = [0; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
fn header(p: &RlweParams, blocks: usize) -> Vec<u64> {
    let mut v = vec![
        p.d as u64,
        p.q,
        p.p,
        p.gadget.ell as u64,
        p.gadget.bits_per as u64,
        p.spiral.crt_count as u64,
        blocks as u64,
    ];
    v.extend_from_slice(&p.spiral.moduli[..p.spiral.crt_count]);
    v
}
/// Exact format length for caller-validated parameters and block count.
pub fn encoded_len(p: &RlweParams, blocks: usize) -> io::Result<u64> {
    let words = (p.d as u64)
        .checked_mul(p.spiral.crt_count as u64)
        .ok_or_else(invalid)?;
    let polys = (blocks as u64)
        .checked_mul(1 + (p.d as u64 - 1) * p.gadget.ell as u64)
        .and_then(|v| v.checked_add((p.d as u64 - 1) * p.gadget.ell as u64))
        .ok_or_else(invalid)?;
    words
        .checked_mul(polys)
        .and_then(|v| v.checked_add((p.d as u64 - 2) * (p.d as u64 + 1)))
        .and_then(|v| v.checked_add(header(p, blocks).len() as u64))
        .and_then(|v| v.checked_mul(8))
        .and_then(|v| v.checked_add(16))
        .ok_or_else(invalid)
}
fn write_poly(
    w: &mut impl Write,
    p: &RlweParams,
    m: &PolyMatrixNTT<'_>,
    rows: usize,
    cols: usize,
) -> io::Result<()> {
    if m.rows != rows
        || m.cols != cols
        || m.as_slice().len() != rows * cols * p.d * p.spiral.crt_count
    {
        return Err(invalid());
    }
    for (i, &n) in m.as_slice().iter().enumerate() {
        if n >= p.spiral.moduli[(i / p.d) % p.spiral.crt_count] {
            return Err(invalid());
        }
        put(w, n)?;
    }
    Ok(())
}
fn read_poly<'a>(
    r: &mut impl Read,
    p: &'a RlweParams,
    rows: usize,
    cols: usize,
) -> io::Result<PolyMatrixNTT<'a>> {
    let mut m = PolyMatrixNTT::zero(&p.spiral, rows, cols);
    for (i, n) in m.as_mut_slice().iter_mut().enumerate() {
        *n = get(r)?;
        if *n >= p.spiral.moduli[(i / p.d) % p.spiral.crt_count] {
            return Err(invalid());
        }
    }
    Ok(m)
}
/// Write complete public state. No client packing keys or secret material enter this format.
pub fn write(
    w: &mut impl Write,
    p: &RlweParams,
    blocks: &[QueryPackPreprocessed<'_>],
    top: &TopKeyImages<'_>,
) -> io::Result<()> {
    top.validate(p).map_err(|_| invalid())?;
    w.write_all(MAGIC)?;
    for n in header(p, blocks.len()) {
        put(w, n)?;
    }
    for b in blocks {
        if b.digits_ntt.len() != p.d - 1 {
            return Err(invalid());
        }
        write_poly(w, p, &b.collapse_a_final_ntt, 1, 1)?;
        for m in &b.digits_ntt {
            write_poly(w, p, m, p.gadget.ell, 1)?;
        }
    }
    for m in top
        .kg_top_left
        .iter()
        .chain(&top.kg_top_right)
        .chain(std::iter::once(&top.kh_top))
    {
        write_poly(w, p, m, 1, p.gadget.ell)?;
    }
    for t in top
        .kg_body_left_tables
        .iter()
        .chain(&top.kg_body_right_tables)
    {
        if !t.validate_permutation(p.d) {
            return Err(invalid());
        }
        put(w, t.exponent())?;
        for &i in t.indices() {
            put(w, i as u64)?;
        }
    }
    Ok(())
}
/// Load without NTT, CRS preprocessing, or top-key image construction. The caller
/// supplies trusted dimensions and must verify file digest/session identity.
pub fn read<'a>(
    r: &mut impl Read,
    p: &'a RlweParams,
    blocks: usize,
) -> io::Result<(Vec<QueryPackPreprocessed<'a>>, TopKeyImages<'a>)> {
    let mut magic = [0; 16];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(invalid());
    }
    for n in header(p, blocks) {
        if get(r)? != n {
            return Err(invalid());
        }
    }
    let mut pre = Vec::with_capacity(blocks);
    for _ in 0..blocks {
        let collapse_a_final_ntt = read_poly(r, p, 1, 1)?;
        let mut digits_ntt = Vec::with_capacity(p.d - 1);
        for _ in 0..p.d - 1 {
            digits_ntt.push(read_poly(r, p, p.gadget.ell, 1)?);
        }
        pre.push(QueryPackPreprocessed {
            params: p,
            collapse_a_final_ntt,
            digits_ntt,
        });
    }
    let mut images = || -> io::Result<Vec<PolyMatrixNTT<'a>>> {
        (0..p.d / 2 - 1)
            .map(|_| read_poly(r, p, 1, p.gadget.ell))
            .collect()
    };
    let kg_top_left = images()?;
    let kg_top_right = images()?;
    let kh_top = read_poly(r, p, 1, p.gadget.ell)?;
    let mut tables = || -> io::Result<Vec<NttAutomorphTable>> {
        (0..p.d / 2 - 1)
            .map(|_| {
                let exponent = get(r)?;
                if exponent >= 2 * p.d as u64 || exponent % 2 == 0 {
                    return Err(invalid());
                }
                let indices = (0..p.d)
                    .map(|_| u32::try_from(get(r)?).map_err(|_| invalid()))
                    .collect::<io::Result<Vec<_>>>()?;
                NttAutomorphTable::from_prepared(exponent, indices.into_boxed_slice(), p.d)
                    .ok_or_else(invalid)
            })
            .collect()
    };
    let kg_body_left_tables = tables()?;
    let kg_body_right_tables = tables()?;
    let top = TopKeyImages {
        kg_top_left,
        kg_top_right,
        kh_top,
        kg_body_left_tables,
        kg_body_right_tables,
    };
    top.validate(p).map_err(|_| invalid())?;
    let mut trailing = [0];
    if r.read(&mut trailing)? != 0 {
        return Err(invalid());
    }
    Ok((pre, top))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{params::GadgetParams, preprocess::PackingKeys};
    use spiral_rs::poly::{to_ntt_alloc, PolyMatrixRaw};
    #[test]
    fn round_trip_and_malformed_state() {
        let p = RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 3,
                ell: 5,
            },
        )
        .unwrap();
        let mut raw = PolyMatrixRaw::zero(&p.spiral, p.d, 1);
        for (i, n) in raw.as_mut_slice().iter_mut().enumerate() {
            *n = (i as u64 + 1) % p.q;
        }
        let pre = QueryPackPreprocessed::build(&p, &to_ntt_alloc(&raw)).unwrap();
        let top = TopKeyImages::build(&p);
        let keys = PackingKeys {
            kg_body: PolyMatrixNTT::zero(&p.spiral, 1, p.gadget.ell),
            kh_body: PolyMatrixNTT::zero(&p.spiral, 1, p.gadget.ell),
        };
        let values = vec![3; p.d];
        let expected = pre.pack_b(&values, &keys, &top).unwrap();
        let mut bytes = Vec::new();
        write(&mut bytes, &p, &[pre], &top).unwrap();
        assert_eq!(bytes.len() as u64, encoded_len(&p, 1).unwrap());
        let (loaded, images) = read(&mut bytes.as_slice(), &p, 1).unwrap();
        let actual = loaded[0].pack_b(&values, &keys, &images).unwrap();
        assert_eq!(expected.inner.as_slice(), actual.inner.as_slice());
        let mut copy = Vec::new();
        write(&mut copy, &p, &loaded, &images).unwrap();
        assert_eq!(bytes, copy);
        for n in [0, 16, 72, bytes.len() - 1] {
            assert!(read(&mut &bytes[..n], &p, 1).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(read(&mut extra.as_slice(), &p, 1).is_err());
        assert!(read(&mut bytes.as_slice(), &p, 2).is_err());
        for offset in [0, 16, 72, bytes.len() - 8] {
            let mut bad = bytes.clone();
            bad[offset..offset + 8].fill(255);
            assert!(read(&mut bad.as_slice(), &p, 1).is_err());
        }
    }
}
