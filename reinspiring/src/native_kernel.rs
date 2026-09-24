//! Low-word dot products. Wrapping modulo 2^64 is exact before reduction mod 2^k.
#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

/// Query decomposition shared by every database column. Signed radix-256 digits
/// allow exact byte dot products with AVX-512 VNNI; no query precision is lost.
/// The result remains an integer product modulo the validated power-of-two q.
pub struct PreparedU16Query {
    words: Vec<u64>,
    #[cfg(target_arch = "x86_64")]
    digits: Vec<Vec<i8>>,
    mask: u64,
}
impl PreparedU16Query {
    /// Validate q=2^k, 1<=k<=56 and canonical query words before preprocessing.
    pub fn new(words: &[u64], q: u64) -> Result<Self, crate::ReinspiringError> {
        if !q.is_power_of_two() || !(2..=1u64 << 56).contains(&q) || words.iter().any(|&x| x >= q) {
            return Err(crate::ReinspiringError::InvalidParams(
                "invalid native dot query".into(),
            ));
        }
        #[cfg(target_arch = "x86_64")]
        let mut digits = Vec::new();
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("avx512vnni")
            && std::is_x86_feature_detected!("avx512bw")
            && std::is_x86_feature_detected!("avx512dq")
            && std::is_x86_feature_detected!("avx512f")
        {
            digits = vec![vec![0; words.len()]; (q.trailing_zeros() as usize).div_ceil(8)];
            for (i, &x) in words.iter().enumerate() {
                let mut x = x;
                for digit in &mut digits {
                    digit[i] = x as u8 as i8;
                    x = (x + 128) >> 8;
                }
            }
        }
        Ok(Self {
            words: words.to_vec(),
            #[cfg(target_arch = "x86_64")]
            digits,
            mask: q - 1,
        })
    }
    /// Dot one equally sized database column, including non-vector tails.
    pub fn dot(&self, column: &[u16]) -> u64 {
        assert_eq!(column.len(), self.words.len());
        self.dot_range(column, 0)
    }
    /// Whether this process supports the interleaved byte kernel.
    pub fn supports_interleaved() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            std::is_x86_feature_detected!("avx512vnni")
                && std::is_x86_feature_detected!("avx512bw")
                && std::is_x86_feature_detected!("avx512dq")
                && std::is_x86_feature_detected!("avx512f")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }
    /// Offline conversion of whole 16-column bands into byte-plane tiles.
    /// A tile contains four rows of each column: first their 64 low bytes, then
    /// their 64 high bytes, stored as little-endian pairs in u16 words. The
    /// storage remains exactly two bytes per database element.
    pub fn interleave_columns(db: &mut [u16], rows: usize) {
        assert!(rows > 0 && rows % 4 == 0 && db.len() % (rows * 16) == 0);
        for band in db.chunks_exact_mut(rows * 16) {
            let mut scratch = vec![0; band.len()];
            for row in (0..rows).step_by(4) {
                for col in 0..16 {
                    for pair in 0..2 {
                        let x = band[col * rows + row + 2 * pair];
                        let y = band[col * rows + row + 2 * pair + 1];
                        scratch[row * 16 + col * 2 + pair] = (x & 255) | ((y & 255) << 8);
                        scratch[row * 16 + 32 + col * 2 + pair] = (x >> 8) | (y & 0xff00);
                    }
                }
            }
            band.copy_from_slice(&scratch);
        }
    }
    /// Multiply interleaved 16-column bands, with bounded i32 byte accumulators.
    pub fn multiply_interleaved(&self, db: &[u16], out: &mut [u64]) {
        let rows = self.words.len();
        assert!(rows > 0 && rows % 4 == 0 && out.len() % 16 == 0);
        assert_eq!(db.len(), rows.checked_mul(out.len()).expect("matrix size"));
        for (band, out) in db.chunks_exact(rows * 16).zip(out.chunks_exact_mut(16)) {
            #[cfg(target_arch = "x86_64")]
            if !self.digits.is_empty() {
                // SAFETY: constructor checks SIMD features and digit lengths;
                // shape checks above guarantee complete 4-row/16-column tiles.
                unsafe {
                    x86::interleaved_vnni(band, &self.digits, out, self.mask);
                }
                continue;
            }
            out.fill(0);
            for row in (0..rows).step_by(4) {
                for (col, dst) in out.iter_mut().enumerate() {
                    for k in 0..4 {
                        let lane = col * 4 + k;
                        let lo = (band[row * 16 + lane / 2] >> ((lane % 2) * 8)) & 255;
                        let hi = (band[row * 16 + 32 + lane / 2] >> ((lane % 2) * 8)) & 255;
                        let value = lo | (hi << 8);
                        *dst = dst.wrapping_add((value as u64).wrapping_mul(self.words[row + k]));
                    }
                }
            }
            for x in out {
                *x &= self.mask;
            }
        }
    }
    fn dot_range(&self, column: &[u16], offset: usize) -> u64 {
        let words = &self.words[offset..offset + column.len()];
        #[cfg(target_arch = "x86_64")]
        if !self.digits.is_empty() {
            // SAFETY: the checked constructor verifies CPU features and limb
            // lengths; private callers keep offset+column.len() within words.
            return unsafe {
                match self.digits.len() {
                    1 => x86::u16_dot_vnni::<1>(column, words, &self.digits, offset),
                    2 => x86::u16_dot_vnni::<2>(column, words, &self.digits, offset),
                    3 => x86::u16_dot_vnni::<3>(column, words, &self.digits, offset),
                    4 => x86::u16_dot_vnni::<4>(column, words, &self.digits, offset),
                    5 => x86::u16_dot_vnni::<5>(column, words, &self.digits, offset),
                    6 => x86::u16_dot_vnni::<6>(column, words, &self.digits, offset),
                    7 => x86::u16_dot_vnni::<7>(column, words, &self.digits, offset),
                    _ => unreachable!("validated byte limb count"),
                }
            } & self.mask;
        }
        dot_u16(column, words) & self.mask
    }
}

/// Runtime-dispatched u16-by-u64 dot product, including all tail elements.
/// The result is the low 64 bits of the integer sum; callers reduce mod 2^k.
pub fn dot_u16(a: &[u16], b: &[u64]) -> u64 {
    assert_eq!(a.len(), b.len());
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512dq") {
        // SAFETY: features detected; equal slices and whole-vector loads.
        return unsafe { x86::u16_dot_512(a, b) };
    }
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        // SAFETY: feature detected, equal-length slices, kernel loads whole groups.
        return unsafe { x86::u16_dot(a, b) };
    }
    a.iter().zip(b).fold(0u64, |s, (&a, &b)| {
        s.wrapping_add((a as u64).wrapping_mul(b))
    })
}
pub(crate) fn dot_i32(a: &[i32], b: &[u64]) -> u64 {
    assert_eq!(a.len(), b.len());
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512dq") {
        // SAFETY: features detected; equal slices and whole-vector loads.
        return unsafe { x86::i32_dot_512(a, b) };
    }
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        // SAFETY: feature detected, equal-length slices, kernel loads whole groups.
        return unsafe { x86::i32_dot(a, b) };
    }
    scalar_i32(a, b)
}
fn scalar_i32(a: &[i32], b: &[u64]) -> u64 {
    a.iter().zip(b).fold(0u64, |s, (&a, &b)| {
        s.wrapping_add((a as i64 as u64).wrapping_mul(b))
    })
}
#[cfg(target_arch = "x86_64")]
mod x86 {
    use std::arch::x86_64::*;
    #[target_feature(enable = "avx512f,avx512dq,avx512bw,avx512vnni")]
    pub(super) unsafe fn interleaved_vnni(
        db: &[u16],
        digits: &[Vec<i8>],
        out: &mut [u64],
        mask: u64,
    ) {
        // Specialize limb count so LLVM keeps the accumulators in registers.
        macro_rules! call {
            ($n:expr) => {
                unsafe { interleaved_inner::<$n>(db, digits, out, mask) }
            };
        }
        match digits.len() {
            1 => call!(1),
            2 => call!(2),
            3 => call!(3),
            4 => call!(4),
            5 => call!(5),
            6 => call!(6),
            7 => call!(7),
            _ => unreachable!(),
        }
    }
    #[target_feature(enable = "avx512f,avx512dq,avx512bw,avx512vnni")]
    unsafe fn interleaved_inner<const L: usize>(
        db: &[u16],
        digits: &[Vec<i8>],
        out: &mut [u64],
        mask: u64,
    ) {
        out.fill(0);
        let rows = db.len() / 16;
        for start in (0..rows).step_by(65536) {
            let end = (start + 65536).min(rows);
            let mut low = [_mm512_setzero_si512(); L];
            let mut high = [_mm512_setzero_si512(); L];
            for row in (start..end).step_by(4) {
                // SAFETY: validated whole tiles and digit lengths; unaligned loads.
                unsafe {
                    // Prepacked byte planes avoid shifts/conversions in the scan.
                    let lo = _mm512_loadu_si512(db.as_ptr().add(row * 16).cast());
                    let hi = _mm512_loadu_si512(db.as_ptr().add(row * 16 + 32).cast());
                    for j in 0..L {
                        let y = _mm512_set1_epi32(
                            digits[j].as_ptr().add(row).cast::<i32>().read_unaligned(),
                        );
                        low[j] = _mm512_dpbusd_epi32(low[j], lo, y);
                        // This term has weight 2^(8*L), which vanishes modulo q.
                        if j + 1 < L {
                            high[j] = _mm512_dpbusd_epi32(high[j], hi, y);
                        }
                    }
                }
            }
            // Each lane sums at most 65536*255*128 < 2^31 in magnitude.
            for j in 0..L {
                let mut low_words = [0i32; 16];
                let mut high_words = [0i32; 16];
                // SAFETY: each output array holds exactly one vector.
                unsafe {
                    _mm512_storeu_si512(low_words.as_mut_ptr().cast(), low[j]);
                    _mm512_storeu_si512(high_words.as_mut_ptr().cast(), high[j]);
                }
                for col in 0..16 {
                    out[col] = out[col].wrapping_add((low_words[col] as i64 as u64) << (8 * j));
                    if j + 1 < L {
                        out[col] =
                            out[col].wrapping_add((high_words[col] as i64 as u64) << (8 * j + 8));
                    }
                }
            }
        }
        for x in out {
            *x &= mask;
        }
    }
    #[target_feature(enable = "avx512f,avx512dq,avx512bw,avx512vnni")]
    pub(super) unsafe fn u16_dot_vnni<const L: usize>(
        a: &[u16],
        b: &[u64],
        digits: &[Vec<i8>],
        offset: usize,
    ) -> u64 {
        let end = a.len() / 64 * 64;
        let mut result = 0u64;
        // Each i32 lane accumulates at most 65536/16 byte products of magnitude
        // 255*128, below 2^27. There is no saturation or intermediate overflow.
        for start in (0..end).step_by(65536) {
            let stop = (start + 65536).min(end);
            let mut low = [_mm512_setzero_si512(); L];
            let mut high = [_mm512_setzero_si512(); L];
            for i in (start..stop).step_by(64) {
                // SAFETY: whole 64-element groups in equally sized slices.
                unsafe {
                    let x0 = _mm512_loadu_si512(a.as_ptr().add(i).cast());
                    let x1 = _mm512_loadu_si512(a.as_ptr().add(i + 32).cast());
                    let lo = _mm512_inserti64x4::<1>(
                        _mm512_castsi256_si512(_mm512_cvtepi16_epi8(x0)),
                        _mm512_cvtepi16_epi8(x1),
                    );
                    let hi = _mm512_inserti64x4::<1>(
                        _mm512_castsi256_si512(_mm512_cvtepi16_epi8(_mm512_srli_epi16::<8>(x0))),
                        _mm512_cvtepi16_epi8(_mm512_srli_epi16::<8>(x1)),
                    );
                    for j in 0..L {
                        let y = _mm512_loadu_si512(digits[j].as_ptr().add(offset + i).cast());
                        low[j] = _mm512_dpbusd_epi32(low[j], lo, y);
                        high[j] = _mm512_dpbusd_epi32(high[j], hi, y);
                    }
                }
            }
            for j in 0..L {
                // Even the sum over ALL lanes fits i32: at most
                // 65536*255*128 = 2^31-2^23 in absolute value.
                let l = _mm512_reduce_add_epi32(low[j]) as i64 as u64;
                let h = _mm512_reduce_add_epi32(high[j]) as i64 as u64;
                result = result
                    .wrapping_add(l.wrapping_shl((8 * j) as u32))
                    .wrapping_add(h.wrapping_shl((8 * j + 8) as u32));
            }
        }
        a[end..].iter().zip(&b[end..]).fold(result, |s, (&x, &y)| {
            s.wrapping_add((x as u64).wrapping_mul(y))
        })
    }
    #[target_feature(enable = "avx512f,avx512dq")]
    pub(super) unsafe fn i32_dot_512(a: &[i32], b: &[u64]) -> u64 {
        let end = a.len() / 32 * 32;
        let mut sums = [_mm512_setzero_si512(); 4];
        for i in (0..end).step_by(32) {
            for (j, sum) in sums.iter_mut().enumerate() {
                // SAFETY: i+32<=both lengths, and unaligned loads are allowed.
                unsafe {
                    let x =
                        _mm512_cvtepi32_epi64(_mm256_loadu_si256(a.as_ptr().add(i + j * 8).cast()));
                    let y = _mm512_loadu_si512(b.as_ptr().add(i + j * 8).cast());
                    *sum = _mm512_add_epi64(*sum, _mm512_mullo_epi64(x, y));
                }
            }
        }
        let sum = _mm512_add_epi64(
            _mm512_add_epi64(sums[0], sums[1]),
            _mm512_add_epi64(sums[2], sums[3]),
        );
        let mut words = [0u64; 8];
        // SAFETY: output holds exactly one vector.
        unsafe {
            _mm512_storeu_si512(words.as_mut_ptr().cast(), sum);
        }
        let tail = a[end..].iter().zip(&b[end..]).fold(0u64, |s, (&x, &y)| {
            s.wrapping_add((x as i64 as u64).wrapping_mul(y))
        });
        words.into_iter().fold(tail, u64::wrapping_add)
    }
    #[target_feature(enable = "avx512f,avx512dq")]
    pub(super) unsafe fn u16_dot_512(a: &[u16], b: &[u64]) -> u64 {
        let end = a.len() / 32 * 32;
        let mut sums = [_mm512_setzero_si512(); 4];
        for i in (0..end).step_by(32) {
            for (j, sum) in sums.iter_mut().enumerate() {
                // SAFETY: i+32<=both lengths, and unaligned loads are allowed.
                unsafe {
                    let x =
                        _mm512_cvtepu16_epi64(_mm_loadu_si128(a.as_ptr().add(i + j * 8).cast()));
                    let y = _mm512_loadu_si512(b.as_ptr().add(i + j * 8).cast());
                    *sum = _mm512_add_epi64(*sum, _mm512_mullo_epi64(x, y));
                }
            }
        }
        let sum = _mm512_add_epi64(
            _mm512_add_epi64(sums[0], sums[1]),
            _mm512_add_epi64(sums[2], sums[3]),
        );
        let mut words = [0u64; 8];
        // SAFETY: output holds exactly one vector.
        unsafe {
            _mm512_storeu_si512(words.as_mut_ptr().cast(), sum);
        }
        let tail = a[end..].iter().zip(&b[end..]).fold(0u64, |s, (&x, &y)| {
            s.wrapping_add((x as i64 as u64).wrapping_mul(y))
        });
        words.into_iter().fold(tail, u64::wrapping_add)
    }
    #[target_feature(enable = "avx2")]
    unsafe fn mul64(a: __m256i, b: __m256i) -> __m256i {
        let low = _mm256_mul_epu32(a, b);
        let cross = _mm256_add_epi64(
            _mm256_mul_epu32(_mm256_srli_epi64::<32>(a), b),
            _mm256_mul_epu32(a, _mm256_srli_epi64::<32>(b)),
        );
        _mm256_add_epi64(low, _mm256_slli_epi64::<32>(cross))
    }
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn i32_dot(a: &[i32], b: &[u64]) -> u64 {
        let end = a.len() / 4 * 4;
        let mut sum = _mm256_setzero_si256();
        for i in (0..end).step_by(4) {
            // SAFETY: i+4<=end<=both lengths; loads are unaligned.
            unsafe {
                let x = _mm256_cvtepi32_epi64(_mm_loadu_si128(a.as_ptr().add(i).cast()));
                let y = _mm256_loadu_si256(b.as_ptr().add(i).cast());
                sum = _mm256_add_epi64(sum, mul64(x, y));
            }
        }
        let mut words = [0u64; 4];
        // SAFETY: output contains exactly 32 writable bytes.
        unsafe {
            _mm256_storeu_si256(words.as_mut_ptr().cast(), sum);
        }
        words
            .into_iter()
            .fold(super::scalar_i32(&a[end..], &b[end..]), u64::wrapping_add)
    }
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn u16_dot(a: &[u16], b: &[u64]) -> u64 {
        let end = a.len() / 4 * 4;
        let mut sum = _mm256_setzero_si256();
        for i in (0..end).step_by(4) {
            // SAFETY: four u16 and four u64 words remain in the slices.
            unsafe {
                let x = _mm256_cvtepu16_epi64(_mm_loadl_epi64(a.as_ptr().add(i).cast()));
                let y = _mm256_loadu_si256(b.as_ptr().add(i).cast());
                sum = _mm256_add_epi64(sum, mul64(x, y));
            }
        }
        let mut words = [0u64; 4];
        // SAFETY: output contains exactly 32 writable bytes.
        unsafe {
            _mm256_storeu_si256(words.as_mut_ptr().cast(), sum);
        }
        let tail = a[end..].iter().zip(&b[end..]).fold(0u64, |s, (&a, &b)| {
            s.wrapping_add((a as u64).wrapping_mul(b))
        });
        words.into_iter().fold(tail, u64::wrapping_add)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_byte_dot_is_exact_with_carries_full_u16_chunks_and_tails() {
        let mut state = 12345u64;
        for bits in [1, 8, 9, 16, 24, 32, 40, 48, 49, 54, 56] {
            let q = 1u64 << bits;
            for n in [0, 1, 63, 64, 65, 127, 128, 137, 65535, 65536, 65537] {
                let mut a = Vec::with_capacity(n);
                let mut b = Vec::with_capacity(n);
                for i in 0..n {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    a.push(if i % 3 == 0 { u16::MAX } else { state as u16 });
                    b.push(match i % 5 {
                        0 => q - 1,
                        1 => q / 2,
                        2 => 0x80808080808080 & (q - 1),
                        _ => state & (q - 1),
                    });
                }
                let expected = a.iter().zip(&b).fold(0u64, |s, (&x, &y)| {
                    s.wrapping_add((x as u64).wrapping_mul(y))
                }) & (q - 1);
                assert_eq!(
                    PreparedU16Query::new(&b, q).unwrap().dot(&a),
                    expected,
                    "bits={bits} n={n}"
                );
            }
        }
        assert!(PreparedU16Query::new(&[], 1).is_err());
        assert!(PreparedU16Query::new(&[], 3).is_err());
        assert!(PreparedU16Query::new(&[], 1 << 57).is_err());
        assert!(PreparedU16Query::new(&[256], 256).is_err());
    }
    #[test]
    fn interleaved_matrix_matches_independent_scalar_across_accumulator_windows() {
        for bits in [8, 16, 54, 56] {
            let q = 1u64 << bits;
            for rows in [4, 68, 2052, 65540] {
                let cols = 32;
                let query: Vec<_> = (0..rows)
                    .map(|i| [q - 1, 0x80808080808080 & (q - 1), 0, q / 2][i % 4])
                    .collect();
                let mut db: Vec<_> = (0..rows * cols)
                    .map(|i| {
                        if i % 3 == 0 {
                            u16::MAX
                        } else {
                            (i as u16).wrapping_mul(173)
                        }
                    })
                    .collect();
                let expected: Vec<_> = db
                    .chunks_exact(rows)
                    .map(|c| {
                        c.iter().zip(&query).fold(0u64, |s, (&a, &b)| {
                            s.wrapping_add((a as u64).wrapping_mul(b))
                        }) & (q - 1)
                    })
                    .collect();
                PreparedU16Query::interleave_columns(&mut db, rows);
                let mut out = vec![0; cols];
                PreparedU16Query::new(&query, q)
                    .unwrap()
                    .multiply_interleaved(&db, &mut out);
                assert_eq!(out, expected, "bits={bits}, rows={rows}");
            }
        }
    }
    #[test]
    fn dispatched_kernels_match_scalar_with_signs_overflow_and_tails() {
        for n in 0..137 {
            let a: Vec<_> = (0..n)
                .map(|i| [i32::MIN, -1, 0, 1, i32::MAX][i % 5])
                .collect();
            let b: Vec<_> = (0..n)
                .map(|i| match i % 7 {
                    0 => u64::MAX,
                    1 => 1 << 31,
                    2 => (1 << 32) - 1,
                    3 => 1 << 63,
                    _ => (i as u64).wrapping_mul(0x9e3779b97f4a7c15),
                })
                .collect();
            assert_eq!(dot_i32(&a, &b), scalar_i32(&a, &b));
            let c: Vec<_> = (0..n).map(|i| u16::MAX.wrapping_sub(i as u16)).collect();
            let expected = c.iter().zip(&b).fold(0u64, |s, (&a, &b)| {
                s.wrapping_add((a as u64).wrapping_mul(b))
            });
            assert_eq!(dot_u16(&c, &b), expected);
            #[cfg(target_arch = "x86_64")]
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: features checked; test vectors have matching lengths.
                unsafe {
                    assert_eq!(x86::i32_dot(&a, &b), scalar_i32(&a, &b));
                    assert_eq!(x86::u16_dot(&c, &b), expected);
                }
            }
        }
    }
}
