//! Low-word dot products. Wrapping modulo 2^64 is exact before reduction mod 2^k.
#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

/// Runtime-dispatched u16-by-u64 dot product, including all tail elements.
/// The result is the low 64 bits of the integer sum; callers reduce mod 2^k.
pub fn dot_u16(a: &[u16], b: &[u64]) -> u64 {
    assert_eq!(a.len(), b.len());
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
    fn dispatched_kernels_match_scalar_with_signs_overflow_and_tails() {
        for n in 0..137 {
            let a: Vec<_> = (0..n)
                .map(|i| [i32::MIN, -1, 0, 1, i32::MAX][i % 5])
                .collect();
            let b: Vec<_> = (0..n)
                .map(|i| u64::MAX.wrapping_mul(i as u64 + 17))
                .collect();
            assert_eq!(dot_i32(&a, &b), scalar_i32(&a, &b));
            let c: Vec<_> = (0..n).map(|i| u16::MAX.wrapping_sub(i as u16)).collect();
            let expected = c.iter().zip(&b).fold(0u64, |s, (&a, &b)| {
                s.wrapping_add((a as u64).wrapping_mul(b))
            });
            assert_eq!(dot_u16(&c, &b), expected);
        }
    }
}
