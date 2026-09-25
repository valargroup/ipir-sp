//! Appendix D.1 helpers: approximate division by `d` and modulus switching.
//!
//! Used when `q` is even so `d^{-1} mod q` does not exist. The odd-`q`
//! InspiRING path must **not** call these (SPEC.md §8).

use crate::error::ReinspiringError;

/// Centered representative of `x mod q` in `(-⌊q/2⌋, ⌊q/2⌋]`.
#[must_use]
pub fn center(x: u64, q: u64) -> i64 {
    let x = x % q;
    let half = q / 2;
    if x > half {
        x as i64 - q as i64
    } else {
        x as i64
    }
}

/// Round `x` from modulus `from_q` down to `to_q`: `⌊x · to_q / from_q⌉`.
#[must_use]
pub fn modulus_switch_coeff(x: u64, from_q: u64, to_q: u64) -> u64 {
    let xc = center(x, from_q);
    let num = i128::from(xc) * i128::from(to_q);
    let den = i128::from(from_q);
    let rounded = if num >= 0 {
        (num + den / 2) / den
    } else {
        (num - den / 2) / den
    };
    rounded.rem_euclid(i128::from(to_q)) as u64
}

/// Coefficient-wise modulus switch.
pub fn modulus_switch_poly(
    coeffs: &[u64],
    from_q: u64,
    to_q: u64,
) -> Result<Vec<u64>, ReinspiringError> {
    if from_q < to_q {
        return Err(ReinspiringError::InvalidParams(
            "modulus_switch: from_q must be ≥ to_q".into(),
        ));
    }
    Ok(coeffs
        .iter()
        .map(|&x| modulus_switch_coeff(x, from_q, to_q))
        .collect())
}

/// Approximate division by `d`: `⌊center(c) / d⌉` reduced mod `q`.
///
/// Matches the floor-division view in ReinsPIRe Appendix D.1 / Lemma 10.
#[must_use]
pub fn approx_div_by_d_coeff(c: u64, d: usize, q: u64) -> u64 {
    let xc = center(c, q);
    let q_i = i128::from(q);
    let d_i = i128::from(d as u64);
    let mut div = i128::from(xc) / d_i;
    // Round toward nearest for the remainder? Lemma 10 uses floor of centered
    // lift; keep truncating division toward zero on the centered value.
    if xc < 0 && i128::from(xc) % d_i != 0 {
        // toward -∞ floor for negative
        div -= 1;
    }
    div.rem_euclid(q_i) as u64
}

/// Approximate `d^{-1}` scaling for a full polynomial (D.1).
#[must_use]
pub fn approx_div_by_d_poly(coeffs: &[u64], d: usize, q: u64) -> Vec<u64> {
    coeffs
        .iter()
        .map(|&c| approx_div_by_d_coeff(c, d, q))
        .collect()
}

/// Bound from Lemma 10 / ReinspiRING Lemma 4: `∥e_div∥_∞ ≤ d²` (ternary secret).
#[must_use]
pub fn ediv_infinity_bound(d: usize) -> u64 {
    (d as u64).saturating_mul(d as u64)
}
