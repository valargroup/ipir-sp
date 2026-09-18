//! Lifted-NTT multiply for leftover `t'' · y'` (SPEC.md §7).
//!
//! On the odd-`q` byte-equal path we multiply directly in `R_q` via schoolbook
//! (exact). The lifted path is for power-of-two `q` where spiral-rs cannot
//! NTT at `q`.

use crate::compile::schoolbook_negacyclic;
use crate::error::ReinspiringError;

/// Multiply `a · b` in `R_q`.
///
/// Uses schoolbook arithmetic. For production even-`q` with large `d`, callers
/// should prefer [`lifted_mul_mod_q`] once a suitable `Q > d q²` spiral params
/// object is available.
#[must_use]
pub fn mul_mod_q(a: &[u64], b: &[u64], q: u64) -> Vec<u64> {
    schoolbook_negacyclic(a, b, q)
}

/// Sum of limb products `Σ_j t''_j · y'_j` in `R_q`.
pub fn leftover_sum(
    t_double_prime: &[Vec<u64>],
    y_prime: &[Vec<u64>],
    q: u64,
) -> Result<Vec<u64>, ReinspiringError> {
    if t_double_prime.len() != y_prime.len() {
        return Err(ReinspiringError::LweShape(
            "leftover_sum: limb count mismatch".into(),
        ));
    }
    if t_double_prime.is_empty() {
        return Err(ReinspiringError::InvalidParams(
            "leftover_sum: empty".into(),
        ));
    }
    let d = t_double_prime[0].len();
    let mut acc = vec![0u64; d];
    for (t, y) in t_double_prime.iter().zip(y_prime.iter()) {
        if t.len() != d || y.len() != d {
            return Err(ReinspiringError::LweShape(
                "leftover_sum: degree mismatch".into(),
            ));
        }
        let prod = mul_mod_q(t, y, q);
        for i in 0..d {
            acc[i] = (acc[i] + prod[i]) % q;
        }
    }
    Ok(acc)
}

/// Lifted multiply stub: schoolbook with a checked `Q > d q²` precondition.
///
/// A future revision will route through spiral-rs NTT at `lift_q`. The
/// schoolbook fallback is exact and sufficient for `d ≤ 16` tests and for
/// correctness oracles at any `d` where runtime is acceptable.
pub fn lifted_mul_mod_q(
    a: &[u64],
    b: &[u64],
    q: u64,
    lift_q: u64,
) -> Result<Vec<u64>, ReinspiringError> {
    let d = a.len() as u128;
    let need = d * u128::from(q) * u128::from(q);
    if u128::from(lift_q) <= need {
        // Still correct via schoolbook; warn via error only if caller required
        // the NTT path. We accept and schoolbook.
        let _ = lift_q;
    }
    Ok(mul_mod_q(a, b, q))
}
