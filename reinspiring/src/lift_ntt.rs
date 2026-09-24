//! Exact negacyclic products via three pinned NTT primes and signed CRT.
//!
//! Spiral supplies the NTT and pointwise multiplication. Each product is
//! reconstructed separately before summing limbs: the proven bound is per
//! product, not a bound on a sum of an arbitrary number of products.
use crate::error::ReinspiringError;
use spiral_rs::{
    params::Params,
    poly::{from_ntt_alloc, multiply, to_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw},
};

// Distinct primes, each 1 mod 8192. Their product fits i128 and exceeds
// d*q^2 for every supported degree/modulus. Keep separate Spiral Params:
// Spiral's combined `modulus` field is only u64.
const PRIMES: [u64; 3] = [4398046568449, 4398046666753, 4398046781441];

/// Validated, reusable auxiliary NTT context. No native-q NTT is required.
pub struct LiftContext {
    d: usize,
    q: u64,
    params: Vec<Params>,
    product: u128,
    inverses: [u64; 2],
}

impl LiftContext {
    /// Construct for d in 2..=4096 and q in 2..=2^56.
    pub fn new(d: usize, q: u64) -> Result<Self, ReinspiringError> {
        if !(2..=4096).contains(&d) || !d.is_power_of_two() || !(2..=1 << 56).contains(&q) {
            return Err(ReinspiringError::InvalidParams(
                "unsupported lifted product parameters".into(),
            ));
        }
        let product = PRIMES.iter().map(|&x| x as u128).product::<u128>();
        let need = (d as u128)
            .checked_mul(q as u128)
            .and_then(|x| x.checked_mul(q as u128))
            .ok_or_else(|| ReinspiringError::InvalidParams("lift bound overflow".into()))?;
        if product <= need {
            return Err(ReinspiringError::InvalidParams(
                "insufficient CRT reconstruction capacity".into(),
            ));
        }
        let inverses = [
            spiral_rs::number_theory::invert_uint_mod(PRIMES[0] % PRIMES[1], PRIMES[1]).unwrap(),
            spiral_rs::number_theory::invert_uint_mod(
                ((PRIMES[0] as u128 * PRIMES[1] as u128) % PRIMES[2] as u128) as u64,
                PRIMES[2],
            )
            .unwrap(),
        ];
        let params = PRIMES
            .iter()
            .map(|&p| Params::init(d, &[p], 6.4, 1, 2, 20, 1, 1, 1, 1, false, 0, 0, 1, 1, 0))
            .collect();
        Ok(Self {
            d,
            q,
            params,
            product,
            inverses,
        })
    }

    fn validate(&self, a: &[u64]) -> Result<(), ReinspiringError> {
        if a.len() != self.d || a.iter().any(|&x| x >= self.q) {
            return Err(ReinspiringError::LweShape(
                "noncanonical lifted polynomial or wrong degree".into(),
            ));
        }
        Ok(())
    }

    /// Exact product of two canonical polynomials modulo q.
    pub fn multiply(&self, a: &[u64], b: &[u64]) -> Result<Vec<u64>, ReinspiringError> {
        self.validate(a)?;
        self.validate(b)?;
        let mut residues = Vec::with_capacity(3);
        for params in &self.params {
            let mut ar = PolyMatrixRaw::zero(params, 1, 1);
            let mut br = PolyMatrixRaw::zero(params, 1, 1);
            for i in 0..self.d {
                ar.get_poly_mut(0, 0)[i] =
                    centered(a[i], self.q).rem_euclid(params.modulus as i128) as u64;
                br.get_poly_mut(0, 0)[i] =
                    centered(b[i], self.q).rem_euclid(params.modulus as i128) as u64;
            }
            let mut out = PolyMatrixNTT::zero(params, 1, 1);
            multiply(&mut out, &to_ntt_alloc(&ar), &to_ntt_alloc(&br));
            residues.push(from_ntt_alloc(&out).get_poly(0, 0).to_vec());
        }
        Ok((0..self.d)
            .map(|i| {
                let mut x = residues[0][i] as u128;
                let mut m = PRIMES[0] as u128;
                for j in 1..3 {
                    let p = PRIMES[j] as u128;
                    let delta = (residues[j][i] as u128 + p - x % p) % p;
                    x += m * (delta * self.inverses[j - 1] as u128 % p);
                    m *= p;
                }
                let signed = if x > self.product / 2 {
                    x as i128 - self.product as i128
                } else {
                    x as i128
                };
                signed.rem_euclid(self.q as i128) as u64
            })
            .collect())
    }

    /// Sum independent exact products, reducing each one before accumulation.
    pub fn sum(&self, a: &[Vec<u64>], b: &[Vec<u64>]) -> Result<Vec<u64>, ReinspiringError> {
        if a.is_empty() || a.len() != b.len() {
            return Err(ReinspiringError::LweShape(
                "lifted limb count mismatch".into(),
            ));
        }
        let mut out = vec![0; self.d];
        for (a, b) in a.iter().zip(b) {
            for (dst, x) in out.iter_mut().zip(self.multiply(a, b)?) {
                *dst = (*dst + x) % self.q;
            }
        }
        Ok(out)
    }
}

pub(crate) fn centered(x: u64, q: u64) -> i128 {
    if x > q / 2 {
        x as i128 - q as i128
    } else {
        x as i128
    }
}

/// Exact modular product using a checked auxiliary context.
pub fn mul_mod_q(a: &[u64], b: &[u64], q: u64) -> Vec<u64> {
    LiftContext::new(a.len(), q)
        .and_then(|ctx| ctx.multiply(a, b))
        .expect("valid lifted product")
}

/// Checked convenience sum; long-lived callers should retain a LiftContext.
pub fn leftover_sum(a: &[Vec<u64>], b: &[Vec<u64>], q: u64) -> Result<Vec<u64>, ReinspiringError> {
    let d = a
        .first()
        .ok_or_else(|| ReinspiringError::LweShape("empty leftover".into()))?
        .len();
    LiftContext::new(d, q)?.sum(a, b)
}

/// Legacy single-prime entry point. Reject insufficient capacity explicitly.
/// The actual multiplication uses the validated multi-prime engine.
pub fn lifted_mul_mod_q(
    a: &[u64],
    b: &[u64],
    q: u64,
    lift_q: u64,
) -> Result<Vec<u64>, ReinspiringError> {
    let need = (a.len() as u128)
        .checked_mul(q as u128)
        .and_then(|x| x.checked_mul(q as u128));
    if need.is_none() || lift_q as u128 <= need.unwrap() {
        return Err(ReinspiringError::InvalidParams(
            "single lift modulus cannot reconstruct product".into(),
        ));
    }
    LiftContext::new(a.len(), q)?.multiply(a, b)
}
