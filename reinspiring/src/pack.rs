//! `ReinspiRING.Pack` — online `H'·y + t''·y' + b̃` (SPEC.md §6).

use inspiring::{PackingKeys, RlweCiphertext};
use spiral_rs::poly::{from_ntt_alloc, stack_ntt, to_ntt_alloc, PolyMatrix, PolyMatrixRaw};

use crate::error::ReinspiringError;
use crate::lift_ntt::leftover_sum;
use crate::preprocess::ReinspiringPreprocessed;

/// Online packing: returns an RLWE ciphertext under the base secret.
///
/// For odd NTT-friendly `q` this is an exact rewrite of
/// [`inspiring::QueryPackPreprocessed::pack_b`].
pub fn pack<'a>(
    b_scalars: &[u64],
    keys: &PackingKeys<'a>,
    pre: &ReinspiringPreprocessed<'a>,
) -> Result<RlweCiphertext<'a>, ReinspiringError> {
    let ip = pre.inspiring_params;
    let d = ip.d;
    let ell = ip.gadget.ell;
    let q = ip.q;

    if b_scalars.len() != d {
        return Err(ReinspiringError::LweShape(format!(
            "expected {d} b scalars, got {}",
            b_scalars.len()
        )));
    }
    keys.validate(ip)?;

    let y_limbs = body_limbs_coeff(&keys.kg_body, ell, d);
    let y_prime_limbs = body_limbs_coeff(&keys.kh_body, ell, d);

    let mut y = Vec::with_capacity(ell * d);
    for limb in &y_limbs {
        y.extend(limb.iter().map(|c| c % q));
    }

    let mut c2 = vec![0u64; d];
    pre.h_prime.matvec(&y, &mut c2)?;

    let z = leftover_sum(&pre.t_double_prime, &y_prime_limbs, q)?;
    for i in 0..d {
        c2[i] = (c2[i] + z[i]) % q;
        c2[i] = (c2[i] + (b_scalars[i] % q)) % q;
    }

    let mut b_raw = PolyMatrixRaw::zero(&ip.spiral, 1, 1);
    b_raw.get_poly_mut(0, 0)[..d].copy_from_slice(&c2);
    let b_ntt = to_ntt_alloc(&b_raw);

    Ok(RlweCiphertext {
        inner: stack_ntt(&pre.a_tilde_ntt, &b_ntt),
    })
}

fn body_limbs_coeff(body: &spiral_rs::poly::PolyMatrixNTT<'_>, ell: usize, d: usize) -> Vec<Vec<u64>> {
    assert_eq!(body.rows, 1);
    assert_eq!(body.cols, ell);
    let raw = from_ntt_alloc(body);
    let mut limbs = Vec::with_capacity(ell);
    for j in 0..ell {
        let poly = raw.get_poly(0, j);
        limbs.push(poly[..d].to_vec());
    }
    limbs
}
