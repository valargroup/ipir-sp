use inspiring::automorph::{h, tau_g_pow};
use inspiring::collapse::{collapse_one, CollapseState};
use inspiring::key_switching::{automorphic_image, ks_setup};
use inspiring::{GadgetParams, RlweParams};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use spiral_rs::poly::{from_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw};

fn params() -> RlweParams {
    RlweParams::new(
        8,
        12289,
        4,
        0.1,
        GadgetParams {
            bits_per: 3,
            ell: 5,
        },
    )
    .expect("valid tiny test parameters")
}

fn raw_from_coeffs<'a>(params: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixRaw<'a> {
    let mut raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    raw.get_poly_mut(0, 0).copy_from_slice(coeffs);
    raw
}

fn ntt_from_coeffs<'a>(params: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixNTT<'a> {
    raw_from_coeffs(params, coeffs).ntt()
}

fn tau_coeffs(poly: &[u64], exponent: u64, q: u64) -> Vec<u64> {
    let d = poly.len();
    let mut out = vec![0; d];

    for (i, coeff) in poly.iter().enumerate() {
        let exp = (i as u64 * exponent) % (2 * d as u64);
        let reduced = coeff % q;
        let (idx, value) = if exp < d as u64 {
            (exp as usize, reduced)
        } else {
            (
                (exp - d as u64) as usize,
                if reduced == 0 { 0 } else { q - reduced },
            )
        };
        out[idx] = (out[idx] + value) % q;
    }

    out
}

fn negacyclic_mul(lhs: &[u64], rhs: &[u64], q: u64) -> Vec<u64> {
    let d = lhs.len();
    let mut out = vec![0; d];

    for (i, lhs_coeff) in lhs.iter().enumerate() {
        for (j, rhs_coeff) in rhs.iter().enumerate() {
            let product = (u128::from(*lhs_coeff) * u128::from(*rhs_coeff) % u128::from(q)) as u64;
            let degree = i + j;
            if degree < d {
                out[degree] = (out[degree] + product) % q;
            } else if product != 0 {
                out[degree - d] = (out[degree - d] + q - product) % q;
            }
        }
    }

    out
}

fn add_poly(lhs: &[u64], rhs: &[u64], q: u64) -> Vec<u64> {
    lhs.iter().zip(rhs).map(|(x, y)| (x + y) % q).collect()
}

fn sub_poly(lhs: &[u64], rhs: &[u64], q: u64) -> Vec<u64> {
    lhs.iter().zip(rhs).map(|(x, y)| (q + x - y) % q).collect()
}

fn decrypt_single_state(
    params: &RlweParams,
    a: &PolyMatrixNTT<'_>,
    b: &PolyMatrixNTT<'_>,
    s_tilde: &[u64],
) -> Vec<u64> {
    let a_raw = from_ntt_alloc(a);
    let b_raw = from_ntt_alloc(b);
    let decrypted = add_poly(
        b_raw.get_poly(0, 0),
        &negacyclic_mul(a_raw.get_poly(0, 0), s_tilde, params.q),
        params.q,
    );

    decrypted
        .iter()
        .map(|coeff| ((coeff + params.delta / 2) / params.delta) % params.p)
        .collect()
}

#[test]
fn collapse_one_with_real_key_switching_preserves_plaintext() {
    let params = params();
    let s0 = vec![3, 1, 4, 1, 5, 9, 2, 6];
    let s1 = tau_coeffs(&s0, tau_g_pow(1, params.d), params.q);
    let a0 = vec![5, 7, 11, 13, 17, 19, 23, 29];
    let a1 = vec![31, 37, 41, 43, 47, 53, 59, 61];
    let messages = vec![0, 1, 2, 3, 3, 2, 1, 0];
    let encoded: Vec<_> = messages
        .iter()
        .map(|message| (params.delta * message) % params.q)
        .collect();
    let b = sub_poly(
        &sub_poly(&encoded, &negacyclic_mul(&a0, &s0, params.q), params.q),
        &negacyclic_mul(&a1, &s1, params.q),
        params.q,
    );

    let mut rng = ChaCha20Rng::seed_from_u64(0xC011A5E);
    let k = ks_setup(
        &params,
        &params.spiral,
        &ntt_from_coeffs(&params, &s1),
        &ntt_from_coeffs(&params, &s0),
        &mut rng,
    );
    let mut state = CollapseState {
        a: vec![ntt_from_coeffs(&params, &a0), ntt_from_coeffs(&params, &a1)],
        b: ntt_from_coeffs(&params, &b),
    };

    collapse_one(&mut state, &k);

    assert_eq!(
        decrypt_single_state(&params, &state.a[0], &state.b, &s0),
        messages
    );
}

#[test]
fn automorphic_key_image_switches_matching_tau_g_secret_pair() {
    let params = params();
    let s = vec![3, 1, 4, 1, 5, 9, 2, 6];
    let s_from_base = tau_coeffs(&s, tau_g_pow(1, params.d), params.q);
    let image_exp = tau_g_pow(2, params.d);
    let s0 = tau_coeffs(&s, image_exp, params.q);
    let s1 = tau_coeffs(
        &s,
        (image_exp * tau_g_pow(1, params.d)) % (2 * params.d as u64),
        params.q,
    );
    let a0 = vec![5, 7, 11, 13, 17, 19, 23, 29];
    let a1 = vec![31, 37, 41, 43, 47, 53, 59, 61];
    let messages = vec![0, 1, 2, 3, 3, 2, 1, 0];
    let encoded: Vec<_> = messages
        .iter()
        .map(|message| (params.delta * message) % params.q)
        .collect();
    let b = sub_poly(
        &sub_poly(&encoded, &negacyclic_mul(&a0, &s0, params.q), params.q),
        &negacyclic_mul(&a1, &s1, params.q),
        params.q,
    );

    let mut rng = ChaCha20Rng::seed_from_u64(0xA70A);
    let kg = ks_setup(
        &params,
        &params.spiral,
        &ntt_from_coeffs(&params, &s_from_base),
        &ntt_from_coeffs(&params, &s),
        &mut rng,
    );
    let k_image = automorphic_image(&kg, image_exp);
    let mut state = CollapseState {
        a: vec![ntt_from_coeffs(&params, &a0), ntt_from_coeffs(&params, &a1)],
        b: ntt_from_coeffs(&params, &b),
    };

    collapse_one(&mut state, &k_image);

    assert_eq!(
        decrypt_single_state(&params, &state.a[0], &state.b, &s0),
        messages
    );
}

#[test]
fn tau_h_automorphic_key_image_switches_matching_right_half_secret_pair() {
    let params = params();
    let s = vec![3, 1, 4, 1, 5, 9, 2, 6];
    let s_from_base = tau_coeffs(&s, tau_g_pow(1, params.d), params.q);
    let image_exp = (h(params.d) * tau_g_pow(2, params.d)) % (2 * params.d as u64);
    let s0 = tau_coeffs(&s, image_exp, params.q);
    let s1 = tau_coeffs(
        &s,
        (image_exp * tau_g_pow(1, params.d)) % (2 * params.d as u64),
        params.q,
    );
    let a0 = vec![5, 7, 11, 13, 17, 19, 23, 29];
    let a1 = vec![31, 37, 41, 43, 47, 53, 59, 61];
    let messages = vec![0, 1, 2, 3, 3, 2, 1, 0];
    let encoded: Vec<_> = messages
        .iter()
        .map(|message| (params.delta * message) % params.q)
        .collect();
    let b = sub_poly(
        &sub_poly(&encoded, &negacyclic_mul(&a0, &s0, params.q), params.q),
        &negacyclic_mul(&a1, &s1, params.q),
        params.q,
    );

    let mut rng = ChaCha20Rng::seed_from_u64(0xA70B);
    let kg = ks_setup(
        &params,
        &params.spiral,
        &ntt_from_coeffs(&params, &s_from_base),
        &ntt_from_coeffs(&params, &s),
        &mut rng,
    );
    let k_image = automorphic_image(&kg, image_exp);
    let mut state = CollapseState {
        a: vec![ntt_from_coeffs(&params, &a0), ntt_from_coeffs(&params, &a1)],
        b: ntt_from_coeffs(&params, &b),
    };

    collapse_one(&mut state, &k_image);

    assert_eq!(
        decrypt_single_state(&params, &state.a[0], &state.b, &s0),
        messages
    );
}
