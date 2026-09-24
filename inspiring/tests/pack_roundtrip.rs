use inspiring::automorph::{h, tau_g_pow};
use inspiring::key_switching::ks_setup;
use inspiring::{pack, GadgetParams, LweBatch, LweCiphertext, PackPreprocessed, RlweParams};
use rand_chacha::rand_core::SeedableRng;
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

fn lwe_for_message(params: &RlweParams, a: Vec<u64>, s: &[u64], message: u64) -> LweCiphertext {
    let inner_product = a.iter().zip(s).fold(0_u64, |acc, (ai, si)| {
        (acc + (u128::from(*ai) * u128::from(*si) % u128::from(params.q)) as u64) % params.q
    });
    let encoded = (params.delta * message) % params.q;
    let b = (params.q + encoded - inner_product) % params.q;
    LweCiphertext { a, b }
}

fn crs_from_batch<'a>(params: &'a RlweParams, batch: &LweBatch) -> PolyMatrixNTT<'a> {
    let mut crs = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
    for (row, ct) in batch.inner.iter().enumerate() {
        crs.get_poly_mut(row, 0).copy_from_slice(&ct.a);
    }
    crs.ntt()
}

fn decrypt(
    params: &RlweParams,
    ct: &inspiring::pack::RlweCiphertext<'_>,
    s_tilde: &[u64],
) -> Vec<u64> {
    let raw = from_ntt_alloc(&ct.inner);
    let phase = add_poly(
        raw.get_poly(1, 0),
        &negacyclic_mul(raw.get_poly(0, 0), s_tilde, params.q),
        params.q,
    );
    phase
        .iter()
        .map(|coeff| ((coeff + params.delta / 2) / params.delta) % params.p)
        .collect()
}

#[test]
fn pack_roundtrip_recovers_all_message_slots_for_many_seeds() {
    let params = params();
    let s_tilde = vec![1, 0, params.q - 1, 1, 0, 1, params.q - 1, 0];
    let tau_g_s = tau_coeffs(&s_tilde, tau_g_pow(1, params.d), params.q);
    let tau_h_s = tau_coeffs(&s_tilde, h(params.d), params.q);

    for seed in [0x51A7_u64, 0x51A8, 0x51A9, 0x51AA, 0x51AB] {
        let messages: Vec<_> = (0..params.d)
            .map(|idx| ((seed as usize + idx * 3) % params.p as usize) as u64)
            .collect();
        let batch = LweBatch {
            inner: messages
                .iter()
                .enumerate()
                .map(|(row, message)| {
                    let a = (0..params.d)
                        .map(|col| ((seed + (row * params.d + col) as u64 * 17 + 5) % params.q))
                        .collect();
                    lwe_for_message(&params, a, &s_tilde, *message)
                })
                .collect(),
        };
        let crs = crs_from_batch(&params, &batch);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let kg = ks_setup(
            &params,
            &ntt_from_coeffs(&params, &tau_g_s),
            &ntt_from_coeffs(&params, &s_tilde),
            &mut rng,
        );
        let kh = ks_setup(
            &params,
            &ntt_from_coeffs(&params, &tau_h_s),
            &ntt_from_coeffs(&params, &s_tilde),
            &mut rng,
        );
        let pre = PackPreprocessed::build(&params, &crs, &kg, &kh).expect("valid preprocessing");

        let packed = pack(&batch, &pre).expect("pack succeeds");

        assert_eq!(decrypt(&params, &packed, &s_tilde), messages, "seed {seed}");
    }
}
