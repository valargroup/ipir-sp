//! Larger-parameter equivalence (56-bit single-CRT q, modest d).

use inspiring::{GadgetParams, PackingKeys, QueryPackPreprocessed, RlweParams, TopKeyImages};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use reinspiring::{pack, preprocess_from_inspiring, CompileAlgo};
use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};

const SINGLE_CRT_Q: u64 = 72_057_594_037_641_217;

fn params_d(d: usize) -> RlweParams {
    RlweParams::new(
        d,
        SINGLE_CRT_Q,
        1 << 14,
        6.4,
        GadgetParams {
            bits_per: 19,
            ell: 3,
        },
    )
    .expect("valid params")
}

#[test]
fn reinspiring_matches_pack_b_d16_56bit() {
    let params = Box::leak(Box::new(params_d(16)));
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let mut crs_raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
    for coeff in crs_raw.as_mut_slice().iter_mut() {
        *coeff = rng.next_u64() % params.q;
    }
    let crs = to_ntt_alloc(&crs_raw);
    let pre = QueryPackPreprocessed::build(params, &crs).expect("preprocess");
    let mut secret = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    secret.get_poly_mut(0, 0)[0] = 1;
    secret.get_poly_mut(0, 0)[1] = params.q - 1;
    let keys = PackingKeys::generate_full(params, &to_ntt_alloc(&secret), &mut rng);
    let top = TopKeyImages::build(params);
    let b: Vec<u64> = (0..params.d)
        .map(|_| rng.next_u64() % params.q)
        .collect();

    let expected = pre.pack_b(&b, &keys, &top).expect("pack_b");
    let rp = preprocess_from_inspiring(&pre, SINGLE_CRT_Q, CompileAlgo::Fast).expect("compile");
    let actual = pack(&b, &keys, &rp).expect("reinspiring");
    assert_eq!(actual.inner.as_slice(), expected.inner.as_slice());
}
