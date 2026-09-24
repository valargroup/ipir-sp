//! Byte-equality: reinspiring::pack vs inspiring::QueryPackPreprocessed::pack_b.

use inspiring::{GadgetParams, PackingKeys, QueryPackPreprocessed, RlweParams, TopKeyImages};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use reinspiring::{pack, preprocess_from_inspiring, CompileAlgo};
use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};

fn tiny_params() -> RlweParams {
    RlweParams::new(
        8,
        12289,
        4,
        3.2,
        GadgetParams {
            bits_per: 3,
            ell: 5,
        },
    )
    .expect("valid tiny params")
}

fn crs<'a>(params: &'a RlweParams) -> spiral_rs::poly::PolyMatrixNTT<'a> {
    let mut raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
    for row in 0..params.d {
        for col in 0..params.d {
            raw.get_poly_mut(row, 0)[col] = ((row * 17 + col * 3 + 5) as u64) % params.q;
        }
    }
    to_ntt_alloc(&raw)
}

fn fixture() -> (
    &'static RlweParams,
    QueryPackPreprocessed<'static>,
    PackingKeys<'static>,
    TopKeyImages<'static>,
) {
    let params = Box::leak(Box::new(tiny_params()));
    let crs = crs(params);
    let pre = QueryPackPreprocessed::build(params, &crs).expect("preprocess");
    let mut secret = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    secret.get_poly_mut(0, 0)[0] = 1;
    secret.get_poly_mut(0, 0)[2] = params.q - 1;
    let secret_ntt = to_ntt_alloc(&secret);
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let keys = PackingKeys::generate_full(params, &secret_ntt, &mut rng);
    let top = TopKeyImages::build(params);
    (params, pre, keys, top)
}

#[test]
fn reinspiring_matches_pack_b_tiny_naive() {
    let (params, pre, keys, top) = fixture();
    let b: Vec<u64> = (0..params.d)
        .map(|i| (i as u64 * 11 + 3) % params.q)
        .collect();

    let expected = pre.pack_b(&b, &keys, &top).expect("inspiring pack_b");
    // Legacy lift hint; the remainder uses its validated multi-prime context.
    let lift_q = 1_000_003u64;
    let rp = preprocess_from_inspiring(&pre, lift_q, CompileAlgo::Naive).expect("compile");
    let actual = pack(&b, &keys, &rp).expect("reinspiring pack");

    assert_eq!(
        actual.inner.as_slice(),
        expected.inner.as_slice(),
        "naive Compile must be byte-equal to inspiring pack_b"
    );
}

#[test]
fn reinspiring_matches_pack_b_tiny_fast() {
    let (params, pre, keys, top) = fixture();
    let b: Vec<u64> = (0..params.d)
        .map(|i| (i as u64 * 13 + 9) % params.q)
        .collect();

    let expected = pre.pack_b(&b, &keys, &top).expect("inspiring pack_b");
    let rp = preprocess_from_inspiring(&pre, 1_000_003, CompileAlgo::Fast).expect("compile");
    let actual = pack(&b, &keys, &rp).expect("reinspiring pack");

    assert_eq!(actual.inner.as_slice(), expected.inner.as_slice());
}

#[test]
fn compile_naive_and_fast_agree() {
    let (_params, pre, keys, _top) = fixture();
    let b: Vec<u64> = (0..8).map(|i| i as u64 * 5).collect();
    let naive = preprocess_from_inspiring(&pre, 1_000_003, CompileAlgo::Naive).unwrap();
    let fast = preprocess_from_inspiring(&pre, 1_000_003, CompileAlgo::Fast).unwrap();
    assert_eq!(naive.matrix().data, fast.matrix().data);
    let ct_n = pack(&b, &keys, &naive).unwrap();
    let ct_f = pack(&b, &keys, &fast).unwrap();
    assert_eq!(ct_n.inner.as_slice(), ct_f.inner.as_slice());
}

#[test]
fn degree_two_has_only_the_final_h_switch() {
    let p = RlweParams::new(
        2,
        12289,
        4,
        3.2,
        GadgetParams {
            bits_per: 3,
            ell: 5,
        },
    )
    .unwrap();
    let pre = QueryPackPreprocessed::build(&p, &crs(&p)).unwrap();
    let mut secret = PolyMatrixRaw::zero(&p.spiral, 1, 1);
    secret.get_poly_mut(0, 0)[0] = 1;
    let keys = PackingKeys::generate_full(
        &p,
        &to_ntt_alloc(&secret),
        &mut ChaCha20Rng::from_seed([7; 32]),
    );
    let top = TopKeyImages::build(&p);
    let expected = pre.pack_b(&[17, 19], &keys, &top).unwrap();
    for algo in [CompileAlgo::Fast, CompileAlgo::Naive] {
        let rp = preprocess_from_inspiring(&pre, 12289, algo).unwrap();
        assert_eq!(
            pack(&[17, 19], &keys, &rp).unwrap().inner.as_slice(),
            expected.inner.as_slice()
        );
    }
}
