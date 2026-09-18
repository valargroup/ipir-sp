//! Fuzz target: reinspiring pack must not panic on arbitrary b scalars.

#![no_main]
use inspiring::{GadgetParams, PackingKeys, QueryPackPreprocessed, RlweParams};
use libfuzzer_sys::fuzz_target;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use reinspiring::{pack, preprocess_from_inspiring, CompileAlgo};
use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};
use std::sync::OnceLock;

struct Fixture {
    pre: QueryPackPreprocessed<'static>,
    keys: PackingKeys<'static>,
    rp: reinspiring::ReinspiringPreprocessed<'static>,
}

fn fixture() -> &'static Fixture {
    static FIX: OnceLock<Fixture> = OnceLock::new();
    FIX.get_or_init(|| {
        let params = Box::leak(Box::new(
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
            .unwrap(),
        ));
        let mut crs_raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
        for (i, c) in crs_raw.as_mut_slice().iter_mut().enumerate() {
            *c = (i as u64) % params.q;
        }
        let pre = QueryPackPreprocessed::build(params, &to_ntt_alloc(&crs_raw)).unwrap();
        let mut secret = PolyMatrixRaw::zero(&params.spiral, 1, 1);
        secret.get_poly_mut(0, 0)[0] = 1;
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let keys = PackingKeys::generate_full(params, &to_ntt_alloc(&secret), &mut rng);
        let rp = preprocess_from_inspiring(&pre, 1_000_003, CompileAlgo::Fast).unwrap();
        Fixture { pre, keys, rp }
    })
}

fuzz_target!(|data: &[u8]| {
    let fix = fixture();
    let d = fix.pre.params.d;
    let q = fix.pre.params.q;
    let mut b = vec![0u64; d];
    for (i, slot) in b.iter_mut().enumerate() {
        let byte = data.get(i).copied().unwrap_or(0);
        *slot = u64::from(byte) % q;
    }
    let _ = pack(&b, &fix.keys, &fix.rp);
});
