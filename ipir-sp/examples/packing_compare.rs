//! Packing-only comparison; deterministic fixtures, correctness outside timing.
use inspiring::{GadgetParams, PackingKeys, QueryPackPreprocessed, RlweParams, TopKeyImages};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use reinspiring::native::*;
use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixRaw};
use std::{hint::black_box, time::Instant};
fn measure<T>(name: &str, mut f: impl FnMut() -> T) {
    for _ in 0..5 {
        black_box(f());
    }
    for i in 0..30 {
        let t = Instant::now();
        let out = f();
        let ms = t.elapsed().as_secs_f64() * 1000.;
        black_box(out);
        println!(
            "{}",
            serde_json::json!({"kind":"sample","name":name,"sample":i,"ms":ms,"threads":rayon::current_num_threads()})
        );
    }
}
fn main() {
    let d = 2048;
    let q = 72_057_594_037_641_217;
    let mut rng = ChaCha20Rng::seed_from_u64(0x2417);
    let p = RlweParams::new(
        d,
        q,
        1 << 14,
        6.4,
        GadgetParams {
            bits_per: 19,
            ell: 3,
        },
    )
    .unwrap();
    let mut crs = PolyMatrixRaw::zero(&p.spiral, d, 1);
    for i in 0..d {
        for x in crs.get_poly_mut(i, 0) {
            *x = rng.next_u64() % q;
        }
    }
    let t = Instant::now();
    let pre = QueryPackPreprocessed::build(&p, &to_ntt_alloc(&crs)).unwrap();
    let inspiring_s = t.elapsed().as_secs_f64();
    drop(crs);
    let t = Instant::now();
    let rein =
        reinspiring::preprocess_from_inspiring(&pre, q, reinspiring::CompileAlgo::Fast).unwrap();
    let compile_s = t.elapsed().as_secs_f64();
    let secret = ipir_sp::client::ClientSecret::sample_gaussian(&p, &mut rng);
    let keys = PackingKeys::generate_full(&p, &secret.to_ntt(&p), &mut rng);
    let top = TopKeyImages::build(&p);
    let b: Vec<_> = (0..d).map(|_| rng.next_u64() % q).collect();
    let a = pre.pack_b(&b, &keys, &top).unwrap();
    let c = reinspiring::pack(&b, &keys, &rein).unwrap();
    assert_eq!(a.inner.as_slice(), c.inner.as_slice());
    println!(
        "{}",
        serde_json::json!({"kind":"setup","backend":"odd","d":d,"inspiring_s":inspiring_s,"compile_s":compile_s,"matrix_bytes":rein.matrix_storage_bytes()})
    );
    measure("inspiring_odd", || {
        pre.pack_b(black_box(&b), &keys, &top).unwrap()
    });
    measure("reinspiring_odd", || {
        reinspiring::pack(black_box(&b), &keys, &rein).unwrap()
    });
    drop(rein);
    drop(pre);
    for ell in [2, 3] {
        let p = NativeParams::paper(ell, SecretDistribution::Gaussian).unwrap();
        let setup = NativeSetup::new(p.clone(), [7; 32]);
        let masks: Vec<Vec<_>> = (0..d)
            .map(|_| (0..d).map(|_| rng.next_u64() & (p.q() - 1)).collect())
            .collect();
        let t = Instant::now();
        let pre = NativePreprocessed::build(&setup, &masks).unwrap();
        let offline_s = t.elapsed().as_secs_f64();
        let secret = NativeSecret::sample(&p, &mut rng);
        let keys = NativeKeys::generate(&setup, &secret, &mut rng).unwrap();
        let messages: Vec<_> = (0..d).map(|_| rng.next_u64() & (p.p() - 1)).collect();
        let b: Vec<_> = masks
            .iter()
            .zip(&messages)
            .map(|(a, &m)| secret.encrypt_lwe(a, m, &mut rng).unwrap())
            .collect();
        let ct = pre.pack(&b, &keys).unwrap();
        assert_eq!(secret.decrypt(&ct).unwrap(), messages);
        println!(
            "{}",
            serde_json::json!({"kind":"setup","backend":"native","ell":ell,"offline_s":offline_s,"coeff_bytes":pre.coefficient_bytes(),"phase_error":secret.phase_error(&ct,&messages).unwrap()})
        );
        measure(&format!("native_l{ell}_matrix"), || {
            pre.matrix_product(&keys).unwrap()
        });
        measure(&format!("native_l{ell}_leftover"), || {
            pre.leftover_product(&keys).unwrap()
        });
        measure(&format!("native_l{ell}_pack"), || {
            pre.pack(black_box(&b), &keys).unwrap()
        });
    }
}
