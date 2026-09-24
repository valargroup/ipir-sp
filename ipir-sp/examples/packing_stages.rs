//! Packing-only offline stages and many-block online latency.
//! Args: blocks (default 16), limbs (2), samples (30). RAYON_NUM_THREADS sets workers.
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use rayon::prelude::*;
use reinspiring::native::*;
use std::{hint::black_box, time::Instant};
fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .map(|x| x.parse().unwrap())
        .collect();
    let blocks = *args.first().unwrap_or(&16);
    let ell = *args.get(1).unwrap_or(&2);
    let samples = *args.get(2).unwrap_or(&30);
    assert!((1..=32).contains(&blocks));
    let p = NativeParams::paper(ell, SecretDistribution::Gaussian).unwrap();
    let d = p.d();
    let setup = NativeSetup::new(p.clone(), [71; 32]);
    let mut rng = ChaCha20Rng::seed_from_u64(0x5041434b);
    let secret = NativeSecret::sample(&p, &mut rng);
    let mut pre = Vec::new();
    let mut bodies = Vec::new();
    let mut expected = Vec::new();
    for block in 0..blocks {
        let masks: Vec<Vec<_>> = (0..d)
            .map(|_| (0..d).map(|_| rng.next_u64() & (p.q() - 1)).collect())
            .collect();
        let (compiled, timing) = NativePreprocessed::build_timed(&setup, &masks).unwrap();
        println!(
            "{}",
            serde_json::json!({"kind":"setup", "block":block,"blocks":blocks,"ell":ell,"threads":rayon::current_num_threads(),"aggregation_s":timing.aggregation.as_secs_f64(),"trace_s":timing.trace.as_secs_f64(),"compilation_s":timing.compilation.as_secs_f64(),"total_s":timing.total.as_secs_f64(),"coefficient_bytes":compiled.coefficient_bytes()})
        );
        let messages: Vec<_> = (0..d).map(|_| rng.next_u64() & (p.p() - 1)).collect();
        let b: Vec<_> = masks
            .iter()
            .zip(&messages)
            .map(|(a, &m)| secret.encrypt_lwe(a, m, &mut rng).unwrap())
            .collect();
        pre.push(compiled);
        bodies.push(b);
        expected.push(messages);
    }
    for sample in 0..samples + 5 {
        // Fresh uploaded keys; the fixed fixture secret lets ciphertexts be
        // checked without putting database-hint generation in the timed region.
        let keys = NativeKeys::generate(&setup, &secret, &mut rng).unwrap();
        let start = Instant::now();
        let result: Vec<_> = pre
            .par_iter()
            .zip(&bodies)
            .map(|(pre, b)| pre.pack(black_box(b), &keys).unwrap())
            .collect();
        let elapsed = start.elapsed().as_secs_f64() * 1000.;
        for (ct, messages) in result.iter().zip(&expected) {
            assert_eq!(secret.decrypt(ct).unwrap(), *messages);
        }
        if sample >= 5 {
            println!(
                "{}",
                serde_json::json!({"kind":"online","sample":sample-5,"blocks":blocks,"ell":ell,"threads":rayon::current_num_threads(),"ms":elapsed,"correct":true})
            );
        }
    }
}
