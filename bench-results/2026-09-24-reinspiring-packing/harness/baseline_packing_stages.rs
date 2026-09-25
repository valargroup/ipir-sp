//! Packing-only offline stages and many-block online latency.
//! Args: blocks (16), limbs (2), samples (30), concurrent setup blocks (1).
//! Fifth arg: 0 legacy, 1 shared keys, 2 matrix, 3 leftover, 4 read-only.
//! RAYON_NUM_THREADS sets workers.
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use rayon::prelude::*;
use reinspiring::native::*;
use sha2::{Digest, Sha256};
use std::{hint::black_box, time::Instant};
fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .map(|x| x.parse().unwrap())
        .collect();
    let blocks = *args.first().unwrap_or(&16);
    let ell = *args.get(1).unwrap_or(&2);
    let samples = *args.get(2).unwrap_or(&30);
    let concurrency = *args.get(3).unwrap_or(&1);
    let mode = *args.get(4).unwrap_or(&0);
    let cached = false;
    assert_eq!(mode, 0, "baseline supports legacy packing only");
    assert!((1..=32).contains(&blocks) && (1..=blocks).contains(&concurrency));
    let p = NativeParams::paper(ell, SecretDistribution::Gaussian).unwrap();
    let d = p.d();
    let setup = NativeSetup::new(p.clone(), [71; 32]);
    let mut rng = ChaCha20Rng::seed_from_u64(0x5041434b);
    let secret = NativeSecret::sample(&p, &mut rng);
    let mut pre = Vec::new();
    let mut bodies = Vec::new();
    let mut expected = Vec::new();
    // Build fixtures before timing; deterministic ordering is independent of
    // concurrency. Keep RNG consumption identical to the serial fixture.
    let mut all_masks = Vec::new();
    for _ in 0..blocks {
        let masks: Vec<Vec<_>> = (0..d)
            .map(|_| (0..d).map(|_| rng.next_u64() & (p.q() - 1)).collect())
            .collect();
        let messages: Vec<_> = (0..d).map(|_| rng.next_u64() & (p.p() - 1)).collect();
        let b: Vec<_> = masks
            .iter()
            .zip(&messages)
            .map(|(a, &m)| secret.encrypt_lwe(a, m, &mut rng).unwrap())
            .collect();
        all_masks.push(masks);
        bodies.push(b);
        expected.push(messages);
    }
    let mut fixture_hash = Sha256::new();
    for word in all_masks
        .iter()
        .flatten()
        .flatten()
        .chain(bodies.iter().flatten())
        .chain(expected.iter().flatten())
    {
        fixture_hash.update(word.to_le_bytes());
    }
    let fixture_sha256 = format!("{:x}", fixture_hash.finalize());
    let start = Instant::now();
    let mut built = Vec::with_capacity(blocks);
    for batch in all_masks.chunks(concurrency) {
        let batch: Vec<_> = batch
            .par_iter()
            .map(|masks| NativePreprocessed::build_timed(&setup, masks).unwrap())
            .collect();
        built.extend(batch);
    }
    let elapsed = start.elapsed().as_secs_f64();
    drop(all_masks);
    println!(
        "{}",
        serde_json::json!({"kind":"batch_setup","blocks":blocks,"ell":ell,"threads":rayon::current_num_threads(),"concurrency":concurrency,"seconds":elapsed,"fixture_sha256":fixture_sha256,"degree":d,"output_columns":blocks*d})
    );
    for (block, (compiled, timing)) in built.into_iter().enumerate() {
        println!(
            "{}",
            serde_json::json!({"kind":"setup", "block":block,"blocks":blocks,"ell":ell,"threads":rayon::current_num_threads(),"aggregation_s":timing.aggregation.as_secs_f64(),"trace_s":timing.trace.as_secs_f64(),"compilation_s":timing.compilation.as_secs_f64(),"total_s":timing.total.as_secs_f64(),"coefficient_bytes":compiled.coefficient_bytes()})
        );
        pre.push(compiled);
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
        let (key_ms, contribution_ms, finish_ms) = (0., 0., 0.);
        let elapsed = start.elapsed().as_secs_f64() * 1000.;
        for (ct, messages) in result.iter().zip(&expected) {
            assert_eq!(secret.decrypt(ct).unwrap(), *messages);
        }
        let mut result_hash = Sha256::new();
        for ct in &result {
            for word in ct.rows().0.iter().chain(ct.rows().1.iter()) {
                result_hash.update(word.to_le_bytes());
            }
        }
        let ciphertext_sha256 = format!("{:x}", result_hash.finalize());
        if sample >= 5 {
            println!(
                "{}",
                serde_json::json!({"ciphertext_sha256":ciphertext_sha256,"kind":"online","sample":sample-5,"blocks":blocks,"ell":ell,"threads":rayon::current_num_threads(),"ms":elapsed,"cached":cached,"key_ms":key_ms,"contribution_ms":contribution_ms,"finish_ms":finish_ms,"correct":true})
            );
        }
    }
}
