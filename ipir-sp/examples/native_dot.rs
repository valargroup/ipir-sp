//! Isolate exact native database scan kernels, with identical full-width inputs.
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use rayon::prelude::*;
use reinspiring::native_kernel::{dot_u16, PreparedU16Query};
use std::time::Instant;
fn main() {
    let rows = 28672;
    let cols = 32768;
    let q = 1u64 << 54;
    let mut rng = ChaCha20Rng::seed_from_u64(0x2417);
    let mut db: Vec<u16> = (0..rows * cols).map(|_| rng.next_u32() as u16).collect();
    let query: Vec<_> = (0..rows).map(|_| rng.next_u64() & (q - 1)).collect();
    let prepared = PreparedU16Query::new(&query, q).unwrap();
    let expected: Vec<_> = db
        .par_chunks_exact(rows)
        .map(|c| dot_u16(c, &query) & (q - 1))
        .collect();
    for threads in [1, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        pool.install(|| {
            for method in ["word", "byte"] {
                for sample in 0..33 {
                    let start = Instant::now();
                    let out = db
                        .par_chunks_exact(rows)
                        .map(|c| {
                            if method == "word" {
                                dot_u16(c, &query) & (q - 1)
                            } else {
                                prepared.dot(c)
                            }
                        })
                        .collect::<Vec<_>>();
                    let ms = start.elapsed().as_secs_f64() * 1000.;
                    assert_eq!(out, expected);
                    if sample >= 3 {
                        println!(
                            "{}",
                            serde_json::json!({"kind":"sample","name":method,
                        "threads":threads,"sample":sample-3,"ms":ms,"correct":true})
                        );
                    }
                }
            }
        });
    }
    db.par_chunks_mut(rows * 16)
        .for_each(|band| PreparedU16Query::interleave_columns(band, rows));
    for threads in [1, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        pool.install(|| {
            for sample in 0..33 {
                let start = Instant::now();
                let mut out = vec![0; cols];
                out.par_chunks_mut(16)
                    .zip(db.par_chunks(rows * 16))
                    .for_each(|(out, db)| prepared.multiply_interleaved(db, out));
                let ms = start.elapsed().as_secs_f64() * 1000.;
                assert_eq!(out, expected);
                if sample >= 3 {
                    println!(
                        "{}",
                        serde_json::json!({"kind":"sample","name":"interleaved",
                "threads":threads,"sample":sample-3,"ms":ms,"correct":true})
                    );
                }
            }
        });
    }
}
