//! Isolate exact native database scan kernels, with identical full-width inputs.
//! Flags: `--rows N` (28672), `--cols N` (32768), `--pbits N` (16),
//! `--query-bits N` (54: a full-width query; fewer bits lift a k-bit query by
//! 2^(54-k), as the server does for transported queries), `--storage u8|u16`.
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use rayon::prelude::*;
use reinspiring::native_kernel::{dot_u16, dot_u8, PreparedU16Query};
use std::time::Instant;

fn flag(raw: &[String], name: &str, default: usize) -> usize {
    raw.iter()
        .position(|x| x == name)
        .map_or(default, |i| raw[i + 1].parse().unwrap())
}

fn timed(name: &str, threads: usize, expected: &[u64], mut run: impl FnMut() -> Vec<u64>) {
    for sample in 0..33 {
        let start = Instant::now();
        let out = run();
        let ms = start.elapsed().as_secs_f64() * 1000.;
        assert_eq!(out, expected);
        if sample >= 3 {
            println!(
                "{}",
                serde_json::json!({"kind":"sample","name":name,"threads":threads,
                    "sample":sample-3,"ms":ms,"correct":true})
            );
        }
    }
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let rows = flag(&raw, "--rows", 28672);
    let cols = flag(&raw, "--cols", 32768);
    let pbits = flag(&raw, "--pbits", 16);
    let query_bits = flag(&raw, "--query-bits", 54);
    let u8_storage = raw
        .iter()
        .position(|x| x == "--storage")
        .is_some_and(|i| raw[i + 1] == "u8");
    assert!(!u8_storage || pbits <= 8, "u8 storage needs pbits <= 8");
    let q = 1u64 << 54;
    let mut rng = ChaCha20Rng::seed_from_u64(0x2417);
    let entry_mask = ((1u32 << pbits) - 1) as u16;
    let db16: Vec<u16> = (0..rows * cols)
        .map(|_| (rng.next_u32() as u16) & entry_mask)
        .collect();
    let query: Vec<_> = (0..rows)
        .map(|_| ((rng.next_u64() & ((1 << query_bits) - 1)) << (54 - query_bits)) & (q - 1))
        .collect();
    let prepared = PreparedU16Query::new(&query, q).unwrap();
    let expected: Vec<_> = db16
        .par_chunks_exact(rows)
        .map(|c| dot_u16(c, &query) & (q - 1))
        .collect();
    println!(
        "{}",
        serde_json::json!({"kind":"setup","rows":rows,"cols":cols,"pbits":pbits,"query_bits":query_bits,
            "storage":if u8_storage {"u8"} else {"u16"},"database_bytes":rows * cols * if u8_storage {1} else {2},
            "interleaved":PreparedU16Query::supports_interleaved(),
            "scan_skipped_digits":prepared.skipped_low_digits()})
    );
    if u8_storage {
        let mut db: Vec<u8> = db16.iter().map(|&x| x as u8).collect();
        drop(db16);
        for threads in [1, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            pool.install(|| {
                timed("word", threads, &expected, || {
                    db.par_chunks_exact(rows)
                        .map(|c| dot_u8(c, &query) & (q - 1))
                        .collect()
                })
            });
        }
        if PreparedU16Query::supports_interleaved() {
            db.par_chunks_mut(rows * 16)
                .for_each(|band| PreparedU16Query::interleave_u8_columns(band, rows));
            for threads in [1, 8] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap();
                pool.install(|| {
                    timed("interleaved", threads, &expected, || {
                        let mut out = vec![0; cols];
                        out.par_chunks_mut(16)
                            .zip(db.par_chunks(rows * 16))
                            .for_each(|(out, db)| prepared.multiply_interleaved_u8(db, out));
                        out
                    })
                });
            }
        }
        return;
    }
    let mut db = db16;
    for threads in [1, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        pool.install(|| {
            timed("word", threads, &expected, || {
                db.par_chunks_exact(rows)
                    .map(|c| dot_u16(c, &query) & (q - 1))
                    .collect()
            });
            timed("byte", threads, &expected, || {
                db.par_chunks_exact(rows).map(|c| prepared.dot(c)).collect()
            });
        });
    }
    if PreparedU16Query::supports_interleaved() {
        db.par_chunks_mut(rows * 16)
            .for_each(|band| PreparedU16Query::interleave_columns(band, rows));
        for threads in [1, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            pool.install(|| {
                timed("interleaved", threads, &expected, || {
                    let mut out = vec![0; cols];
                    out.par_chunks_mut(16)
                        .zip(db.par_chunks(rows * 16))
                        .for_each(|(out, db)| prepared.multiply_interleaved(db, out));
                    out
                })
            });
        }
    }
}
