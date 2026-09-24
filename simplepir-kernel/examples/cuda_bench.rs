//! Reproducible correctness-checked benchmark; CUDA, upload, and wall timing.
use inspiring::{GadgetParams, RlweParams};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use simplepir_kernel::{cuda::CudaKernel, ChunkedSplitKernel, FirstDimKernel, U16Avx512Kernel};
use std::time::Instant;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rows = args.get(1).map_or(32768, |x| x.parse().unwrap());
    let cols = args.get(2).map_or(12288, |x| x.parse().unwrap());
    let count = args.get(3).map_or(100, |x| x.parse::<usize>().unwrap());
    let rlwe = RlweParams::new(
        2048,
        72_057_594_037_641_217,
        1 << 14,
        6.4,
        GadgetParams {
            bits_per: 19,
            ell: 3,
        },
    )
    .unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let db: Vec<u16> = (0..rows * cols)
        .map(|_| (rng.next_u32() % (1 << 14)) as u16)
        .collect();
    let queries: Vec<Vec<u64>> = (0..count)
        .map(|_| (0..rows).map(|_| rng.next_u64()).collect())
        .collect();
    let cpu: Box<dyn FirstDimKernel<u16>> = if U16Avx512Kernel::is_supported() {
        Box::new(U16Avx512Kernel::default())
    } else {
        Box::new(ChunkedSplitKernel::default())
    };
    let now = Instant::now();
    let mut gpu = CudaKernel::new(0).unwrap();
    println!(
        "initialization_ms={:.3}",
        now.elapsed().as_secs_f64() * 1000.0
    );
    let now = Instant::now();
    gpu.try_prepare(&db, rows, cols).unwrap();
    println!(
        "shape={rows}x{cols}, db_bytes={}, upload_ms={:.3}, cpu_avx512={}, cpu_threads={}",
        db.len() * 2,
        now.elapsed().as_secs_f64() * 1000.0,
        U16Avx512Kernel::is_supported(),
        rayon::current_num_threads()
    );
    let mut expected = vec![vec![0; cols]; count];
    for (q, out) in queries.iter().zip(&mut expected) {
        cpu.multiply_query(&rlwe, &db, rows, cols, q, 16383, out);
    }
    let mut out = vec![0; cols];
    for q in queries.iter().cycle().take(10) {
        gpu.try_multiply_query(&rlwe, &db, rows, cols, q, 16383, &mut out)
            .unwrap();
    }
    for repetition in 0..3 {
        let now = Instant::now();
        for (q, expected) in queries.iter().zip(&expected) {
            cpu.multiply_query(&rlwe, &db, rows, cols, q, 16383, &mut out);
            assert_eq!(&out, expected);
        }
        println!(
            "repeat={repetition}, cpu_wall_ms_per_query={:.3}",
            now.elapsed().as_secs_f64() * 1000.0 / count as f64
        );
        for callers in [1, 4] {
            let now = Instant::now();
            let results: Vec<_> = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..callers)
                    .map(|caller| {
                        let (gpu, db, queries, expected, rlwe) =
                            (&gpu, &db, &queries, &expected, &rlwe);
                        scope.spawn(move || {
                            let mut total_kernel = 0.0;
                            let mut total_latency = 0.0;
                            let mut out = vec![0; cols];
                            for i in (caller..count).step_by(callers) {
                                let start = Instant::now();
                                total_kernel +=
                                    gpu.multiply_query_timed(
                                        rlwe,
                                        db,
                                        rows,
                                        cols,
                                        &queries[i],
                                        &mut out,
                                    )
                                    .unwrap() as f64;
                                total_latency += start.elapsed().as_secs_f64() * 1000.0;
                                assert_eq!(out, expected[i]);
                            }
                            (total_kernel, total_latency)
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            println!("repeat={repetition}, callers={callers}, queries={count}, gpu_wall_ms_per_query={:.3}, kernel_ms={:.3}, request_latency_ms={:.3}",
                now.elapsed().as_secs_f64()*1000.0/count as f64,
                results.iter().map(|x| x.0).sum::<f64>()/count as f64,
                results.iter().map(|x| x.1).sum::<f64>()/count as f64);
        }
    }
}
