#![cfg(feature = "cuda")]
use inspiring::{GadgetParams, RlweParams};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use simplepir_kernel::{cuda::CudaKernel, FirstDimKernel, ScalarKernel};
fn params() -> RlweParams {
    RlweParams::new(
        2048,
        72_057_594_037_641_217,
        1 << 14,
        6.4,
        GadgetParams {
            bits_per: 19,
            ell: 3,
        },
    )
    .unwrap()
}
#[test]
#[ignore = "requires a real NVIDIA GPU and NVRTC; never silently skips"]
fn exact_arithmetic_and_snapshot_replacement() {
    let mut gpu = CudaKernel::new(0).expect("GPU is required");
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let mut rlwe = params();
    for rows in [0, 1, 255, 256, 4095, 4096, 4097, 8193] {
        for cols in [0, 1, 7] {
            let mut db: Vec<u16> = (0..rows * cols).map(|_| rng.next_u32() as u16).collect();
            let query: Vec<u64> = (0..rows)
                .map(|i| match i % 8 {
                    0 => 0,
                    1 => u64::MAX,
                    2 => 72_057_594_037_641_216,
                    3 => u32::MAX as u64,
                    4 => 1 << 32,
                    5 => 1,
                    _ => rng.next_u64(),
                })
                .collect();
            for pass in 0..3 {
                if pass == 1 {
                    db.fill(u16::MAX);
                }
                if pass == 2 {
                    db.fill(0);
                }
                gpu.try_prepare(&db, rows, cols).unwrap();
                for q in [1, 2, 72_057_594_037_641_217, u64::MAX] {
                    rlwe.q = q;
                    let mut expected = vec![0; cols];
                    ScalarKernel.multiply_query(
                        &rlwe,
                        &db,
                        rows,
                        cols,
                        &query,
                        u16::MAX as u64,
                        &mut expected,
                    );
                    for _ in 0..2 {
                        let mut actual = vec![u64::MAX; cols];
                        gpu.try_multiply_query(
                            &rlwe,
                            &db,
                            rows,
                            cols,
                            &query,
                            u16::MAX as u64,
                            &mut actual,
                        )
                        .unwrap();
                        assert_eq!(actual, expected, "{rows}x{cols}, q={q}, pass={pass}");
                    }
                }
            }
        }
    }
}
#[test]
#[ignore = "requires a real NVIDIA GPU and NVRTC; never silently skips"]
fn concurrent_calls_and_errors() {
    let rlwe = params();
    let (rows, cols) = (4097, 13);
    let db = vec![u16::MAX; rows * cols];
    let mut gpu = CudaKernel::new(0).unwrap();
    let mut out = vec![0; cols];
    assert!(gpu
        .try_multiply_query(&rlwe, &db, rows, cols, &vec![1; rows], 65535, &mut out)
        .is_err());
    gpu.try_prepare(&db, rows, cols).unwrap();
    // Another instance with identical dimensions must not replace this upload.
    let mut other = CudaKernel::new(0).unwrap();
    let zero_db = vec![0; db.len()];
    other.try_prepare(&zero_db, rows, cols).unwrap();
    other
        .try_multiply_query(
            &rlwe,
            &zero_db,
            rows,
            cols,
            &vec![u64::MAX; rows],
            0,
            &mut out,
        )
        .unwrap();
    assert_eq!(out, vec![0; cols]);
    let mut invalid = rlwe.clone();
    invalid.q = 0;
    assert!(gpu
        .try_multiply_query(&invalid, &db, rows, cols, &vec![1; rows], 65535, &mut out)
        .is_err());
    std::thread::scope(|scope| {
        for value in [0, 1, u64::MAX, rlwe.q - 1] {
            let (gpu, db, rlwe) = (&gpu, &db, &rlwe);
            scope.spawn(move || {
                let query = vec![value; rows];
                let mut expected = vec![0; cols];
                ScalarKernel.multiply_query(rlwe, db, rows, cols, &query, 65535, &mut expected);
                for _ in 0..10 {
                    let mut out = vec![0; cols];
                    gpu.try_multiply_query(rlwe, db, rows, cols, &query, 65535, &mut out)
                        .unwrap();
                    assert_eq!(out, expected);
                    let ms = gpu
                        .multiply_query_timed(rlwe, db, rows, cols, &query, &mut out)
                        .unwrap();
                    assert!(ms.is_finite() && ms >= 0.0);
                    assert_eq!(out, expected);
                }
            });
        }
    });
    assert!(gpu
        .try_multiply_query(&rlwe, &db, rows, cols, &[], 65535, &mut out)
        .is_err());
    assert!(gpu.try_prepare(&[], usize::MAX, 2).is_err());
    assert!(gpu
        .try_multiply_query(&rlwe, &db, rows, cols, &vec![1; rows], 65535, &mut out)
        .is_err());
    assert!(CudaKernel::new(usize::MAX).is_err());
}

#[test]
fn oversized_device_ordinal_fails_before_loading_cuda() {
    assert!(
        matches!(CudaKernel::new(i32::MAX as usize + 1), Err(e) if e.to_string().contains("ordinal"))
    );
    #[cfg(target_pointer_width = "64")]
    assert!(matches!(CudaKernel::new(1usize << 32), Err(e) if e.to_string().contains("ordinal")));
}
