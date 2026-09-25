use simplepir_kernel::{FirstDimKernel, ScalarKernel};

fn check(kernel: &mut impl FirstDimKernel<u16>) {
    let (rows, cols) = (4097, 3);
    let db: Vec<u16> = (0..rows * cols).map(|i| (i * 171 + 65535) as u16).collect();
    kernel.try_prepare(&db, rows, cols).unwrap();
    for q in [2, 1u64 << 54, 1u64 << 63] {
        for case in 0..3 {
            let query: Vec<u64> = (0..rows)
                .map(|i| match case {
                    0 => 0,
                    1 => q - 1,
                    _ => (i as u64 * 1234567891011) & (q - 1),
                })
                .collect();
            let mut out = vec![0; cols];
            kernel
                .try_multiply_power_of_two(q, &db, rows, cols, &query, &mut out)
                .unwrap();
            let expected: Vec<u64> = db
                .chunks_exact(rows)
                .map(|col| {
                    (col.iter()
                        .zip(&query)
                        .map(|(&a, &b)| a as u128 * b as u128)
                        .sum::<u128>()
                        % q as u128) as u64
                })
                .collect();
            assert_eq!(out, expected);
        }
    }
    for (q, rows, cols, db, query, mut out) in [
        (8, 0, 1, vec![], vec![], vec![0]),
        (8, 1, 0, vec![], vec![0], vec![]),
        (7, 1, 1, vec![1], vec![0], vec![0]),
        (8, 1, 1, vec![1], vec![8], vec![0]),
        (8, 2, 1, vec![1], vec![0], vec![0]),
    ] {
        assert!(kernel
            .try_multiply_power_of_two(q, &db, rows, cols, &query, &mut out)
            .is_err());
    }
}
#[test]
fn cpu_native_modulus_matches_integer_oracle() {
    check(&mut ScalarKernel);
}
#[cfg(feature = "cuda")]
#[test]
#[ignore = "requires NVIDIA GPU and NVRTC"]
fn cuda_native_modulus_matches_integer_oracle() {
    check(&mut simplepir_kernel::cuda::CudaKernel::new(0).unwrap());
}
