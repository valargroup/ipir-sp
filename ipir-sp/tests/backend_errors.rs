use inspiring::RlweParams;
use ipir_sp::{
    server::{MatvecBackend, YServer},
    ProductionSimplePirParams, SimplePirProfile,
};
use simplepir_kernel::{FirstDimKernel, KernelError};
struct FailingKernel {
    preparation: bool,
}
impl FirstDimKernel<u16> for FailingKernel {
    fn try_prepare(&mut self, _: &[u16], _: usize, _: usize) -> Result<(), KernelError> {
        if self.preparation {
            Err(KernelError("prepare failure".into()))
        } else {
            Ok(())
        }
    }
    fn multiply_query(
        &self,
        _: &RlweParams,
        _: &[u16],
        _: usize,
        _: usize,
        _: &[u64],
        _: u64,
        _: &mut [u64],
    ) {
        panic!("fallible evaluation must be used");
    }
    fn try_multiply_query(
        &self,
        _: &RlweParams,
        _: &[u16],
        _: usize,
        _: usize,
        _: &[u64],
        _: u64,
        _: &mut [u64],
    ) -> Result<(), KernelError> {
        Err(KernelError("evaluation failure".into()))
    }
}
#[test]
fn backend_errors_are_returned() {
    let profile = ProductionSimplePirParams::new(2048, 2048 * 14, SimplePirProfile::P14).unwrap();
    for preparation in [true, false] {
        let server = YServer::try_with_kernel(
            profile.ypir().clone(),
            std::iter::repeat(0),
            false,
            true,
            Box::new(FailingKernel { preparation }),
        );
        if preparation {
            assert!(server.is_err());
        } else {
            let server = server.unwrap();
            let error = server
                .try_multiply_query(profile.rlwe(), &vec![0; server.db_rows_padded()])
                .unwrap_err();
            assert_eq!(error.to_string(), "evaluation failure");
        }
    }
    let cpu = YServer::try_from_profile_with_backend(
        &profile,
        std::iter::repeat(0),
        false,
        true,
        MatvecBackend::Cpu,
    )
    .unwrap();
    assert!(cpu.try_multiply_query(profile.rlwe(), &[]).is_err());
}
#[cfg(not(feature = "cuda"))]
#[test]
fn cuda_request_without_feature_fails() {
    let profile = ProductionSimplePirParams::new(2048, 2048 * 14, SimplePirProfile::P14).unwrap();
    let result = YServer::try_from_profile_with_backend(
        &profile,
        std::iter::repeat(0),
        false,
        true,
        MatvecBackend::Cuda { device: 0 },
    );
    assert!(matches!(result, Err(e) if e.to_string().contains("cuda feature")));
}
