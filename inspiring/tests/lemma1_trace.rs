use inspiring::automorph::trace;
use inspiring::{GadgetParams, RlweParams};
use spiral_rs::poly::{PolyMatrix, PolyMatrixRaw};

fn params(d: usize) -> RlweParams {
    RlweParams::new(
        d,
        12289,
        4,
        3.2,
        GadgetParams {
            bits_per: 3,
            ell: 5,
        },
    )
    .expect("valid tiny test parameters")
}

fn raw_from_coeffs<'a>(params: &'a RlweParams, coeffs: &[u64]) -> PolyMatrixRaw<'a> {
    let mut poly = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    poly.get_poly_mut(0, 0).copy_from_slice(coeffs);
    poly
}

#[test]
fn trace_keeps_only_d_times_constant_for_d8_and_d16() {
    for d in [8, 16] {
        let params = params(d);
        let coeffs: Vec<_> = (0..d)
            .map(|idx| (idx as u64 * 17 + 42) % params.q)
            .collect();
        let traced = trace(&raw_from_coeffs(&params, &coeffs));

        let mut expected = vec![0; d];
        expected[0] = (params.d as u64 * coeffs[0]) % params.q;
        assert_eq!(traced.get_poly(0, 0), expected);
    }
}
