use inspiring::automorph::{h, tau_g_pow};
use inspiring::collapse::collapse;
use inspiring::intermediate::{aggregate, transform};
use inspiring::key_switching::{automorphic_image, KeySwitchingMatrix};
use inspiring::{pack, GadgetParams, LweBatch, LweCiphertext, PackPreprocessed, RlweParams};
use spiral_rs::poly::{PolyMatrix, PolyMatrixNTT, PolyMatrixRaw};

fn params() -> RlweParams {
    RlweParams::new(
        8,
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

fn zero_ks<'a>(params: &'a RlweParams) -> KeySwitchingMatrix<'a> {
    KeySwitchingMatrix {
        mat: PolyMatrixNTT::zero(&params.spiral, 2, params.gadget.ell),
    }
}

fn batch(params: &RlweParams) -> LweBatch {
    LweBatch {
        inner: (0..params.d)
            .map(|row| LweCiphertext {
                a: (0..params.d)
                    .map(|col| (row * params.d + col + 3) as u64)
                    .collect(),
                b: (row as u64 * 11 + 7) % params.q,
            })
            .collect(),
    }
}

fn crs_from_batch<'a>(params: &'a RlweParams, batch: &LweBatch) -> PolyMatrixNTT<'a> {
    let mut crs = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
    for (row, ct) in batch.inner.iter().enumerate() {
        crs.get_poly_mut(row, 0).copy_from_slice(&ct.a);
    }
    crs.ntt()
}

fn all_online_pack<'a>(
    params: &'a RlweParams,
    batch: &LweBatch,
    kg: &KeySwitchingMatrix<'a>,
    kh: &KeySwitchingMatrix<'a>,
) -> PolyMatrixNTT<'a> {
    let irctxs: Vec<_> = batch.inner.iter().map(|ct| transform(params, ct)).collect();
    let agg = aggregate(params, &irctxs);
    let two_d = 2 * params.d as u64;
    let h_d = h(params.d);
    let left_images: Vec<_> = (0..(params.d / 2 - 1))
        .map(|i| automorphic_image(kg, tau_g_pow(i, params.d)))
        .collect();
    let right_images: Vec<_> = (0..(params.d / 2 - 1))
        .map(|i| automorphic_image(kg, (tau_g_pow(i, params.d) * h_d) % two_d))
        .collect();

    collapse(params, agg, &left_images, &right_images, kh).inner
}

#[test]
fn online_pack_matches_all_online_execution_for_same_crs() {
    let params = params();
    let batch = batch(&params);
    let crs = crs_from_batch(&params, &batch);
    let kg = zero_ks(&params);
    let kh = zero_ks(&params);
    let expected = all_online_pack(&params, &batch, &kg, &kh);
    let pre = PackPreprocessed::build(&params, &crs, kg, kh).expect("valid preprocessing");

    let actual = pack(&batch, &pre).expect("pack succeeds").inner;

    assert_eq!(actual.as_slice(), expected.as_slice());
}
