use inspiring::key_switching::{ks_call_count, KeySwitchingMatrix};
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

fn crs<'a>(params: &'a RlweParams) -> PolyMatrixNTT<'a> {
    let mut crs = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
    for row in 0..params.d {
        for col in 0..params.d {
            crs.get_poly_mut(row, 0)[col] = (row * params.d + col + 1) as u64;
        }
    }
    crs.ntt()
}

fn batch(params: &RlweParams) -> LweBatch {
    LweBatch {
        inner: (0..params.d)
            .map(|idx| LweCiphertext {
                a: vec![0; params.d],
                b: idx as u64,
            })
            .collect(),
    }
}

#[test]
fn pack_uses_linear_cascade_switch_count_not_cdks_tree_shape() {
    let params = params();
    let crs = crs(&params);
    let pre = PackPreprocessed::build(&params, &crs, zero_ks(&params), zero_ks(&params))
        .expect("valid preprocessing");

    ks_call_count::reset();
    let _ = pack(&batch(&params), &pre).expect("pack succeeds");

    assert_eq!(ks_call_count::get(), (params.d - 1) as u64);
    assert_ne!(
        ks_call_count::get(),
        params.d.ilog2() as u64,
        "CDKS-style logarithmic-level switching accidentally appeared"
    );
}

#[test]
fn preprocessing_api_accepts_exactly_two_base_key_switching_matrices() {
    let params = params();
    let crs = crs(&params);
    let pre = PackPreprocessed::build(&params, &crs, zero_ks(&params), zero_ks(&params))
        .expect("valid preprocessing");

    assert_eq!(pre.kg.mat.rows, 2);
    assert_eq!(pre.kh.mat.rows, 2);
    assert_eq!(pre.kg_images_left.len(), params.d / 2 - 1);
    assert_eq!(pre.kg_images_right.len(), params.d / 2 - 1);
}
