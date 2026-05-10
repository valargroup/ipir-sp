use inspiring::{GadgetParams, InspiringError, LweBatch, LweCiphertext, RlweParams};

fn gadget() -> GadgetParams {
    GadgetParams {
        bits_per: 3,
        ell: 5,
    }
}

#[test]
fn rlwe_params_reject_invalid_shapes_and_moduli() {
    assert!(matches!(
        RlweParams::new(7, 12289, 4, 3.2, gadget()),
        Err(InspiringError::InvalidParams(_))
    ));
    assert!(matches!(
        RlweParams::new(8, 12288, 4, 3.2, gadget()),
        Err(InspiringError::InvalidParams(_))
    ));
    assert!(matches!(
        RlweParams::new(8, 12289, 1, 3.2, gadget()),
        Err(InspiringError::InvalidParams(_))
    ));
    assert!(matches!(
        RlweParams::new(8, 12289, 4, f64::NAN, gadget()),
        Err(InspiringError::InvalidParams(_))
    ));
}

#[test]
fn lwe_batch_validation_rejects_wrong_batch_and_ciphertext_lengths() {
    let params = RlweParams::new(8, 12289, 4, 3.2, gadget()).expect("valid params");

    let short_batch = LweBatch {
        inner: vec![LweCiphertext {
            a: vec![0; params.d],
            b: 0,
        }],
    };
    assert!(matches!(
        short_batch.validate(&params),
        Err(InspiringError::LweShape(_))
    ));

    let bad_ciphertext = LweBatch {
        inner: (0..params.d)
            .map(|idx| LweCiphertext {
                a: vec![0; params.d - usize::from(idx == 0)],
                b: 0,
            })
            .collect(),
    };
    assert!(matches!(
        bad_ciphertext.validate(&params),
        Err(InspiringError::LweShape(_))
    ));
}
