//! The three public mask families must be pairwise distinct.
//!
//! Query masks (setup seed), `K_g` masks (`REFERENCE_W_SEED`) and `K_h` masks
//! (`REFERENCE_V_SEED`) are all expanded from ChaCha20 without a domain label.
//! Separating them properly changes the CRS and the wire format, so it waits
//! for the next profile ID. Until then this test pins that the deployed setup
//! seed and the reference seeds themselves give distinct masks, and that the
//! server-side guard rejects a collision.

use inspiring::{reference_mask_coeffs, REFERENCE_V_SEED, REFERENCE_W_SEED};
use ipir_sp::client::IPIRClient;
use ipir_sp::server::verify_query_masks_distinct_from_key_masks;
use ipir_sp::{ProductionSimplePirParams, SimplePirProfile};

/// The deployed row count; only the column count is reduced.
const ROWS: u64 = 28_672;

/// `--setup-seed` default of the nullifier server and the demo server.
const DEPLOYED_SETUP_SEED: u64 = 7;

/// Same mapping as `nullifier_pir::backend::seed_from_u64`.
fn seed_from_u64(value: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    seed
}

fn profile() -> ProductionSimplePirParams {
    ProductionSimplePirParams::new(ROWS, 2048 * 14, SimplePirProfile::P14)
        .expect("production profile")
}

fn negate(poly: &[u64], q: u64) -> Vec<u64> {
    poly.iter()
        .map(|&c| if c == 0 { 0 } else { q - c })
        .collect()
}

fn invert(poly: &[u64], q: u64) -> Vec<u64> {
    let d = poly.len();
    let mut out = vec![0u64; d];
    out[0] = poly[0];
    for idx in 1..d {
        let c = poly[d - idx];
        out[idx] = if c == 0 { 0 } else { q - c };
    }
    out
}

#[test]
fn mask_families_are_pairwise_distinct_for_reference_and_deployed_seeds() {
    let profile = profile();
    let rlwe = profile.rlwe();
    let client = IPIRClient::new(&profile);

    let kg = reference_mask_coeffs(rlwe, REFERENCE_W_SEED);
    let kh = reference_mask_coeffs(rlwe, REFERENCE_V_SEED);
    assert_eq!(kg.len(), rlwe.gadget.ell);
    assert_eq!(kh.len(), rlwe.gadget.ell);
    for g in &kg {
        assert_eq!(g.len(), rlwe.d);
        assert!(g.iter().any(|&c| c != 0), "K_g mask is zero");
        for h in &kh {
            assert_ne!(g, h, "a K_g mask equals a K_h mask");
            assert_ne!(
                *g,
                negate(h, rlwe.q),
                "a K_g mask equals a negated K_h mask"
            );
        }
    }

    // The deployed setup seed, the README example seed, the seeds the
    // production flow test uses, and the key seeds themselves. The last two
    // matter most: if a server operator ever passed a key seed as the setup
    // seed, the different samplers still keep the families apart.
    let setup_seeds = [
        seed_from_u64(DEPLOYED_SETUP_SEED),
        [0x1D; 32],
        [0x5A; 32],
        REFERENCE_W_SEED,
        REFERENCE_V_SEED,
    ];
    for seed in setup_seeds {
        let setup = client.generate_public_query_setup_simplepir_from_seed(seed);
        assert_eq!(setup.polys().len(), ROWS as usize / rlwe.d);
        verify_query_masks_distinct_from_key_masks(rlwe, setup.polys())
            .unwrap_or_else(|err| panic!("setup seed {seed:?}: {err}"));
        for (idx, poly) in setup.polys().iter().enumerate() {
            let inverse = invert(poly, rlwe.q);
            for mask in kg.iter().chain(&kh) {
                assert_ne!(poly, mask, "seed {seed:?} poly {idx} equals a key mask");
                assert_ne!(
                    &inverse, mask,
                    "seed {seed:?} poly {idx} equals a key mask under X^-1"
                );
            }
        }
    }
}

#[test]
fn guard_rejects_query_masks_that_coincide_with_key_masks() {
    let profile = profile();
    let rlwe = profile.rlwe();
    let client = IPIRClient::new(&profile);
    let honest = client
        .generate_public_query_setup_simplepir_from_seed(seed_from_u64(DEPLOYED_SETUP_SEED))
        .polys()
        .to_vec();
    verify_query_masks_distinct_from_key_masks(rlwe, &honest).expect("honest seed passes");

    let kg = reference_mask_coeffs(rlwe, REFERENCE_W_SEED);
    let kh = reference_mask_coeffs(rlwe, REFERENCE_V_SEED);
    let collisions: Vec<(&str, Vec<u64>)> = vec![
        ("K_g mask", kg[0].clone()),
        ("negated K_g mask", negate(&kg[0], rlwe.q)),
        ("K_g mask under X^-1", invert(&kg[0], rlwe.q)),
        (
            "negated K_g mask under X^-1",
            negate(&invert(&kg[0], rlwe.q), rlwe.q),
        ),
        ("last K_h mask", kh[rlwe.gadget.ell - 1].clone()),
        (
            "last K_h mask under X^-1",
            invert(&kh[rlwe.gadget.ell - 1], rlwe.q),
        ),
    ];
    for (label, collision) in collisions {
        let mut polys = honest.clone();
        let slot = polys.len() - 1;
        polys[slot] = collision;
        let err = verify_query_masks_distinct_from_key_masks(rlwe, &polys)
            .expect_err(&format!("{label} must be rejected"));
        assert!(
            matches!(err, inspiring::InspiringError::PreprocessMismatch(_)),
            "{label}: {err}"
        );
        assert!(
            err.to_string()
                .contains(&format!("query polynomial {slot}")),
            "{label}: {err}"
        );
    }

    let mut short = honest;
    short[0].pop();
    assert!(verify_query_masks_distinct_from_key_masks(rlwe, &short).is_err());
}
