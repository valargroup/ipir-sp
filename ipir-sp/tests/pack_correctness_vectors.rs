//! Committed golden pack vectors for Inspiring and Reinspiring backends.
//!
//! Regenerate with:
//! ```text
//! IPIR_SP_WRITE_FIXTURES=1 cargo test -p ipir-sp --test pack_correctness_vectors -- --nocapture
//! ```

use std::fs;
use std::path::PathBuf;

use inspiring::{GadgetParams, PackingKeys, RlweParams, TopKeyImages};
use ipir_sp::server::{build_pack_preprocessed_blocks, pack_intermediate_blocks, CrsBlock};
use ipir_sp::{build_reinspiring_blocks, pack_intermediate_blocks_reinspiring};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use spiral_rs::poly::{from_ntt_alloc, to_ntt_alloc, PolyMatrix, PolyMatrixRaw};

const SINGLE_CRT_Q: u64 = 72_057_594_037_641_217;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FixtureParams {
    d: usize,
    q: u64,
    p: u64,
    sigma: f64,
    bits_per: u32,
    ell: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackFixture {
    schema_version: u64,
    name: String,
    params: FixtureParams,
    /// Seed for ChaCha20 key generation (`PackingKeys::generate_full`).
    key_seed: [u8; 32],
    /// Deterministic ternary-ish secret coeffs used for key gen.
    secret_coeffs: Vec<u64>,
    /// CRS rows: length `d`, each length `d`.
    crs_rows: Vec<Vec<u64>>,
    /// Online `b` scalars for the single pack block.
    b_scalars: Vec<u64>,
    /// Golden packed ciphertext coefficients (Inspiring path).
    golden_c1: Vec<u64>,
    golden_c2: Vec<u64>,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn tiny_params() -> RlweParams {
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
    .expect("tiny params")
}

fn prodlike_params() -> RlweParams {
    RlweParams::new(
        16,
        SINGLE_CRT_Q,
        1 << 14,
        6.4,
        GadgetParams {
            bits_per: 19,
            ell: 3,
        },
    )
    .expect("prodlike params")
}

fn build_crs_rows(params: &RlweParams, seed: u64) -> Vec<Vec<u64>> {
    (0..params.d)
        .map(|row| {
            (0..params.d)
                .map(|col| {
                    (seed
                        .wrapping_mul(1_000_003)
                        .wrapping_add(row as u64 * 65_537)
                        .wrapping_add(col as u64 * 17)
                        .wrapping_add(1))
                        % params.q
                })
                .collect()
        })
        .collect()
}

fn secret_coeffs(params: &RlweParams, seed: u64) -> Vec<u64> {
    (0..params.d)
        .map(|i| match (i as u64 + seed) % 3 {
            0 => 0,
            1 => 1,
            _ => params.q - 1,
        })
        .collect()
}

fn b_scalars(params: &RlweParams, seed: u64) -> Vec<u64> {
    (0..params.d)
        .map(|i| (seed.wrapping_mul(11).wrapping_add(i as u64 * 13 + 7)) % params.q)
        .collect()
}

fn make_fixture(name: &str, params: &RlweParams, seed: u64, key_seed: [u8; 32]) -> PackFixture {
    let crs_rows = build_crs_rows(params, seed);
    let secret = secret_coeffs(params, seed);
    let b = b_scalars(params, seed ^ 0xBEEF);

    let block = CrsBlock {
        rows: crs_rows.clone(),
    };
    let pre = build_pack_preprocessed_blocks(params, &[block]).expect("preprocess");
    let mut secret_raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    secret_raw.get_poly_mut(0, 0)[..params.d].copy_from_slice(&secret);
    let mut rng = ChaCha20Rng::from_seed(key_seed);
    let keys = PackingKeys::generate_full(params, &to_ntt_alloc(&secret_raw), &mut rng);
    let top = TopKeyImages::build(params);
    let packed = pack_intermediate_blocks(&b, &keys, &top, &pre).expect("pack");
    let raw = from_ntt_alloc(&packed[0].inner);

    PackFixture {
        schema_version: 1,
        name: name.to_string(),
        params: FixtureParams {
            d: params.d,
            q: params.q,
            p: params.p,
            sigma: params.sigma_chi,
            bits_per: params.gadget.bits_per,
            ell: params.gadget.ell,
        },
        key_seed,
        secret_coeffs: secret,
        crs_rows,
        b_scalars: b,
        golden_c1: raw.get_poly(0, 0).to_vec(),
        golden_c2: raw.get_poly(1, 0).to_vec(),
    }
}

fn write_fixtures_if_requested() {
    if std::env::var_os("IPIR_SP_WRITE_FIXTURES").is_none() {
        return;
    }
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).expect("create fixtures dir");

    let tiny = make_fixture(
        "tiny_d8_q12289_seed42",
        &tiny_params(),
        42,
        [42u8; 32],
    );
    let prodlike = make_fixture(
        "prodlike_d16_q56bit_seed9",
        &prodlike_params(),
        9,
        [9u8; 32],
    );

    for fix in [&tiny, &prodlike] {
        let path = dir.join(format!("{}.json", fix.name));
        let json = serde_json::to_string_pretty(fix).expect("serialize");
        fs::write(&path, json + "\n").expect("write fixture");
        eprintln!("wrote {}", path.display());
    }

    let manifest = json!({
        "schema_version": 1,
        "files": [
            "tiny_d8_q12289_seed42.json",
            "prodlike_d16_q56bit_seed9.json"
        ]
    });
    fs::write(
        dir.join("MANIFEST.json"),
        serde_json::to_string_pretty(&manifest).unwrap() + "\n",
    )
    .expect("write manifest");
}

fn load_fixture(name: &str) -> PackFixture {
    let path = fixtures_dir().join(format!("{name}.json"));
    let text = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing fixture {}: {e}. Run with IPIR_SP_WRITE_FIXTURES=1 to generate.",
            path.display()
        )
    });
    serde_json::from_str(&text).expect("parse fixture")
}

fn params_from_fixture(fix: &PackFixture) -> RlweParams {
    RlweParams::new(
        fix.params.d,
        fix.params.q,
        fix.params.p,
        fix.params.sigma,
        GadgetParams {
            bits_per: fix.params.bits_per,
            ell: fix.params.ell,
        },
    )
    .expect("fixture params")
}

fn assert_backends_match_golden(fix: &PackFixture) {
    let params = Box::leak(Box::new(params_from_fixture(fix)));
    let block = CrsBlock {
        rows: fix.crs_rows.clone(),
    };
    let pre = build_pack_preprocessed_blocks(params, &[block]).expect("preprocess");
    let mut secret_raw = PolyMatrixRaw::zero(&params.spiral, 1, 1);
    secret_raw.get_poly_mut(0, 0)[..params.d].copy_from_slice(&fix.secret_coeffs);
    let mut rng = ChaCha20Rng::from_seed(fix.key_seed);
    let keys = PackingKeys::generate_full(params, &to_ntt_alloc(&secret_raw), &mut rng);
    let top = TopKeyImages::build(params);

    let inspiring = pack_intermediate_blocks(&fix.b_scalars, &keys, &top, &pre).expect("inspiring");
    let insp_raw = from_ntt_alloc(&inspiring[0].inner);
    assert_eq!(
        insp_raw.get_poly(0, 0),
        fix.golden_c1.as_slice(),
        "{}: Inspiring c1 != golden",
        fix.name
    );
    assert_eq!(
        insp_raw.get_poly(1, 0),
        fix.golden_c2.as_slice(),
        "{}: Inspiring c2 != golden",
        fix.name
    );

    let rein_pre = build_reinspiring_blocks(&pre).expect("reinspiring preprocess");
    let reinspiring =
        pack_intermediate_blocks_reinspiring(&fix.b_scalars, &keys, &rein_pre).expect("reinspiring");
    let rein_raw = from_ntt_alloc(&reinspiring[0].inner);
    assert_eq!(
        rein_raw.get_poly(0, 0),
        fix.golden_c1.as_slice(),
        "{}: Reinspiring c1 != golden",
        fix.name
    );
    assert_eq!(
        rein_raw.get_poly(1, 0),
        fix.golden_c2.as_slice(),
        "{}: Reinspiring c2 != golden",
        fix.name
    );
}

#[test]
fn write_fixtures_when_env_set() {
    write_fixtures_if_requested();
}

#[test]
fn tiny_fixture_inspiring_and_reinspiring_match_golden() {
    let fix = load_fixture("tiny_d8_q12289_seed42");
    assert_eq!(fix.schema_version, 1);
    assert_eq!(fix.params.d, 8);
    assert!(
        fix.crs_rows.iter().flatten().any(|&c| c != 0),
        "CRS must be non-zero"
    );
    assert_backends_match_golden(&fix);
}

#[test]
fn prodlike_fixture_inspiring_and_reinspiring_match_golden() {
    let fix = load_fixture("prodlike_d16_q56bit_seed9");
    assert_eq!(fix.schema_version, 1);
    assert_eq!(fix.params.d, 16);
    assert_eq!(fix.params.q, SINGLE_CRT_Q);
    assert!(
        fix.crs_rows.iter().flatten().any(|&c| c != 0),
        "CRS must be non-zero"
    );
    assert_backends_match_golden(&fix);
}

#[test]
fn manifest_lists_committed_fixtures() {
    let text = fs::read_to_string(fixtures_dir().join("MANIFEST.json")).expect(
        "missing MANIFEST.json — run with IPIR_SP_WRITE_FIXTURES=1 once to generate",
    );
    let v: serde_json::Value = serde_json::from_str(&text).expect("manifest json");
    assert_eq!(v["schema_version"], 1);
    let files = v["files"].as_array().expect("files");
    assert!(files.iter().any(|f| f == "tiny_d8_q12289_seed42.json"));
    assert!(files.iter().any(|f| f == "prodlike_d16_q56bit_seed9.json"));
}
