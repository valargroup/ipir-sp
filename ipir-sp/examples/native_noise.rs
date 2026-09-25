//! Public snapshot noise report. Args: rows cols Kh-wire-bits (defaults: 28672 32768 54).
//! Deterministic research snapshot; never a certificate for a different database.
use ipir_sp::native::*;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use reinspiring::{
    native::*,
    noise::{gaussian_cdf_sha256, gaussian_counts, WeightNorms},
};
use serde_json::{json, Value};
fn norms(n: WeightNorms) -> Value {
    json!({"l1":n.l1.to_string(),"l2_squared":n.l2_squared.to_string(),"max":n.max.to_string()})
}
fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let two_mask = raw.iter().any(|x| x == "--two-mask");
    let args: Vec<usize> = raw
        .into_iter()
        .filter(|x| x != "--two-mask")
        .map(|x| x.parse().unwrap())
        .collect();
    let rows = *args.first().unwrap_or(&28672);
    let cols = *args.get(1).unwrap_or(&32768);
    let kh_bits = *args.get(2).unwrap_or(&54);
    let published_bits = *args.get(3).unwrap_or(&64);
    let p = NativeParams::new(2048, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    let profile = NativeProfile::new(p, rows, cols)
        .unwrap()
        .with_kh_bits(kh_bits)
        .unwrap();
    let profile = if two_mask {
        profile.with_two_mask_output().unwrap()
    } else {
        profile
    };
    let profile = profile.with_published_mask_bits(published_bits).unwrap();
    let setup = NativePublicSetup::new(profile, [7; 32], [19; 32]);
    let mut rng = ChaCha20Rng::seed_from_u64(0x2417);
    let db: Vec<u16> = (0..rows * cols).map(|_| rng.next_u32() as u16).collect();
    // Bind evidence to both the declared snapshot identity and the actual contents.
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for x in &db {
        hash.update(x.to_le_bytes());
    }
    let db_hash = format!("{:x}", hash.finalize());
    eprintln!("Analyzing {rows}x{cols} public snapshot, Kh transport {kh_bits} bits");
    let (server, blocks) = NativeServer::build_analyzed(setup, db).unwrap();
    let blocks: Vec<_> = blocks.into_iter().map(|b| json!({
        "weights":norms(b.packing.weights.independent(b.query)),
        "query_l1":b.query.l1.to_string(),
        "kh_l1":b.packing.kh_l1.to_string(),
        "public_mask_screens":b.packing.public_mask_screens.iter().map(|(bits,w)|json!({"bits":bits,"weights":norms(w.independent(b.query))})).collect::<Vec<_>>(),
        "one_limb":b.packing.one_limb.into_iter().map(|v| json!({"bits":v.bits,"weights":norms(v.weights.independent(b.query))})).collect::<Vec<_>>()
    })).collect();
    println!(
        "{}",
        json!({
            "format":if published_bits!=64 && two_mask { "native-noise-two-mask-rounded-v1" } else if published_bits!=64 { "native-noise-rounded-v1" } else if two_mask { "native-noise-two-mask-v1" } else { "native-noise-v1" },"d":2048,"q_bits":54,"p_bits":16,
            "published_mask_bits":published_bits,"published_bytes":server.published().to_bytes().len(),
            "rows":rows,"cols":cols,"query_bits":49,"response_bits":22,"kh_bits":kh_bits,
            "setup_id":server.setup().id().iter().map(|x|format!("{x:02x}")).collect::<String>(),
            "database_sha256":db_hash,
            "sampler_sha256":gaussian_cdf_sha256().iter().map(|x|format!("{x:02x}")).collect::<String>(),
            "sampler_counts":gaussian_counts().into_iter().map(|(x,n)|json!([x,n.to_string()])).collect::<Vec<_>>(),
            "blocks":blocks
        })
    );
}
