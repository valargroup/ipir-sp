//! Counterfactual public gadget screening, first output block by default.
//! Args: rows cols block. Reports are not executable profiles or certificates.
use ipir_sp::native::*;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use reinspiring::{
    native::*,
    noise::{gaussian_counts, WeightNorms},
};
use serde_json::json;
fn norms(n: WeightNorms) -> serde_json::Value {
    json!({"l1":n.l1.to_string(),"l2_squared":n.l2_squared.to_string(),"max":n.max.to_string()})
}
fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .map(|s| s.parse().unwrap())
        .collect();
    let rows = *args.first().unwrap_or(&28672);
    let cols = *args.get(1).unwrap_or(&32768);
    let block = *args.get(2).unwrap_or(&0);
    let p = NativeParams::new(2048, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
    let setup = NativePublicSetup::new(
        NativeProfile::new(p, rows, cols).unwrap(),
        [7; 32],
        [19; 32],
    );
    let mut rng = ChaCha20Rng::seed_from_u64(0x2417);
    let db: Vec<u16> = (0..rows * cols).map(|_| rng.next_u32() as u16).collect();
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for x in &db {
        hash.update(x.to_le_bytes());
    }
    println!(
        "{}",
        json!({"format":"native-gadget-screen-v1","rows":rows,"cols":cols,"block":block,"d":2048,"q_bits":54,"p_bits":16,"setup_id":setup.id(),"database_sha256":format!("{:x}",hash.finalize()),"sampler_counts":gaussian_counts().into_iter().map(|(x,n)|json!([x,n.to_string()])).collect::<Vec<_>>()})
    );
    NativeServer::screen_gadgets(&setup,&db,block,|widths,b| {
        println!("{}",json!({"kg_widths":widths,"kg_limbs":b.packing.kg_limbs.into_iter().map(norms).collect::<Vec<_>>(),"collapse_secret":norms(b.packing.collapse_secret),"final_mask":b.packing.final_mask,"query":norms(b.query)}));
    }).unwrap();
}
