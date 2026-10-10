//! Public snapshot noise report. Args: rows cols Kh-wire-bits published-mask-bits
//! (defaults: 28672 32768 54 64), plus `--two-mask` and `--query-bits N`
//! (dithered query transport below the default 49-bit nearest rounding).
//! Dithered reports use a distinct `...-dithered-v1` format.
//! Profile flags: `--p-bits N` (16), `--ell N` (2), `--gadget-bits N` (19),
//! `--response-bits N` (p+6) and `--storage u8|u16` (u16; u8 needs p <= 2^8).
//! The database is the e2e stream masked to p, byte-identical at p = 2^16.
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
    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    let two_mask = raw.iter().any(|x| x == "--two-mask");
    let mut flag = |name: &str| {
        raw.iter().position(|x| x == name).map(|i| {
            let value = raw[i + 1].clone();
            raw.drain(i..i + 2);
            value
        })
    };
    let query_bits: Option<usize> = flag("--query-bits").map(|x| x.parse().unwrap());
    let p_bits: u32 = flag("--p-bits").map_or(16, |x| x.parse().unwrap());
    let ell: usize = flag("--ell").map_or(2, |x| x.parse().unwrap());
    let gadget_bits: u32 = flag("--gadget-bits").map_or(19, |x| x.parse().unwrap());
    let response_bits: Option<usize> = flag("--response-bits").map(|x| x.parse().unwrap());
    let storage = flag("--storage").unwrap_or_else(|| "u16".into());
    let args: Vec<usize> = raw
        .into_iter()
        .filter(|x| x != "--two-mask")
        .map(|x| x.parse().unwrap())
        .collect();
    let rows = *args.first().unwrap_or(&28672);
    let cols = *args.get(1).unwrap_or(&32768);
    let kh_bits = *args.get(2).unwrap_or(&54);
    let published_bits = *args.get(3).unwrap_or(&64);
    let p = NativeParams::new(
        2048,
        54,
        p_bits,
        gadget_bits,
        ell,
        SecretDistribution::Gaussian,
    )
    .unwrap();
    let dropped_bits = p.dropped_bits();
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
    let profile = match query_bits {
        Some(bits) => profile.with_dithered_query_bits(bits).unwrap(),
        None => profile,
    };
    let profile = match response_bits {
        Some(bits) => profile.with_response_bits(bits).unwrap(),
        None => profile,
    };
    let response_bits = profile.response_bits();
    let (query_bits, query_rounding) = (
        profile.query_bits(),
        if profile.is_dithered_query() {
            "dithered"
        } else {
            "nearest"
        },
    );
    // Dithered reports get their own format so checkers that predate dithering,
    // which budget only nearest rounding, reject them instead of misreading them.
    let format = format!(
        "native-noise{}{}{}-v1",
        if two_mask { "-two-mask" } else { "" },
        if published_bits != 64 { "-rounded" } else { "" },
        if profile.is_dithered_query() {
            "-dithered"
        } else {
            ""
        },
    );
    let setup = NativePublicSetup::new(profile, [7; 32], [19; 32]);
    let mut rng = ChaCha20Rng::seed_from_u64(0x2417);
    let entry_mask = ((1u32 << p_bits) - 1) as u16;
    let db: Vec<u16> = (0..rows * cols)
        .map(|_| (rng.next_u32() as u16) & entry_mask)
        .collect();
    // Bind evidence to both the declared snapshot identity and the actual contents.
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for x in &db {
        hash.update(x.to_le_bytes());
    }
    let db_hash = format!("{:x}", hash.finalize());
    eprintln!("Analyzing {rows}x{cols} public snapshot, Kh transport {kh_bits} bits, {query_rounding} {query_bits}-bit query");
    let (server, blocks) = if storage == "u8" {
        NativeServer::build_u8_analyzed(setup, db.iter().map(|&x| x as u8).collect()).unwrap()
    } else {
        NativeServer::build_analyzed(setup, db).unwrap()
    };
    let blocks: Vec<_> = blocks.into_iter().map(|b| json!({
        "weights":norms(b.packing.weights.independent(b.query)),
        "query_l1":b.query.l1.to_string(),
        "query_l2_squared":b.query.l2_squared.to_string(),
        "kh_l1":b.packing.kh_l1.to_string(),
        "public_mask_screens":b.packing.public_mask_screens.iter().map(|(bits,w)|json!({"bits":bits,"weights":norms(w.independent(b.query))})).collect::<Vec<_>>(),
        "one_limb":b.packing.one_limb.into_iter().map(|v| json!({"bits":v.bits,"weights":norms(v.weights.independent(b.query))})).collect::<Vec<_>>()
    })).collect();
    println!(
        "{}",
        json!({
            "format":format,"d":2048,"q_bits":54,"p_bits":p_bits,"ell":ell,"gadget_bits":gadget_bits,"dropped_bits":dropped_bits,
            "published_mask_bits":published_bits,"published_bytes":server.published().to_bytes().len(),
            "rows":rows,"cols":cols,"query_bits":query_bits,"query_rounding":query_rounding,"response_bits":response_bits,"kh_bits":kh_bits,
            "setup_id":server.setup().id().iter().map(|x|format!("{x:02x}")).collect::<String>(),
            "database_sha256":db_hash,
            "sampler_sha256":gaussian_cdf_sha256().iter().map(|x|format!("{x:02x}")).collect::<String>(),
            "sampler_counts":gaussian_counts().into_iter().map(|(x,n)|json!([x,n.to_string()])).collect::<Vec<_>>(),
            "blocks":blocks
        })
    );
}
