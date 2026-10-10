//! Reproducible full-wire native IPIR-SP benchmark. Args: rows cols pbits ell samples
//! concurrent_setup_blocks kh_bits published_mask_bits query_bits (0 = legacy 49-bit nearest;
//! otherwise dithered at that precision).
//!
//! Flags: `--gadget-bits N` (default 19), `--response-bits N` (default pbits+6),
//! `--storage u8|u16` (default u16; u8 needs pbits <= 8), `--threads 1,2,4,8`
//! (overrides `BENCH_THREADS`), `--no-cold-decode`.
//!
//! Memory checkpoints are process RSS in bytes. On Linux the peak is reset
//! before each response, so `respond_peak_delta` isolates server transient
//! memory from the client state living in the same process.
#![recursion_limit = "256"]

#[path = "common/rss.rs"]
mod rss;

use ipir_sp::native::*;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use reinspiring::native::*;
use std::collections::BTreeMap;
use std::time::Instant;

fn take_flag(raw: &mut Vec<String>, name: &str) -> Option<String> {
    let i = raw.iter().position(|x| x == name)?;
    let value = raw.get(i + 1).cloned();
    raw.drain(i..(i + 2).min(raw.len()));
    value
}

fn main() {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();
    let no_cold = raw.iter().any(|x| x == "--no-cold-decode");
    raw.retain(|x| x != "--no-cold-decode");
    let gadget_bits: u32 = take_flag(&mut raw, "--gadget-bits").map_or(19, |x| x.parse().unwrap());
    let response_bits: Option<usize> =
        take_flag(&mut raw, "--response-bits").map(|x| x.parse().unwrap());
    let storage = take_flag(&mut raw, "--storage").unwrap_or_else(|| "u16".into());
    let threads = take_flag(&mut raw, "--threads").unwrap_or_else(|| {
        std::env::var("BENCH_THREADS").unwrap_or_else(|_| rayon::current_num_threads().to_string())
    });
    let args: Vec<usize> = raw.iter().map(|x| x.parse::<usize>().unwrap()).collect();
    let rows = *args.first().unwrap_or(&2048);
    let cols = *args.get(1).unwrap_or(&2048);
    let pbits = *args.get(2).unwrap_or(&14);
    let ell = *args.get(3).unwrap_or(&2);
    let samples = *args.get(4).unwrap_or(&30);
    let concurrency = *args.get(5).unwrap_or(&1);
    let kh_bits = *args.get(6).unwrap_or(&54);
    assert!(
        storage == "u16" || (storage == "u8" && pbits <= 8),
        "u8 storage needs pbits <= 8"
    );
    let memory_start = rss::sample();
    let pack = NativeParams::new(
        2048,
        54,
        pbits as u32,
        gadget_bits,
        ell,
        SecretDistribution::Gaussian,
    )
    .unwrap();
    let profile = NativeProfile::new(pack, rows, cols)
        .unwrap()
        .with_kh_bits(if kh_bits == 0 { 54 } else { kh_bits })
        .unwrap();
    let profile = if kh_bits == 0 {
        profile.with_two_mask_output().unwrap()
    } else {
        profile
    };
    let profile = profile
        .with_published_mask_bits(*args.get(7).unwrap_or(&64))
        .unwrap();
    let profile = match *args.get(8).unwrap_or(&0) {
        0 => profile,
        bits => profile.with_dithered_query_bits(bits).unwrap(),
    };
    let profile = match response_bits {
        Some(bits) => profile.with_response_bits(bits).unwrap(),
        None => profile,
    };
    let query_bits = profile.query_bits();
    let response_bits = profile.response_bits();
    let published_mask_bits = profile.published_mask_bits();
    let setup = NativePublicSetup::new(profile, [7; 32], [19; 32]);
    let setup_id: String = setup.id().iter().map(|x| format!("{x:02x}")).collect();
    // Same RNG stream for both storage widths, so the logical database matches.
    let mut data_rng = ChaCha20Rng::seed_from_u64(0x2417);
    let mut entry = move || (data_rng.next_u32() as u16) & ((1u32 << pbits) - 1) as u16;
    let targets = [0, rows / 2, rows - 1];
    let (expected, t, server, memory_db) = if storage == "u8" {
        let db: Vec<u8> = (0..rows * cols).map(|_| entry() as u8).collect();
        let expected: Vec<Vec<u64>> = targets
            .iter()
            .map(|&r| (0..cols).map(|c| db[c * rows + r] as u64).collect())
            .collect();
        let memory_db = rss::sample();
        let t = Instant::now();
        let server = NativeServer::build_u8_with_concurrency(setup, db, concurrency).unwrap();
        (expected, t, server, memory_db)
    } else {
        let db: Vec<u16> = (0..rows * cols).map(|_| entry()).collect();
        let expected: Vec<Vec<u64>> = targets
            .iter()
            .map(|&r| (0..cols).map(|c| db[c * rows + r] as u64).collect())
            .collect();
        let memory_db = rss::sample();
        let t = Instant::now();
        let server = NativeServer::build_with_concurrency(setup, db, concurrency).unwrap();
        (expected, t, server, memory_db)
    };
    let offline = t.elapsed().as_secs_f64();
    let memory_built = rss::sample();
    let trimmed = rss::trim();
    let memory_trimmed = rss::sample();
    let mut storage_counts = BTreeMap::new();
    for kind in server.matrix_storage() {
        *storage_counts.entry(kind.label()).or_insert(0usize) += 1;
    }
    let magnitude = server.matrix_magnitude_bits();
    let published =
        NativePublished::from_bytes(server.setup(), &server.published().to_bytes()).unwrap();
    let preparation = Instant::now();
    let prepared = published.prepare(server.setup()).unwrap();
    let prepare_ms = preparation.elapsed().as_secs_f64() * 1000.;
    let memory_client = rss::sample();
    let key_bytes = if kh_bits == 0 {
        ell * 2048 * 54 / 8
    } else {
        ell * 2048 * (54 + kh_bits) / 8
    };
    let query_bytes = (rows * query_bits).div_ceil(8);
    let skipped = if reinspiring::native_kernel::PreparedU16Query::supports_interleaved() {
        ((54 - query_bits) / 8).min(6)
    } else {
        0
    };
    let timing = server.offline_timing();
    println!(
        "{}",
        serde_json::json!({
            "kind":"setup","backend":"native","rows":rows,"cols":cols,"pbits":pbits,"ell":ell,
            "gadget_bits":gadget_bits,"kh_bits":kh_bits,"two_mask":server.setup().profile().is_two_mask(),
            "query_bits":query_bits,"dithered_query":server.setup().profile().is_dithered_query(),
            "response_bits":response_bits,"published_mask_bits":published_mask_bits,"storage":storage,
            "setup_id":setup_id,"threads":rayon::current_num_threads(),"offline_s":offline,
            "offline_hint_block_s":timing.hints.as_secs_f64(),"offline_packing_block_s":timing.packing.as_secs_f64(),
            "offline_layout_s":timing.layout.as_secs_f64(),"concurrency":concurrency,
            "coeff_bytes":server.coefficient_bytes(),"database_bytes":server.database_bytes(),
            "query_mask_bytes":rows * 8,"matrix_storage":storage_counts,
            "matrix_magnitude_bits":{"min":magnitude.iter().min(),"max":magnitude.iter().max()},
            "scan_skipped_digits":skipped,"key_bytes":key_bytes,"query_bytes":query_bytes,
            "request_bytes":36 + key_bytes + query_bytes,"response_bytes":68 + (cols * response_bits).div_ceil(8),
            "published_bytes":published.to_bytes().len(),"prepare_decode_ms":prepare_ms,
            "decode_coeff_bytes":prepared.coefficient_bytes(),
            "memory":{"start":memory_start.json(),"db_generated":memory_db.json(),"server_built":memory_built.json(),
                "trimmed":trimmed,"server_built_trimmed":memory_trimmed.json(),"client_prepared":memory_client.json()}
        })
    );
    let mut rng = ChaCha20Rng::seed_from_u64(0x2418);
    for workers in threads.split(',').map(|x| x.parse::<usize>().unwrap()) {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        let mut respond_peak_delta: Option<u64> = None;
        pool.install(|| {
            for i in 0..samples + 3 {
                let target = i % targets.len();
                let t = Instant::now();
                let mut request =
                    NativeRequest::generate_with_rng(server.setup(), targets[target], &mut rng)
                        .unwrap();
                let generate_ms = t.elapsed().as_secs_f64() * 1000.;
                let reset = rss::reset_peak();
                let before = rss::sample();
                let t = Instant::now();
                let (response, timing) = server.respond(request.bytes()).unwrap();
                let server_ms = t.elapsed().as_secs_f64() * 1000.;
                let after = rss::sample();
                if reset && i >= 3 {
                    if let (Some(peak), Some(rss)) = (after.peak, before.rss) {
                        let delta = peak.saturating_sub(rss);
                        respond_peak_delta = Some(respond_peak_delta.map_or(delta, |m| m.max(delta)));
                    }
                }
                let cold_decode_ms = if no_cold {
                    None
                } else {
                    let cold = Instant::now();
                    let cold_prepared = published.prepare(server.setup()).unwrap();
                    let cold_decoded = request.decode_prepared(&cold_prepared, &response).unwrap();
                    assert_eq!(cold_decoded, expected[target]);
                    Some(cold.elapsed().as_secs_f64() * 1000.)
                };
                let preparation = Instant::now();
                request.prepare_decode(&prepared).unwrap();
                let prepare_ms = preparation.elapsed().as_secs_f64() * 1000.;
                let t = Instant::now();
                let decoded = request.decode_prepared(&prepared, &response).unwrap();
                let decode_ms = t.elapsed().as_secs_f64() * 1000.;
                assert_eq!(decoded, expected[target]);
                let legacy = Instant::now();
                assert_eq!(request.decode(&published, &response).unwrap(), decoded);
                let legacy_decode_ms = legacy.elapsed().as_secs_f64() * 1000.;
                let (_, error) = request
                    .decode_with_error(&published, &response, &expected[target])
                    .unwrap();
                if i >= 3 {
                    println!(
                        "{}",
                        serde_json::json!({"kind":"sample","threads":rayon::current_num_threads(),"sample":i-3,
                            "client_ms":generate_ms + prepare_ms,"generate_ms":generate_ms,"prepare_ms":prepare_ms,
                            "server_ms":server_ms,"decode_ms":decode_ms,"cold_decode_ms":cold_decode_ms,
                            "legacy_decode_ms":legacy_decode_ms,"parse_ms":timing.deserialize.as_secs_f64()*1000.,
                            "matvec_ms":timing.matrix_vector.as_secs_f64()*1000.,"packing_ms":timing.packing.as_secs_f64()*1000.,
                            "serialize_ms":timing.serialization.as_secs_f64()*1000.,"upload_bytes":request.bytes().len(),
                            "download_bytes":response.len(),"phase_error":error,"correct":true})
                    );
                }
            }
        });
        println!(
            "{}",
            serde_json::json!({"kind":"memory","threads":workers,"respond_peak_delta":respond_peak_delta,
                "rss":rss::sample().json()})
        );
    }
}
