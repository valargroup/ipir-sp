//! Alternating paired full-size upload experiment. Args: samples (default 30).
//! Request preparation is included in client generation for BOTH modes.
use ipir_sp::native::*;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use reinspiring::native::*;
use std::time::Instant;
fn main() {
    let samples = std::env::args()
        .nth(1)
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(30);
    let mask_bits = std::env::args()
        .nth(2)
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(64);
    let (rows, cols) = (28672, 32768);
    let mut rng = ChaCha20Rng::seed_from_u64(0x2417);
    let db: Vec<u16> = (0..rows * cols).map(|_| rng.next_u32() as u16).collect();
    let targets = [0, rows / 2, rows - 1];
    let expected: Vec<Vec<u64>> = targets
        .iter()
        .map(|&r| (0..cols).map(|c| db[c * rows + r] as u64).collect())
        .collect();
    let mut cases = Vec::new();
    for two in [false, true] {
        let p = NativeParams::new(2048, 54, 16, 19, 2, SecretDistribution::Gaussian).unwrap();
        let p = NativeProfile::new(p, rows, cols).unwrap();
        let p = if two {
            p.with_two_mask_output()
                .unwrap()
                .with_published_mask_bits(mask_bits)
                .unwrap()
        } else {
            p
        };
        let t = Instant::now();
        let server =
            NativeServer::build(NativePublicSetup::new(p, [7; 32], [19; 32]), db.clone()).unwrap();
        let offline_s = t.elapsed().as_secs_f64();
        let published =
            NativePublished::from_bytes(server.setup(), &server.published().to_bytes()).unwrap();
        let t = Instant::now();
        let prepared = published.prepare(server.setup()).unwrap();
        println!(
            "{}",
            serde_json::json!({"kind":"setup","two_mask":two,"mask_bits":server.setup().profile().published_mask_bits(),"offline_s":offline_s,"prepare_ms":t.elapsed().as_secs_f64()*1000.,"decode_coeff_bytes":prepared.coefficient_bytes(),"published_bytes":published.to_bytes().len(),"coeff_bytes":server.coefficient_bytes()})
        );
        cases.push((server, published, prepared));
    }
    drop(db);
    let mut rng = ChaCha20Rng::seed_from_u64(0x2418);
    for i in 0..samples + 3 {
        for mode in if i % 2 == 0 { [0, 1] } else { [1, 0] } {
            let (server, published, prepared) = &cases[mode];
            let target = i % targets.len();
            let t = Instant::now();
            let mut request =
                NativeRequest::generate_with_rng(server.setup(), targets[target], &mut rng)
                    .unwrap();
            request.prepare_decode(prepared).unwrap();
            let client_ms = t.elapsed().as_secs_f64() * 1000.;
            let t = Instant::now();
            let (response, timing) = server.respond(request.bytes()).unwrap();
            let server_ms = t.elapsed().as_secs_f64() * 1000.;
            let t = Instant::now();
            assert_eq!(
                request.decode_prepared(prepared, &response).unwrap(),
                expected[target]
            );
            let decode_ms = t.elapsed().as_secs_f64() * 1000.;
            let (reference, error) = request
                .decode_with_error(published, &response, &expected[target])
                .unwrap();
            assert_eq!(reference, expected[target]);
            if i >= 3 {
                println!(
                    "{}",
                    serde_json::json!({"kind":"sample","sample":i-3,"two_mask":mode==1,"client_ms":client_ms,"server_ms":server_ms,"decode_ms":decode_ms,"packing_ms":timing.packing.as_secs_f64()*1000.,"upload_bytes":request.bytes().len(),"download_bytes":response.len(),"phase_error":error,"correct":true})
                );
            }
        }
    }
}
