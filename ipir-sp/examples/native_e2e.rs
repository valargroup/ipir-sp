//! Reproducible full-wire native IPIR-SP benchmark. Args: rows cols pbits ell samples.
use ipir_sp::native::*;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use reinspiring::native::*;
use std::time::Instant;
fn main() {
    let args: Vec<_> = std::env::args()
        .skip(1)
        .map(|x| x.parse::<usize>().unwrap())
        .collect();
    let rows = *args.first().unwrap_or(&2048);
    let cols = *args.get(1).unwrap_or(&2048);
    let pbits = *args.get(2).unwrap_or(&14);
    let ell = *args.get(3).unwrap_or(&2);
    let samples = *args.get(4).unwrap_or(&30);
    let pack = NativeParams::new(
        2048,
        54,
        pbits as u32,
        19,
        ell,
        SecretDistribution::Gaussian,
    )
    .unwrap();
    let profile = NativeProfile::new(pack, rows, cols).unwrap();
    let setup = NativePublicSetup::new(profile, [7; 32], [19; 32]);
    let mut data_rng = ChaCha20Rng::seed_from_u64(0x2417);
    let db: Vec<u16> = (0..rows * cols)
        .map(|_| (data_rng.next_u32() as u16) & ((1u32 << pbits) - 1) as u16)
        .collect();
    let targets = [0, rows / 2, rows - 1];
    let expected: Vec<Vec<u64>> = targets
        .iter()
        .map(|&r| (0..cols).map(|c| db[c * rows + r] as u64).collect())
        .collect();
    let t = Instant::now();
    let server = NativeServer::build(setup, db).unwrap();
    let offline = t.elapsed().as_secs_f64();
    let published =
        NativePublished::from_bytes(server.setup(), &server.published().to_bytes()).unwrap();
    println!(
        "{}",
        serde_json::json!({"kind":"setup","backend":"native","rows":rows,"cols":cols,"pbits":pbits,"ell":ell,"threads":rayon::current_num_threads(),"offline_s":offline,"coeff_bytes":server.coefficient_bytes(),"published_bytes":published.to_bytes().len()})
    );
    let mut rng = ChaCha20Rng::seed_from_u64(0x2418);
    let threads =
        std::env::var("BENCH_THREADS").unwrap_or_else(|_| rayon::current_num_threads().to_string());
    for workers in threads.split(',').map(|x| x.parse::<usize>().unwrap()) {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        pool.install(|| {
    for i in 0..samples + 3 {
        let target = i % targets.len();
        let t = Instant::now();
        let request =
            NativeRequest::generate_with_rng(server.setup(), targets[target], &mut rng).unwrap();
        let client_ms = t.elapsed().as_secs_f64() * 1000.;
        let t = Instant::now();
        let (response, timing) = server.respond(request.bytes()).unwrap();
        let server_ms = t.elapsed().as_secs_f64() * 1000.;
        let t = Instant::now();
        let decoded = request.decode(&published, &response).unwrap();
        let decode_ms = t.elapsed().as_secs_f64() * 1000.;
        assert_eq!(decoded, expected[target]);
        let (_, error) = request
            .decode_with_error(&published, &response, &expected[target])
            .unwrap();
        if i >= 3 {
            println!(
                "{}",
                serde_json::json!({"kind":"sample","threads":rayon::current_num_threads(),"sample":i-3,"client_ms":client_ms,"server_ms":server_ms,"decode_ms":decode_ms,"parse_ms":timing.deserialize.as_secs_f64()*1000.,"matvec_ms":timing.matrix_vector.as_secs_f64()*1000.,"packing_ms":timing.packing.as_secs_f64()*1000.,"serialize_ms":timing.serialization.as_secs_f64()*1000.,"upload_bytes":request.bytes().len(),"download_bytes":response.len(),"phase_error":error,"correct":true})
            );
        }
    }
      });
    }
}
