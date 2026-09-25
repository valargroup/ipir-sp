//! Baseline runnable unmodified on main. Args: rows cols profile samples.
use inspiring::TopKeyImages;
use ipir_sp::{
    modulus_switch::recover_published_c1,
    serialize::{deserialize_packing_keys, serialize_packing_keys},
    server::{build_pack_preprocessed_blocks, published_c1_rows},
};
use ipir_sp::{IPIRClient, IPIRServer, ProductionSimplePirParams, SimplePirProfile};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use std::time::Instant;
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let rows = args
        .first()
        .map(|x| x.parse::<usize>().unwrap())
        .unwrap_or(2048);
    let cols = args
        .get(1)
        .map(|x| x.parse::<usize>().unwrap())
        .unwrap_or(2048);
    let variant = match args.get(2).map(String::as_str).unwrap_or("p14") {
        "p14" => SimplePirProfile::P14,
        "p16q46" => SimplePirProfile::P16Q46,
        "p16q48" => SimplePirProfile::P16Q48,
        "p16q49" => SimplePirProfile::P16Q49,
        _ => panic!("unknown profile"),
    };
    let samples = args
        .get(3)
        .map(|x| x.parse::<usize>().unwrap())
        .unwrap_or(30);
    let pbits = variant.plaintext_bits();
    let profile =
        ProductionSimplePirParams::new(rows as u64, (cols * pbits) as u64, variant).unwrap();
    assert_eq!(profile.ypir().db_rows, rows);
    assert_eq!(profile.ypir().db_cols, cols);
    let client = IPIRClient::new(&profile);
    let rlwe = client.rlwe_params();
    let params = client.params();
    let mut rng = ChaCha20Rng::seed_from_u64(0x2417);
    let db = (0..rows * cols).map(|_| (rng.next_u32() as u16) & ((1u32 << pbits) - 1) as u16);
    let server = IPIRServer::new_auto_kernel_from_profile(&profile, db, true, false);
    let targets = [0, rows / 2, rows - 1];
    let expected: Vec<Vec<u64>> = targets
        .iter()
        .map(|&r| {
            (0..cols)
                .map(|c| server.get_elem_row_col(r, c) as u64)
                .collect()
        })
        .collect();
    let setup = client.generate_public_query_setup_simplepir_from_seed([7; 32]);
    let t = Instant::now();
    let offline = server.perform_offline_precomputation_simplepir(rlwe, setup.polys());
    let pre = build_pack_preprocessed_blocks(rlwe, &offline.crs_blocks).unwrap();
    let offline_s = t.elapsed().as_secs_f64();
    drop(offline);
    let published_bytes = published_c1_rows(&pre, rlwe.q);
    let published = recover_published_c1(&published_bytes, rlwe.d, cols / rlwe.d, rlwe.q);
    let top = TopKeyImages::build(rlwe);
    println!(
        "{}",
        serde_json::json!({"kind":"setup","backend":"inspiring","rows":rows,"cols":cols,"profile":variant.id(),"threads":rayon::current_num_threads(),"offline_s":offline_s,"published_bytes":published_bytes.len(),"query_bits":params.query_bits})
    );
    let threads =
        std::env::var("BENCH_THREADS").unwrap_or_else(|_| rayon::current_num_threads().to_string());
    for workers in threads.split(',').map(|x| x.parse::<usize>().unwrap()) {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        pool.install(|| {
    for i in 0..samples + 3 {
        let target = i % 3;
        let t = Instant::now();
        let (query, keys, seed) = client.generate_fresh_query_simplepir(&setup, targets[target]);
        let keybytes = serialize_packing_keys(rlwe, &keys).unwrap();
        let querybytes = query.to_switched_bytes(rlwe.q, params.query_bits);
        let client_ms = t.elapsed().as_secs_f64() * 1000.;
        let t = Instant::now();
        let keys = deserialize_packing_keys(rlwe, &keybytes).unwrap();
        let (response, timing) = server
            .perform_full_online_computation_simplepir_measured(
                rlwe,
                &querybytes,
                &keys,
                &top,
                &pre,
            )
            .unwrap();
        let server_ms = t.elapsed().as_secs_f64() * 1000.;
        let t = Instant::now();
        let decoded = client.decode_response_simplepir_raw(seed, &published, &response);
        let decode_ms = t.elapsed().as_secs_f64() * 1000.;
        assert_eq!(decoded, expected[target]);
        let (_, error) = client.decode_response_simplepir_with_expected_phase_error(
            seed,
            &published,
            &response,
            &expected[target],
        );
        if i >= 3 {
            println!(
                "{}",
                serde_json::json!({"kind":"sample","threads":rayon::current_num_threads(),"sample":i-3,"client_ms":client_ms,"server_ms":server_ms,"decode_ms":decode_ms,"parse_ms":timing.deserialize.as_secs_f64()*1000.,"matvec_ms":timing.matrix_vector.as_secs_f64()*1000.,"packing_ms":timing.packing.as_secs_f64()*1000.,"serialize_ms":timing.serialization.as_secs_f64()*1000.,"upload_bytes":keybytes.len()+querybytes.len(),"download_bytes":response.len(),"phase_error":error,"correct":true})
            );
        }
    }
      });
    }
}
