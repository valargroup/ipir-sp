//! End-to-end in-process experiment; synthetic DB, real production RLWE parameters.
//! cargo run --release -p ipir-sp --features experimental-key-reuse
//!   --example key_reuse_bench -- [rows=2048] [cols=2048] [pool=4] [batches=3]
use inspiring::TopKeyImages;
use ipir_sp::client::reusable::QueryPool;
use ipir_sp::modulus_switch::recover_published_c1;
use ipir_sp::serialize::{deserialize_packing_keys, serialize_packing_keys};
use ipir_sp::server::{build_pack_preprocessed_blocks, published_c1_rows};
use ipir_sp::{params_for_simplepir, IPIRClient, IPIRServer};
use serde_json::json;
use spiral_rs::poly::PolyMatrix;
use std::time::Instant;

fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .map(|v| v.parse().unwrap())
        .collect();
    let rows = args.first().copied().unwrap_or(2048);
    let cols = args.get(1).copied().unwrap_or(2048);
    let count = args.get(2).copied().unwrap_or(4);
    let batches = args.get(3).copied().unwrap_or(3);
    assert!(batches > 0 && cols % 2048 == 0);
    let (r, y) = params_for_simplepir(rows as u64, (cols * 14) as u64).unwrap();
    let pool = QueryPool::new(IPIRClient::new(&r, &y), [0x72; 32], count).unwrap();
    let value = |row: usize, col: usize| ((row * 31 + col * 17 + 5) % y.p as usize) as u16;
    let started = Instant::now();
    let server = IPIRServer::new_auto_kernel(
        y.clone(),
        (0..y.db_rows).flat_map(|row| (0..cols).map(move |col| value(row, col))),
        false,
        true,
    );
    let database_build_ms = started.elapsed().as_secs_f64() * 1000.;
    let top = TopKeyImages::build(&r);
    let mut pre = Vec::new();
    let mut c1 = Vec::new();
    let mut offline_ms = Vec::new();
    let mut public_bytes = 0;
    let mut cache_bytes = 0;
    for (slot, set) in pool.sets().iter().enumerate() {
        let started = Instant::now();
        let offline = server.perform_offline_precomputation_simplepir(&r, set);
        let p = build_pack_preprocessed_blocks(&r, &offline.crs_blocks).unwrap();
        let bytes = published_c1_rows(&p, r.q);
        public_bytes += bytes.len();
        cache_bytes += p
            .iter()
            .map(|p| {
                p.collapse_a_final_ntt.as_slice().len() * 8
                    + p.digits_ntt
                        .iter()
                        .map(|d| d.as_slice().len() * 8)
                        .sum::<usize>()
            })
            .sum::<usize>();
        c1.push(recover_published_c1(&bytes, r.d, cols / r.d, r.q));
        pre.push(p);
        offline_ms.push(started.elapsed().as_secs_f64() * 1000.);
        eprintln!("prepared slot {slot} in {:.1} ms", offline_ms[slot]);
    }
    let mut client_ms = [Vec::new(), Vec::new()];
    let mut answer_ms = [Vec::new(), Vec::new()];
    let mut decode_ms = [Vec::new(), Vec::new()];
    let mut key_parse_ms = [Vec::new(), Vec::new()];
    let mut upload = [0_usize; 2];
    let mut download = [0_usize; 2];
    let mut worst_error = [0_u64; 2];
    let mut key_bytes = 0;
    for batch_idx in 0..batches {
        // Alternate modes to reduce systematic thermal/cache ordering bias.
        for mode in [batch_idx % 2, 1 - batch_idx % 2] {
            let start = Instant::now();
            let mut batch = (mode == 1).then(|| pool.start_batch());
            let cached_bytes = batch
                .as_ref()
                .map(|b| serialize_packing_keys(&r, b.keys()).unwrap());
            let mut generation_ms = start.elapsed().as_secs_f64() * 1000.;
            let start = Instant::now();
            let cached_keys = cached_bytes
                .as_ref()
                .map(|b| deserialize_packing_keys(&r, b).unwrap());
            if let Some(bytes) = &cached_bytes {
                upload[mode] += bytes.len();
                key_parse_ms[mode].push(start.elapsed().as_secs_f64() * 1000.);
            }
            for slot in 0..count {
                let row = match slot % 4 {
                    0 => 0,
                    1 => r.d - 1,
                    2 => y.db_rows / 2,
                    _ => y.db_rows - 1,
                };
                let start = Instant::now();
                let mut fresh_seed = None;
                let mut fresh_key_bytes = None;
                let query_bytes = if let Some(b) = &mut batch {
                    let q = b.next_query(row).unwrap();
                    assert_eq!(q.slot(), slot);
                    q.bytes().to_vec()
                } else {
                    let (q, k, s) = pool
                        .client()
                        .generate_fresh_query_simplepir(&pool.sets()[0], row);
                    fresh_seed = Some(s);
                    fresh_key_bytes = Some(serialize_packing_keys(&r, &k).unwrap());
                    q.to_switched_bytes(r.q, y.query_bits)
                };
                generation_ms += start.elapsed().as_secs_f64() * 1000.;
                let start = Instant::now();
                let fresh_keys = fresh_key_bytes
                    .as_ref()
                    .map(|b| deserialize_packing_keys(&r, b).unwrap());
                if let Some(bytes) = &fresh_key_bytes {
                    key_bytes = bytes.len();
                    upload[mode] += bytes.len();
                    key_parse_ms[mode].push(start.elapsed().as_secs_f64() * 1000.);
                }
                upload[mode] += query_bytes.len();
                let keys = cached_keys.as_ref().or(fresh_keys.as_ref()).unwrap();
                let bank = if mode == 0 { 0 } else { slot };
                let start = Instant::now();
                let (response, _) = server
                    .perform_full_online_computation_simplepir_measured(
                        &r,
                        &query_bytes,
                        keys,
                        &top,
                        &pre[bank],
                    )
                    .unwrap();
                answer_ms[mode].push(start.elapsed().as_secs_f64() * 1000.);
                download[mode] += response.len();
                let start = Instant::now();
                let (decoded, error) = if let Some(b) = &batch {
                    b.decode_with_margin(&c1[bank], &response)
                } else {
                    pool.client().decode_response_simplepir_with_margin(
                        fresh_seed.unwrap(),
                        &c1[bank],
                        &response,
                    )
                };
                decode_ms[mode].push(start.elapsed().as_secs_f64() * 1000.);
                worst_error[mode] = worst_error[mode].max(error);
                assert_eq!(decoded.len(), cols);
                for (col, actual) in decoded.into_iter().enumerate() {
                    assert_eq!(
                        actual,
                        u64::from(value(row, col)),
                        "mode={mode} slot={slot} row={row} col={col}"
                    );
                }
                assert!(error < r.delta / 8, "insufficient decryption headroom");
            }
            client_ms[mode].push(generation_ms / count as f64);
        }
    }
    let queries = batches * count;
    let stats = |values: &[f64]| {
        let mut v = values.to_vec();
        v.sort_by(f64::total_cmp);
        json!({"mean": v.iter().sum::<f64>()/v.len() as f64,
            "median":v[v.len()/2],"min":v[0],"max":v[v.len()-1]})
    };
    let metrics: Vec<_> = (0..2)
        .map(|mode| {
            json!({
                "mode":if mode==0 {"fresh"} else {"reused"},
                "client_generation_ms_per_query":stats(&client_ms[mode]),
                "server_answer_ms":stats(&answer_ms[mode]),
                "client_decode_ms":stats(&decode_ms[mode]),
                "server_key_parse_ms_total":key_parse_ms[mode].iter().sum::<f64>(),
                "upload_bytes_per_query":upload[mode]/queries,
                "response_bytes_per_query":download[mode]/queries,
                "warm_total_bytes_per_query":(upload[mode]+download[mode])/queries,
                "cold_first_batch_bytes_per_query":(upload[mode]+download[mode])/queries +
                    if mode==0 {public_bytes/count/count} else {public_bytes/count},
                "max_decryption_error":worst_error[mode],
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "rows":y.db_rows,"cols":cols,"degree":r.d,"query_bits":y.query_bits,
            "secret_distribution":"discrete-gaussian","secret_stddev":r.sigma_chi,
            "pool_size":count,"batches":batches,"queries_per_mode":queries,
            "rayon_threads":rayon::current_num_threads(),"synthetic_database":true,
            "database_build_ms":database_build_ms,"offline_ms_per_set":offline_ms,
            "packing_cache_payload_bytes":cache_bytes,"public_c1_bytes_per_set":public_bytes/count,
            "key_bytes":key_bytes,"decryption_threshold":r.delta/2,
            "metrics":metrics
        }))
        .unwrap()
    );
}
