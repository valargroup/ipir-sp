//! Decision gate for batched (coalesced) packing.
//!
//! Packing one block performs `(d - 1) * ell` multiply-accumulates per NTT
//! slot, and each one reads 8 bytes of `digits_ntt` that is used exactly once.
//! At `d = 2048, ell = 3` that block is 100.6 MB, so a single query streams it
//! end to end to do one MAC per 8 bytes — memory-bound, not arithmetic-bound.
//!
//! `digits_ntt` is derived from the CRS alone, so it is identical for every
//! client. This measures whether packing `k` unrelated queries in one pass over
//! that stream costs meaningfully less than `k` separate passes.
//!
//! ```text
//! cargo run --release -p inspiring --example batched_pack_bench
//! ```
//!
//! Set `INSPIRING_BENCH_SMALL=1` for a `d = 512` shape.

use std::time::Instant;

use inspiring::preprocess::{PackingKeys, QueryPackPreprocessed, TopKeyImages};
use inspiring::{GadgetParams, RlweParams};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use spiral_rs::poly::{to_ntt_alloc, PolyMatrix, PolyMatrixNTT, PolyMatrixRaw};

/// Production IPIR-SP packing parameters: Table 5 row 2 of ePrint 2024/270.
const PROD_D: usize = 2048;
const PROD_Q: u64 = 72_057_594_037_641_217;
const PROD_P: u64 = 1 << 14;
const SMALL_D: usize = 512;

fn build_params(d: usize) -> RlweParams {
    RlweParams::new(
        d,
        PROD_Q,
        PROD_P,
        6.4,
        GadgetParams {
            bits_per: 19,
            ell: 3,
        },
    )
    .expect("valid production packing parameters")
}

/// A pseudorandom CRS block. Contents cannot affect timing — every code path
/// touches every coefficient — so a seeded fill stands in for a real hint.
fn crs<'a>(params: &'a RlweParams, rng: &mut ChaCha20Rng) -> PolyMatrixNTT<'a> {
    let mut raw = PolyMatrixRaw::zero(&params.spiral, params.d, 1);
    for row in 0..params.d {
        let poly = raw.get_poly_mut(row, 0);
        for coeff in poly.iter_mut() {
            *coeff = rand::Rng::gen_range(rng, 0..params.q);
        }
    }
    to_ntt_alloc(&raw)
}

fn key_bodies<'a>(params: &'a RlweParams, rng: &mut ChaCha20Rng) -> PackingKeys<'a> {
    let mut make = || {
        let mut m = PolyMatrixNTT::zero(&params.spiral, 1, params.gadget.ell);
        for coeff in m.as_mut_slice().iter_mut() {
            *coeff = rand::Rng::gen_range(rng, 0..params.q);
        }
        m
    };
    let kg_body = make();
    let kh_body = make();
    PackingKeys { kg_body, kh_body }
}

fn main() {
    let small = std::env::var_os("INSPIRING_BENCH_SMALL").is_some();
    let d = if small { SMALL_D } else { PROD_D };
    let params = build_params(d);
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0A1E5CE);

    let digit_bytes = (d - 1) * params.gadget.ell * d * 8;
    println!(
        "d={} q=2^{:.0} ell={} threads={}",
        d,
        (params.q as f64).log2(),
        params.gadget.ell,
        rayon::current_num_threads()
    );
    println!(
        "digits_ntt per block: {:.1} MB  ({} MACs per pack)",
        digit_bytes as f64 / 1e6,
        (d - 1) * params.gadget.ell * d
    );

    let crs = crs(&params, &mut rng);
    let started = Instant::now();
    let pre = QueryPackPreprocessed::build(&params, &crs).expect("preprocessing succeeds");
    println!("offline build: {:.2} s\n", started.elapsed().as_secs_f64());

    let top = TopKeyImages::build(&params);
    let max_k = 16;
    let keys: Vec<PackingKeys<'_>> = (0..max_k).map(|_| key_bodies(&params, &mut rng)).collect();
    let blocks: Vec<Vec<u64>> = (0..max_k)
        .map(|idx| {
            (0..d)
                .map(|c| ((c as u64 + 1).wrapping_mul(idx as u64 * 7 + 3)) % params.q)
                .collect()
        })
        .collect();

    // One untimed pass so page faults on the freshly built digit cache are not
    // attributed to the first measured configuration.
    let _ = pre
        .pack_b_prevalidated(&blocks[0], &keys[0], &top)
        .expect("warmup pack succeeds");

    println!(
        "{:>3}  {:>12}  {:>12}  {:>10}  {:>12}  {:>9}",
        "k", "seq ms/q", "batch ms/q", "speedup", "stream GB/s", "MAC/cyc"
    );

    for k in [1_usize, 2, 4, 8, 16] {
        let block_refs: Vec<&[u64]> = blocks[..k].iter().map(|b| b.as_slice()).collect();
        let key_refs: Vec<&PackingKeys<'_>> = keys[..k].iter().collect();

        let reps = if d >= 2048 { 7 } else { 20 };

        let mut seq_best = f64::MAX;
        for _ in 0..reps {
            let t = Instant::now();
            for (b, key) in block_refs.iter().zip(key_refs.iter()) {
                let out = pre
                    .pack_b_prevalidated(b, key, &top)
                    .expect("sequential pack succeeds");
                std::hint::black_box(&out);
            }
            seq_best = seq_best.min(t.elapsed().as_secs_f64());
        }

        let mut bat_best = f64::MAX;
        for _ in 0..reps {
            let t = Instant::now();
            let out = pre
                .pack_b_batched_prevalidated(&block_refs, &key_refs, &top)
                .expect("batched pack succeeds");
            std::hint::black_box(&out);
            bat_best = bat_best.min(t.elapsed().as_secs_f64());
        }

        let seq_per = seq_best / k as f64 * 1e3;
        let bat_per = bat_best / k as f64 * 1e3;
        // The batch reads the digit stream once regardless of k.
        let stream_gbs = digit_bytes as f64 / bat_best / 1e9;
        let macs = ((d - 1) * params.gadget.ell * d * k) as f64;
        let mac_per_cycle = macs / bat_best / (rayon::current_num_threads() as f64 * 2.6e9);

        println!(
            "{k:>3}  {seq_per:>12.2}  {bat_per:>12.2}  {:>9.2}x  {stream_gbs:>12.1}  {mac_per_cycle:>9.3}",
            seq_per / bat_per
        );
    }

    println!(
        "\nstream GB/s assumes one pass over digits_ntt per batch; MAC/cyc assumes 2.6 GHz/core."
    );
}
