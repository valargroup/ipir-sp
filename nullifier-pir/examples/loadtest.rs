//! Sustained-throughput harness for a running `nullifier-pir` server.
//!
//! Every existing benchmark in this workspace measures single-query latency.
//! Nothing measured queries per second, which is the number that matters for a
//! service, and nothing exercised concurrency at all — the server pins
//! `.workers(1)` and each query saturates the box with rayon, so concurrent
//! arrivals are expected to serialize rather than speed up. This measures both
//! so that expectation is checked rather than assumed.
//!
//! It replays one fixed query body, which is legitimate for timing: server work
//! is identical regardless of which row a query selects. Use
//! `replay_query` to produce the body.
//!
//! ```text
//! cargo run --release -p nullifier-pir --example loadtest -- \
//!     --url http://127.0.0.1:8080 --query /tmp/q.bin --requests 30 --concurrency 1,2,4,8
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (p * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn main() -> Result<()> {
    let url = arg("--url").unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    let query_path = arg("--query").context("--query <path> is required")?;
    let requests: usize = arg("--requests")
        .unwrap_or_else(|| "30".to_string())
        .parse()?;
    let levels: Vec<usize> = arg("--concurrency")
        .unwrap_or_else(|| "1,2,4,8".to_string())
        .split(',')
        .map(|s| s.trim().parse::<usize>())
        .collect::<Result<Vec<_>, _>>()?;

    let body = std::fs::read(&query_path).with_context(|| format!("read {query_path}"))?;
    let body = Arc::new(body);
    let query_url = format!("{}/query", url.trim_end_matches('/'));

    let client = reqwest::blocking::Client::builder()
        .pool_max_idle_per_host(64)
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    // Warm-up: the first request after start pays page-in on the database and
    // the digit cache, which would otherwise land entirely on concurrency=1.
    for _ in 0..2 {
        client
            .post(&query_url)
            .body(body.as_ref().clone())
            .send()?
            .error_for_status()?;
    }

    println!(
        "url={query_url}  query={} B  requests={requests}",
        body.len()
    );
    println!(
        "{:>5}  {:>9}  {:>10}  {:>10}  {:>10}  {:>10}",
        "conc", "QPS", "mean ms", "p50 ms", "p95 ms", "p99 ms"
    );

    for &conc in &levels {
        let next = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let mut handles = Vec::with_capacity(conc);

        for _ in 0..conc {
            let client = client.clone();
            let query_url = query_url.clone();
            let body = Arc::clone(&body);
            let next = Arc::clone(&next);
            handles.push(std::thread::spawn(move || -> Result<Vec<f64>> {
                let mut samples = Vec::new();
                loop {
                    if next.fetch_add(1, Ordering::SeqCst) >= requests {
                        break;
                    }
                    let t = Instant::now();
                    let response = client
                        .post(&query_url)
                        .body(body.as_ref().clone())
                        .send()?
                        .error_for_status()?;
                    let bytes = response.bytes()?;
                    std::hint::black_box(&bytes);
                    samples.push(t.elapsed().as_secs_f64() * 1e3);
                }
                Ok(samples)
            }));
        }

        let mut latencies = Vec::with_capacity(requests);
        for handle in handles {
            latencies.extend(handle.join().expect("worker panicked")?);
        }
        let elapsed = started.elapsed().as_secs_f64();

        latencies.sort_by(|a, b| a.partial_cmp(b).expect("no NaN latency"));
        let mean = latencies.iter().sum::<f64>() / latencies.len() as f64;
        println!(
            "{:>5}  {:>9.2}  {:>10.1}  {:>10.1}  {:>10.1}  {:>10.1}",
            conc,
            latencies.len() as f64 / elapsed,
            mean,
            percentile(&latencies, 0.50),
            percentile(&latencies, 0.95),
            percentile(&latencies, 0.99),
        );
    }

    Ok(())
}
