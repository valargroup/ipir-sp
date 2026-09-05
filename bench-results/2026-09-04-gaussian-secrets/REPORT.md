# Gaussian client secrets: validation and benchmarks

Fresh-query generation, seed-based decoding and experimental reusable batches now use the pinned backend discrete-Gaussian CDF sampler with standard deviation 6.4 (width `6.4 * sqrt(2*pi)`). Errors already used this distribution. This matches the Gaussian convention for YPIR’s DoublePIR/packing parameters; YPIR’s separate SimplePIR stage uses a different width. See [YPIR parameter selection](https://www.cs.utexas.edu/~dwu4/papers/YPIR.pdf).

The earlier ternary choice originated in the initial client implementation; its commit history contains no documented rationale. This migration aligns the secret distribution but does not establish a security level for the complete InspiRING transcript or its reuse across queries.

## Method and measured results

Measured 2026-09-04 on Apple M4 Max, 128 GiB, macOS, 16 Rayon workers, Rust 1.89.0, release profile. Both fresh and reused modes use Gaussian secrets. The synthetic database, production RLWE parameters, serialization, correctness assertions and byte accounting are the same as the [historical ternary benchmark](../2026-09-04-key-reuse/REPORT.md). Runs were sequential, with no concurrent build or test workload. Workstation timings are descriptive and are not a controlled estimate of the cost of changing the sampler.

All byte figures are amortized per query over a complete four-query batch. Warm totals assume cached public decoding data; cold totals include the first batch’s downloads. HTTP overhead is excluded.

| Shape | Queries per mode | Warm bytes, fresh → reused | Cold bytes, fresh → reused | Mean client generation (ms), fresh → reused | Mean server answer (ms), fresh → reused |
|---|---:|---:|---:|---:|---:|
| 2,048 × 4,096 | 20 | 106,496 → 41,984 | 113,664 → 70,656 | 8.95 → 2.96 | 4.87 → 4.50 |
| 28,672 × 32,768 | 12 | 318,464 → 253,952 | 375,808 → 483,328 | 37.57 → 26.55 | 94.23 → 97.57 |

Gaussian sampling leaves serialized sizes unchanged. Four-way reuse saves 60.6% of warm traffic in the key-dominated shape and 20.3% in the full shape. The full shape still costs 28.6% more for a cold first batch. Retained packing payload is approximately 0.75 and 6.00 GiB respectively; all-set preparation took 3.93 and 41.51 seconds.

## Correctness and compatibility

All 64 benchmark responses exactly matched expected database coefficients. The maximum sampled decryption error was 66,833,511,936 against a threshold of 2,199,023,255,543, giving more than 32× sampled headroom. Every response also passed the existing stricter `error < delta/8` assertion. These observations do not establish a failure probability.

The former ternary-only carry check now uses the Gaussian sampler’s finite support of ±65. Its bound of 76,336,066,560 is below `delta/32` for one key switch; it is not a full-cascade bound. Full-pipeline acceptance thresholds were unchanged.

Validation:

- 140 release tests passed across `inspiring` and `ipir-sp`, with all features; one existing documentation example ignored.
- Added a literal public-seed known-answer vector, backend sampler/RNG-state agreement, scale checks, and exact seed replay of secret, keys and query.
- Existing end-to-end, cancellation, boundary, retry and wrong-slot tests passed with the new high-level sampler.
- Formatting, Clippy and rustdoc checks run with warnings denied where applicable.
- Independent implementation review found no remaining blockers within the research scope; composed security and failure-tail analysis remain outstanding.

Server encodings and public preprocessing remain compatible. **Old unversioned client seeds need the old decoder**; finish outstanding requests before upgrading or issue fresh requests. See [migration instructions](../../ipir-sp/MIGRATION.md).

## Reproduce

```bash
cargo build --release -p ipir-sp --features experimental-key-reuse --example key_reuse_bench
target/release/examples/key_reuse_bench 2048 4096 4 5
target/release/examples/key_reuse_bench 28672 32768 4 3
```

Raw results identify `secret_distribution` and `secret_stddev`:

- [Key-dominated shape](raw/key-dominated-pool4.json)
- [Full snapshot shape](raw/full-snapshot-pool4.json)
