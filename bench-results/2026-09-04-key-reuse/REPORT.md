# Bounded evaluation-key reuse: local prototype measurements

Four-way reuse substantially reduces traffic in the key-dominated shape. In the full-snapshot shape it reduces warm-cache traffic, but increases total bytes for a cold client making one batch. Eight sets save only another 3.3 percentage points of warm traffic in that shape while doubling retained packing-cache payload. The measured result favors four sets for the first experiment, with workload-specific caching criteria before any production decision.

## Environment and method

- Date: 2026-09-04. Apple M4 Max, 128 GiB unified memory, 16 Rayon workers, macOS, Rust 1.89.0. Native local CPU execution; not the Linux AVX-512 production host.
- Base commit: `e875404cef33661906ab60af236dfb327e6b28b1`, plus the accompanying uncommitted experimental changes. Release profile uses optimization level 3, thin LTO and one codegen unit; no additional target-cpu override was set for these runs.
- Production RLWE parameters in every run: degree 2048, modulus 72,057,594,037,641,217, plaintext modulus 16,384, gadget length 3/base 2^19, sampler sigma 6.4.
- Synthetic arithmetic-pattern database, not a downloaded nullifier snapshot. The full profile matches its 28,672 × 32,768 encoded shape. The small profile is 2,048 × 4,096, where keys constitute 80.77% of warm total payload.
- Modes alternate order across batches. Each mode includes fresh private randomness, real key/query serialization, server key deserialization, matrix-vector evaluation, packing and response decoding. Every returned coefficient is checked against its expected row.
- The baseline uses set 0 with fresh keys each query. Reuse keeps one key pair and visits every set once. Both modes run in a process holding the complete pool, so this is not a separately isolated baseline RSS measurement.
- Key-dominated profile: 5 batches, 20 queries per mode. Full 4-set profile: 3 batches, 12 queries per mode. Full 8-set profile: 3 batches, 24 queries per mode. Timings are descriptive samples on a non-isolated workstation, not confidence intervals or production throughput estimates.

## Payload bytes

All figures below are bytes per query, amortized over a complete batch. Warm traffic assumes public decoding data is cached; cold traffic includes downloading the initial batch’s public decoding data. HTTP framing, headers, public seed metadata, connection setup and cache lookup are excluded. Serialized key bodies are 86,016 bytes.

| Profile | Fresh upload | Reused upload | Fresh warm total | Reused warm total | Warm reduction | Fresh cold total | Reused cold total | Cold change |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Key-dominated, 4 sets | 96,256 | 31,744 | 106,496 | 41,984 | 60.6% | 113,664 | 70,656 | -37.8% |
| Full snapshot shape, 4 sets | 236,544 | 172,032 | 318,464 | 253,952 | 20.3% | 375,808 | 483,328 | +28.6% |
| Full snapshot shape, 8 sets | 236,544 | 161,280 | 318,464 | 243,200 | 23.6% | 347,136 | 472,576 | +36.1% |

The cold penalty is public `c1`: 28,672 bytes per set in the key-dominated profile, versus 229,376 bytes per set in the full shape. Four sets save 64,512 key bytes per query; the full shape’s extra decoding download exceeds that saving for one cold batch. Responses remain 10,240 and 81,920 bytes respectively.

For N queries against one snapshot in complete B-query batches, the net saving is `N*K*(1-1/B) - (B-1)*C`, where K is key bytes and C is public decoding bytes per set. In the full shape, four sets break even after about 10.7 queries (12 when restricted to full batches), and eight after about 21.3 (24 in full batches). The key-dominated shape benefits in its first four-query batch. Unused batch slots and frequent snapshot invalidation reduce amortization.

## Runtime and memory

Client generation includes key generation/serialization amortized over the batch and query generation/serialization. Server answer time excludes separately recorded key parsing and all offline preparation. No HTTP/network timing is measured.

| Profile | Mean client generation, fresh → reused (ms/query) | Mean server answer, fresh → reused (ms) | Reported median server answer, fresh → reused (ms) | Retained pool packing payload (GiB) | All-set preparation (s) |
|---|---:|---:|---:|---:|---:|
| Key-dominated, 4 sets | 7.40 → 2.58 | 12.85 → 10.47 | 10.53 → 7.45 | 0.750 | 7.45 |
| Full snapshot shape, 4 sets | 39.95 → 33.19 | 138.84 → 141.30 | 124.76 → 129.08 | 5.998 | 46.31 |
| Full snapshot shape, 8 sets | 32.92 → 24.41 | 65.20 → 115.75 | 61.88 → 72.02 | 11.996 | 106.30 |

The prototype preserves the server’s existing online arithmetic. Reused keys avoid repeated key parsing but do not remove packing work. Timing spread is large, particularly the 8-set reused run (approximately 61–313 ms/server answer), and baseline timings differ across runs. These measurements do not establish a server throughput benefit. Reported medians select the upper middle sample when counts are even.

Packing payload counts allocated polynomial contents, not total process memory. The shared database, fixed top-key images, client setup/decoding data, allocation overhead and transient preprocessing buffers are additional. The 8-set full-profile process peaked at 21,122,465,792 resident bytes (19.67 GiB), measured by macOS `/usr/bin/time -l`; that includes both client and server parts of this in-process harness. Retained packing payload alone was 12,880,707,584 bytes (11.996 GiB).

Preparation measurements include hint construction, CRS packing preprocessing, publication and recovery of decoding data for each set; database ingestion is reported separately in the raw JSON. First-set preparation was approximately 2.02 s, 11.54 s and 14.32 s respectively. These runs do not optimize simultaneous preparation across sets.

## Correctness and review

All 112 benchmark query responses matched every synthetic database coefficient. The worst observed error was 63,712,934,483 against a decryption threshold of 2,199,023,255,543: more than 34× headroom. Every sample also satisfied the stricter `error < delta/8` assertion. These are sampled correctness results, not a bound on failure probability or proof of privacy.

The experimental API enforces private, monotone slot allocation and creates a fresh secret for each batch. A literal public-setup test vector pins derivation; allocation/exhaustion tests cover 4/8/16 sets. The cancellation regression attacks actual switched query bytes. The end-to-end test covers two batches, ring-boundary rows, all four sets, immutable retries and wrong-slot public decoding data.

Independent second-agent code review found no remaining implementation or byte-accounting blockers for the feature-gated in-process prototype. It did not approve production cryptographic use. The conditional security argument, auxiliary evaluation-key assumption, trusted setup assumption and missing transport bindings are documented in [KEY_REUSE_EXPERIMENT.md](../../ipir-sp/KEY_REUSE_EXPERIMENT.md).

The recorded benchmarks and original 142-test validation used the base above. The PR was subsequently isolated onto `main` (`f328c49`), excluding the unrelated row-sharding commit; the same full release suite passed with 138 tests on that base. The query/evaluation arithmetic used by this experiment is unchanged by that exclusion.

Original benchmark validation passed:

- `cargo test -p inspiring -p ipir-sp --all-features --release --no-fail-fast`: 142 tests passed; one pre-existing documentation example ignored.
- `cargo clippy -p inspiring -p ipir-sp --all-targets --all-features -- -D warnings`.
- `cargo fmt -p inspiring -p ipir-sp -- --check`.
- `RUSTDOCFLAGS='-D warnings' cargo doc -p inspiring -p ipir-sp --no-deps --all-features`.
- `git diff --check`.

No production deployment or HTTP integration was performed.

## Reproduction and raw results

```bash
cargo build --release -p ipir-sp --features experimental-key-reuse --example key_reuse_bench
target/release/examples/key_reuse_bench 2048 4096 4 5
target/release/examples/key_reuse_bench 28672 32768 4 3
/usr/bin/time -l target/release/examples/key_reuse_bench 28672 32768 8 3
```

- [Key-dominated, 4 sets](raw/key-dominated-pool4.json)
- [Full snapshot shape, 4 sets](raw/full-snapshot-pool4.json)
- [Full snapshot shape, 8 sets](raw/full-snapshot-pool8.json)
- [8-set process timing and memory](raw/full-snapshot-pool8-time.txt)
