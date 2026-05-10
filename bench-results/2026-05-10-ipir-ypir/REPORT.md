# IPIR+SP vs YPIR+SP Benchmark Report

Date: 2026-05-10

## Environment

- Host: `ipir-avx512-32gb`
- Kernel: `Linux 6.8.0-71-generic`
- CPU: Intel Xeon Platinum 8358, 8 vCPUs, AVX-512 available
- Memory: 31 GiB RAM, no swap
- Rust: `rustc 1.87.0-nightly (ecade534c 2025-03-14)`, `cargo 1.87.0-nightly`
- `/root/ipir-sp` base commit: `96bbef78bbbb483da9ded5ff9ddf93acbf041b2e`
- `/root/ypir` commit: `4f7ef3d3bdd2d6cac898b701c2adf1299840e39a`

Raw artifacts are in `bench-results/2026-05-10-ipir-ypir/raw/`.

## Smoke Runs

### IPIR+SP Default Development Profile

Command:

```bash
cargo bench -p ipir-sp --bench end_to_end
```

Artifact: `raw/ipir-smoke.log`

- Profile: `ipir_sp_smaller_d64_64_128`
- Rows: 64
- Item size: 128 bits
- RLWE degree: 64
- Outputs: 1
- Serialized KS pair: 10 KiB
- Compressed KS pair estimate: 2 KiB
- Response: 0 KiB
- `||e_pack||_inf_bits`: 12
- `offline_crs_extract_and_preprocess/1`: 12.691 ms median
- `online_pack_and_serialize/1`: 1.0555 ms median

After the preprocessing rewrite, the same default profile was rerun:

- Artifact: `raw/ipir-smoke-after-preprocess-fix.log`
- `offline_crs_extract_and_preprocess/1`: 2.8326 ms median
- `online_pack_and_serialize/1`: 1.0691 ms median

### IPIR+SP Mid-Size Validation Profile

Command:

```bash
IPIR_SP_BENCH_MID=1 cargo bench -p ipir-sp --bench end_to_end
```

Artifact: `raw/ipir-mid-d1024-after-preprocess-fix.log`

- Profile: `ipir_sp_mid_d1024_1024_128`
- Rows: 1024
- Item size: 128 bits
- RLWE degree: 1024
- Outputs: 1
- Serialized KS pair: 256 KiB
- Compressed KS pair estimate: 112 KiB
- Response: 1 KiB
- `||e_pack||_inf_bits`: 17
- `offline_crs_extract_and_preprocess/1`: 3.1895 s median
- `online_pack_and_serialize/1`: 489.37 ms median

### YPIR+SP Smaller Supported Run

Command:

```bash
./target/release/run 16384 131072 1 /root/ipir-sp/bench-results/2026-05-10-ipir-ypir/raw/ypir-smoke.json
```

Artifacts: `raw/ypir-smoke.log`, `raw/ypir-smoke.json`

- Offline server time: 7636 ms
- SimplePIR prep time: 2861 ms
- Online server time: 288 ms
- First pass time: 47 ms
- Ring packing time: 278 ms
- Upload: 587776 bytes
- Download: 61440 bytes
- Trial server times: 328 ms, 247 ms

## Headline Runs

### YPIR+SP

Command:

```bash
./target/release/run 32768 131072 5 /root/ipir-sp/bench-results/2026-05-10-ipir-ypir/raw/ypir-32768x131072.json
```

Artifacts: `raw/ypir-32768x131072.log`, `raw/ypir-32768x131072.json`

- Offline server time: 8874 ms
- SimplePIR prep time: 5041 ms
- Online server time: 294 ms
- First pass time: 91 ms
- Ring packing time: 199 ms
- Upload: 702464 bytes
- Download: 61440 bytes
- Trial server times: 293, 292, 295, 298, 290 ms
- Standard deviation: 2.7276 ms

### IPIR+SP

Command:

```bash
IPIR_SP_BENCH_FULL=1 cargo bench -p ipir-sp --bench end_to_end
```

Artifact: `raw/ipir-32768x131072.log`

Result: failed before Criterion emitted the fixture summary or timing output.

```text
process didn't exit successfully: ... end_to_end-5fa70bb3417648ee --bench (signal: 9, SIGKILL: kill)
```

This matches the known full-fixture memory risk for the current preprocessing representation.

### IPIR+SP Lean Preprocessing Retry

Command:

```bash
IPIR_SP_BENCH_FULL=1 IPIR_SP_BENCH_LEAN_PREPROCESS=1 cargo bench -p ipir-sp --bench end_to_end
```

Artifact: `raw/ipir-32768x131072-lean.log`

Result: stopped after about 5.5 minutes with no fixture summary or Criterion timing output. The benchmark process was alive, using one CPU core, and using about 465 MiB RSS. This avoided the immediate OOM but exposed the remaining full-size preprocessing cost: the current InspiRING preprocessing computes the aggregated CRS state through a single-threaded O(d^2) transform/multiply path before Criterion can start measuring `offline_crs_extract_and_preprocess` or `online_pack_and_serialize`.

### IPIR+SP After Preprocessing Rewrite

Command:

```bash
IPIR_SP_BENCH_FULL=1 cargo bench -p ipir-sp --bench end_to_end
```

Artifact: `raw/ipir-32768x131072-after-preprocess-fix.log`

- Profile: `ipir_sp_32768_131072`
- Rows: 32768
- Item size: 131072 bits
- RLWE degree: 2048
- Outputs: 5
- DB columns: 10240
- Serialized KS pair: 192 KiB
- Compressed KS pair estimate: 168 KiB
- Response: 60 KiB
- `||e_pack||_inf_bits`: 34
- `offline_crs_extract_and_preprocess/5`: 100.43 s median
- `online_pack_and_serialize/5`: 4.4272 s median

### IPIR+SP After Online Collapse Digit Cache

Command:

```bash
IPIR_SP_BENCH_FULL=1 cargo bench -p ipir-sp --bench end_to_end
```

Artifact: `raw/ipir-32768x131072-after-online-cache.log`

- Profile: `ipir_sp_32768_131072`
- Rows: 32768
- Item size: 131072 bits
- RLWE degree: 2048
- Outputs: 5
- DB columns: 10240
- Serialized KS pair: 192 KiB
- Compressed KS pair estimate: 168 KiB
- Response: 60 KiB
- `||e_pack||_inf_bits`: 34
- `offline_crs_extract_and_preprocess/5`: 103.83 s median
- `online_pack_and_serialize/5`: 997.07 ms median

### IPIR+SP After Affine Collapse Cache

Command:

```bash
IPIR_SP_BENCH_FULL=1 cargo bench -p ipir-sp --bench end_to_end
```

Artifact: `raw/ipir-32768x131072-after-affine-cache.log`

- Profile: `ipir_sp_32768_131072`
- Rows: 32768
- Item size: 131072 bits
- RLWE degree: 2048
- Outputs: 5
- DB columns: 10240
- Serialized KS pair: 192 KiB
- Compressed KS pair estimate: 168 KiB
- Response: 60 KiB
- `||e_pack||_inf_bits`: 34
- `offline_crs_extract_and_preprocess/5`: 102.43 s median
- `online_pack_only/5`: 16.970 ms median
- `online_serialize_only/5`: 1.2599 ms median
- `online_pack_and_serialize/5`: 18.664 ms median

## Normalized Interpretation

- YPIR+SP headline full-system timing is 294 ms average online server time, including 199 ms ring packing.
- IPIR+SP headline now completes on this 31 GiB/no-swap host after removing the dead `a_hat` cache and replacing the preprocessing aggregation path.
- IPIR+SP pack-only after the affine collapse cache is 16.970 ms for five RLWE outputs. This is the closest local analogue to YPIR's 199 ms ring-packing timer, with the caveat that YPIR's timer includes pack public-parameter unpacking.
- IPIR+SP pack+serialize after the affine collapse cache is 18.664 ms. This is comparable to YPIR's post-first-pass online work (294 ms online server time minus 91 ms first pass = 203 ms), not to YPIR's full online time including the database dot product.
- IPIR+SP headline online pack/serialize improved from 4.4272 s before online caching, to 997.07 ms with cached collapse digits, to 18.664 ms with the affine collapse cache.
- IPIR+SP headline offline CRS extraction/preprocessing is 102.43 s for five RLWE outputs. The affine cache keeps deterministic collapse work offline, so offline setup remains heavy.

## Follow-up Needed

- Consider further preprocessing optimization if 100 s offline setup is too high for the intended benchmark target.
- If a full-system IPIR comparison is required, add a dedicated benchmark around `IPIRServer::perform_online_computation_simplepir` that reports scalar SimplePIR matrix time separately from InspiRING pack/serialize time.

## Online Gap Status

Resolved in code and benchmarked above: `PackPreprocessed` now caches the
affine collapse output (`a_final`, `b_offset`) derived from the deterministic
collapse trace. Online `inspiring::pack` now performs one NTT of `b̃`, one
polynomial add, and one stack per RLWE output, with zero online key-switch
matrix products.
