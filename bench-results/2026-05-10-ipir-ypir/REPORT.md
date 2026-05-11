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

### Nullifier PIR Full-Snapshot Query Check After YPIR-Style Kernel

Command shape:

```bash
target/release/nullifier-pir serve \
  --snapshot-path data/nullifiers.bin \
  --backend local-ipir \
  --host 127.0.0.1 \
  --port 8090 \
  --setup-seed 7
```

Client commands and exact output: `raw/nullifier-full-snapshot-ypir-kernel-query-latency.log`

Notes:

- Server: full `data/nullifiers.bin`, 49,925,853 nullifiers.
- Backend: `local-ipir`, rebuilt after switching `IPIRServer::new` to the default `simplepir-kernel::ChunkedSplitKernel`.
- Timing source: the client prints local query generation, HTTP POST round trip, client decode, and total query time; server time is read from the `/query` response header `x-nullifier-pir-server-time-us`.
- The absent-nullifier process wall time includes the CLI's local full-snapshot scan to confirm absence before sending the PIR query.

Fixture query results:

- Existing nullifier `b3cdb97715d5e3dd624fc87906b9d13b4e4ec6a63989d989936f2504f0a1f706`: found at global index 0, row 0, offset 0, verified through PIR.
  - Full query: 601.768 ms
  - Client query generation: 46.086 ms
  - HTTP POST round trip: 524.163 ms
  - Server: 517.883 ms
  - Client decode: 31.324 ms
  - Process wall: 0.65 s
- Existing nullifier `4b4f13ad02a04d16e6efa83730751f53eead7dbf019e1632d937b8c8631d393e`: found at global index 1,638,400, row 14,628, offset 64, verified through PIR.
  - Full query: 595.809 ms
  - Client query generation: 45.864 ms
  - HTTP POST round trip: 523.787 ms
  - Server: 515.472 ms
  - Client decode: 26.062 ms
  - Process wall: 0.67 s
- Absent nullifier `0000000000000000000000000000000000000000000000000000000000000000`: confirmed absent locally and not present in decoded probe row 0.
  - Full query: 599.461 ms
  - Client query generation: 45.875 ms
  - HTTP POST round trip: 527.433 ms
  - Server: 523.124 ms
  - Client decode: 26.046 ms
  - Process wall: 1.17 s

### Nullifier PIR After Reference-Compatible IPIR-SP Wire Format

Command shape:

```bash
target/release/nullifier-pir serve \
  --snapshot-path data/nullifiers.bin \
  --backend local-ipir \
  --host 127.0.0.1 \
  --port 8090 \
  --setup-seed 7
```

Client commands and exact output: `raw/nullifier-ipir-reference-compatible-3queries.log`

Notes:

- Backend: `local-ipir`, rebuilt after switching the request body from compact `(K_g, K_h)` to reference-style packing-key bodies.
- Request body: `reference_packing_keys || packed_first_dim_query`.
- The old server-side key-bind/preprocess phase is no longer used for this path; uploaded key bodies are consumed by the reference-compatible online packing routine.

Average over the three fixture queries:

- Full query: 2603.886 ms
- Client query generation: 71.658 ms
- HTTP POST round trip: 2504.729 ms
- Server: 2501.919 ms
- Client decode: 27.330 ms
- Upload: 3,768,320 bytes
- Download: 12,288 bytes
- Upload breakdown:
  - Reference packing keys: 98,304 bytes
  - Packed first-dimension query: 3,670,016 bytes
- Server breakdown:
  - Setup/key deserialize: 1.218 ms
  - Pack preprocess: 0.000 ms
  - Online query deserialize: 9.944 ms
  - Matrix-vector multiply: 524.026 ms
  - Reference-compatible packing: 1963.204 ms
  - Serialization: 0.278 ms

Fixture query results:

- Existing nullifier `b3cdb97715d5e3dd624fc87906b9d13b4e4ec6a63989d989936f2504f0a1f706`: found at global index 0, row 0, offset 0, verified through PIR.
  - Full query: 2670.203 ms
  - Server: 2567.314 ms
  - Upload/download: 3,768,320 / 12,288 bytes
- Existing nullifier `4b4f13ad02a04d16e6efa83730751f53eead7dbf019e1632d937b8c8631d393e`: found at global index 1,638,400, row 14,628, offset 64, verified through PIR.
  - Full query: 2609.520 ms
  - Server: 2507.408 ms
  - Upload/download: 3,768,320 / 12,288 bytes
- Absent nullifier `0000000000000000000000000000000000000000000000000000000000000000`: confirmed absent locally and not present in decoded probe row 0.
  - Full query: 2531.935 ms
  - Server: 2431.036 ms
  - Upload/download: 3,768,320 / 12,288 bytes

### Nullifier PIR After Once-Per-Request Key Expansion

Client commands and exact output: `raw/nullifier-ipir-reference-expanded-once-3queries.log`

This run keeps the same reference-compatible wire format but expands the uploaded
packing-key bodies once per request, then reuses the expanded key images across
all five RLWE output blocks.

Average over the three fixture queries:

- Full query: 2483.725 ms
- Client query generation: 71.717 ms
- HTTP POST round trip: 2384.848 ms
- Server: 2380.909 ms
- Client decode: 26.947 ms
- Upload: 3,768,320 bytes
- Download: 12,288 bytes
- Upload breakdown:
  - Reference packing keys: 98,304 bytes
  - Packed first-dimension query: 3,670,016 bytes
- Server breakdown:
  - Setup/key deserialize: 2.132 ms
  - Pack preprocess: 0.000 ms
  - Online query deserialize: 11.475 ms
  - Matrix-vector multiply: 518.773 ms
  - Reference-compatible packing: 1838.673 ms
  - Serialization: 0.263 ms

Compared with the first reference-compatible run, once-per-request expansion
reduced average packing time from 1963.204 ms to 1838.673 ms. The remaining
packing cost is dominated by the `d - 1` key-switch-style products per RLWE
output block, not repeated key image expansion.

### Nullifier PIR After Fixed Top-Row Image Cache

Client commands and exact output: `raw/nullifier-ipir-reference-shared-top-cache-3queries.log`

This run keeps the same reference-compatible wire format and additionally
precomputes the fixed public top-row `K_g` images once at server startup. Per
query, the server now automorphs only the uploaded secret-dependent body row and
stacks it with cached top rows.

Average over the three fixture queries:

- Full query: 1676.448 ms
- Client query generation: 71.612 ms
- HTTP POST round trip: 1578.293 ms
- Server: 1575.765 ms
- Client decode: 26.317 ms
- Upload: 3,768,320 bytes
- Download: 12,288 bytes
- Server breakdown:
  - Setup/key deserialize: 0.936 ms
  - Pack preprocess: 0.000 ms
  - Online query deserialize: 9.118 ms
  - Matrix-vector multiply: 525.198 ms
  - Reference-compatible packing: 1037.349 ms
  - Serialization: 0.269 ms

Representative server-side packing logs:

```text
reference_key_expand_breakdown_us total=792735 restore_kh=23 kg_left_body_images=393900 kg_right_body_images=398802 left_count=1023 right_count=1023
reference_packing_breakdown_us total=1010326 expand_keys=792780 batch_build=14611 block_pack_total=202675 block_pack_by_block=[202675]
```

Compared with once-per-request expansion without the fixed top-row cache,
average packing time dropped from 1838.673 ms to 1037.349 ms. The dominant
remaining cost is now automorphing the uploaded `K_g` body row (`~0.79 s` per
query), while the collapse/key-switch products are about `~0.20 s`.

### Recent Nullifier PIR Comparison: Canonical IPIR+SP vs YPIR+SP

This comparison uses the latest full-dataset `local-ipir` run after making the
fused uploaded-key collapse path canonical for IPIR-SP packing. The YPIR+SP
baseline is the last recorded nullifier run in
`raw/nullifier-ypir-instrumented-3queries.log`.

Average over the three fixture queries from `nullifier-pir/NULLIFIER_FIXTURE.md`:

| Metric | IPIR+SP latest | YPIR+SP last | Difference |
|---|---:|---:|---:|
| Full query | 808.607 ms | 824.032 ms | IPIR -15.425 ms |
| Server total | 705.539 ms | 549.544 ms | IPIR +155.995 ms |
| Matrix-vector | 517.654 ms | 491.667 ms | IPIR +25.987 ms |
| Packing | 171.631 ms | 54.667 ms | IPIR +116.964 ms |
| Client query generation | 71.476 ms | 266.426 ms | IPIR -194.950 ms |
| Client decode | 26.720 ms | 4.119 ms | IPIR +22.601 ms |
| Upload | 3,768,320 bytes | 4,734,976 bytes | IPIR -966,656 bytes |
| Download | 12,288 bytes | 12,288 bytes | same |

Upload breakdown:

| Component | IPIR+SP latest | YPIR+SP last |
|---|---:|---:|
| Packing/public parameters | 98,304 bytes packing keys | 540,672 bytes pack public params |
| Online query | 3,670,016 bytes | 4,194,304 bytes |
| Total upload | 3,768,320 bytes | 4,734,976 bytes |

Per-fixture IPIR+SP results:

| Fixture | Total | Server | Matrix | Packing | Result |
|---|---:|---:|---:|---:|---|
| Row 0 present | 815.571 ms | 710.248 ms | 524.232 ms | 170.336 ms | verified found |
| Row 14628 present | 811.627 ms | 709.611 ms | 520.460 ms | 172.558 ms | verified found |
| Absent probe row 0 | 798.624 ms | 696.758 ms | 508.270 ms | 171.998 ms | verified absent |

The latest IPIR+SP run is about 1.02x faster end-to-end than the last YPIR+SP
nullifier run, despite server-side work remaining about 156 ms slower. IPIR+SP
uploads about 20.4% less data. Server-side packing logs no longer include a
separate key expansion phase; canonical fused packing averages 171.631 ms.

### Nullifier PIR After Packing Hot-Path Micro-Optimizations

Client commands and exact output: `raw/nullifier-ipir-pack-microopt-3queries.log`

This run was taken after removing dummy online LWE `a` vector construction,
hoisting repeated packing-key/top-image validation out of the per-block loop,
removing ad hoc packing stderr instrumentation, reducing once per output
coefficient in `multiply_permuted_body_by_digits` when safe, and adding
block-level Rayon parallelism for multi-output configurations. The nullifier
configuration has one output block, so the parallel block path does not affect
this specific benchmark.

The server was restarted, three warm-up queries were discarded, then three row
0 fixture queries were measured.

Average over the three measured queries:

- Full query: 794.022 ms
- Client query generation: 71.753 ms
- HTTP POST round trip: 694.685 ms
- Server: 690.398 ms
- Client decode: 27.416 ms
- Upload: 3,768,320 bytes
- Download: 12,288 bytes
- Upload breakdown:
  - Reference packing keys: 98,304 bytes
  - Packed first-dimension query: 3,670,016 bytes
- Server breakdown:
  - Setup/key deserialize: 2.163 ms
  - Pack preprocess: 0.000 ms
  - Online query deserialize: 11.644 ms
  - Matrix-vector multiply: 525.753 ms
  - Reference-compatible packing: 150.559 ms
  - Serialization: 0.273 ms

Compared with the previous warmed nullifier run after validation hoisting,
packing improved from 156.813 ms to 150.559 ms. Compared with the canonical
fused-packing comparison above, packing improved from 171.631 ms to 150.559 ms,
and full query latency improved from 808.607 ms to 794.022 ms.

### Nullifier PIR After Uploaded-Key Affine Cache

Client commands and exact output: `raw/nullifier-ipir-uploaded-affine-cache-3queries.log`

This run keeps the reference-compatible fresh-query wire format, but
`QueryPackPreprocessed` now caches the fixed public `c1` collapse trace for the
uploaded-key path. Online packing builds `b̃`, transforms it to NTT form, folds
in only the uploaded body-row `c2` contributions, and stacks with the cached
fixed `c1`.

The server was restarted, three warm-up queries were discarded, then three row
0 fixture queries were measured.

Average over the three measured queries:

- Full query: 695.698 ms
- Client query generation: 82.196 ms
- HTTP POST round trip: 586.136 ms
- Server: 580.595 ms
- Client decode: 27.170 ms
- Upload: 3,768,320 bytes
- Download: 12,288 bytes
- Upload breakdown:
  - Reference packing keys: 98,304 bytes
  - Packed first-dimension query: 3,670,016 bytes
- Server breakdown:
  - Setup/key deserialize: 2.273 ms
  - Pack preprocess: 0.000 ms
  - Online query deserialize: 13.413 ms
  - Matrix-vector multiply: 524.467 ms
  - Reference-compatible packing: 40.166 ms
  - Serialization: 0.270 ms

Compared with the preceding micro-optimized path, packing improved from
150.559 ms to 40.166 ms. Compared with the canonical fused-packing comparison
above, packing improved from 171.631 ms to 40.166 ms, and full query latency
improved from 808.607 ms to 695.698 ms.

### Nullifier PIR After AVX512 First-Pass Kernels

YPIR+SP was rebuilt with its `explicit_avx512` feature enabled using
`RUSTC_BOOTSTRAP=1 RUSTFLAGS="-C target-cpu=native"`, then served through the
`nullifier-pir` `ypir-artifact` backend on the full `data/nullifiers.bin`
snapshot. IPIR+SP was rebuilt with the new `U16Avx512Kernel` selected
automatically for `u16` servers. Both runs used warm server processes.

For YPIR+SP, one warm pass over the three fixture queries was discarded, then
the row 0 existing, row 14628 existing, and row 0 absent fixture queries were
measured. For IPIR+SP, three row 0 warm-up queries were discarded, then three
row 0 fixture queries were measured.

Average over the three measured queries:

| Backend | Full query | Client query gen | HTTP round trip | Server | Matrix-vector | Packing | Client decode | Upload | Download |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| YPIR+SP AVX512 | 447.334 ms | 162.266 ms | 280.736 ms | 277.964 ms | 240.333 ms | 34.667 ms | 4.037 ms | 4,734,976 bytes | 12,288 bytes |
| IPIR+SP AVX512 | 440.438 ms | 71.787 ms | 367.872 ms | 363.939 ms | 308.054 ms | 41.931 ms | 0.479 ms | 3,768,320 bytes | 12,288 bytes |

Server-side, YPIR+SP remains faster after enabling AVX512 in both kernels:
277.964 ms versus 363.939 ms. Most of that gap is the first-dimension
matrix-vector product: 240.333 ms for YPIR+SP versus 308.054 ms for IPIR+SP.
YPIR+SP's packing is also lower at 34.667 ms versus 41.931 ms.

End-to-end, IPIR+SP remains slightly lower in this run, 440.438 ms versus
447.334 ms, because the fresh-query upload is smaller and client query
generation is much faster in the current IPIR client path. IPIR+SP uploads
3,768,320 bytes versus YPIR+SP's 4,734,976 bytes.

## Normalized Interpretation

- YPIR+SP headline full-system timing is 294 ms average online server time, including 199 ms ring packing. Through `nullifier-pir` with the artifact `explicit_avx512` backend, warm full-snapshot online server time is 277.964 ms.
- IPIR+SP headline now completes on this 31 GiB/no-swap host after removing the dead `a_hat` cache and replacing the preprocessing aggregation path.
- IPIR+SP pack-only after the affine collapse cache is 16.970 ms for five RLWE outputs. This is the closest local analogue to YPIR's 199 ms ring-packing timer, with the caveat that YPIR's timer includes pack public-parameter unpacking.
- IPIR+SP pack+serialize after the affine collapse cache is 18.664 ms. This is comparable to YPIR's post-first-pass online work (294 ms online server time minus 91 ms first pass = 203 ms), not to YPIR's full online time including the database dot product.
- IPIR+SP headline online pack/serialize improved from 4.4272 s before online caching, to 997.07 ms with cached collapse digits, to 18.664 ms with the affine collapse cache.
- IPIR+SP headline offline CRS extraction/preprocessing is 102.43 s for five RLWE outputs. The affine cache keeps deterministic collapse work offline, so offline setup remains heavy.
- The reference-compatible fresh-query path intentionally shifts away from the compact affine-cache request shape. It removes the explicit server key-bind/preprocess phase, but the uploaded-key path now caches the fixed public collapse trace; online packing for the full nullifier snapshot is about 40-42 ms after the uploaded-key affine cache and AVX512 first-pass work.
- With AVX512 first-pass kernels on both paths, IPIR+SP is still slightly faster end-to-end in the warm `nullifier-pir` comparison (440.438 ms versus 447.334 ms), while YPIR+SP is faster server-side (277.964 ms versus 363.939 ms).

## Follow-up Needed

- Consider further preprocessing optimization if 100 s offline setup is too high for the intended benchmark target.
- If a full-system IPIR comparison is required, add a dedicated benchmark around `IPIRServer::perform_online_computation_simplepir` that reports scalar SimplePIR matrix time separately from InspiRING pack/serialize time.

## Online Gap Status

Resolved in code and benchmarked above: `PackPreprocessed` now caches the
affine collapse output (`a_final`, `b_offset`) derived from the deterministic
collapse trace. Online `inspiring::pack` now performs one NTT of `b̃`, one
polynomial add, and one stack per RLWE output, with zero online key-switch
matrix products.
