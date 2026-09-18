# IPIR-SP on InspiRING Benchmark Report

Phase 8 adds Criterion benchmarks in `benches/end_to_end.rs` for the YPIR
headline shape:

```bash
cargo bench -p ipir-sp --bench end_to_end
```

By default this runs a smaller development profile that keeps the same
offline/online benchmark shape but uses `d = 64`, one RLWE output, and small
test moduli. Set `IPIR_SP_BENCH_FULL=1` to attempt the full headline profile.

The full benchmark profile uses `params_for_simplepir(32768, 131072)`, which
yields:

| Field | Value |
| --- | ---: |
| DB rows | `32768` |
| item size | `131072` bits |
| RLWE degree | `2048` |
| RLWE outputs | `5` |
| SimplePIR columns | `10240` |
| plaintext modulus | `1 << 14` |
| single-CRT modulus | `72057594037641217` |

## Benchmarks

| Criterion id | What it measures |
| --- | --- |
| `offline_crs_extract_and_preprocess` | YPIR `hint_0` block extraction plus InspiRING query-pack preprocessing for all RLWE outputs. |
| `online_pack_inspiring` | InspiRING NTT packing (`pack_intermediate_blocks`) for all online `b` blocks. |
| `online_pack_reinspiring` | ReinspiRING coefficient packing (`H'·y`) for the same blocks. Built for SMALL/MID only; skipped at `d=2048` (FULL/NULLIFIER) because Compile preprocess is too heavy for the Criterion fixture. |
| `online_pack_and_serialize` | InspiRING packing plus response modulus switching / serialization. |

The stderr summary prints one-shot `packing_inspiring` and `packing_reinspiring` microseconds plus `H'_inf_bits` when ReinspiRING preprocess ran.

The scalar SimplePIR matrix and hint kernels in `ipir-sp` are correctness
ports, not the optimized YPIR kernels. For that reason the Phase 8 benchmark
isolates the packing boundary that is meant to replace CDKS rather than timing
the current portable matrix loops as a YPIR performance claim.

The benchmark fixture explicitly drops transient `hint_0`, CRS block, packed
response, and noise-check message buffers once they are no longer needed. The
long-lived online fixture keeps only the client secret, intermediate `b`
values, and `PackPreprocessed` cache.

## Paper Comparison Targets

| Metric | YPIR-CDKS target | IPIR-SP on InspiRING target |
| --- | ---: | ---: |
| Offline upload, KS keys | ~462 KiB | ~84 KiB compressed, ~96 KiB as current `u64` wire helper |
| Online server time | ~55.6 ms implied baseline | ~40 ms, about 28% lower |
| `\|\|e_pack\|\|_inf` | ~38.5 bits | target <= 33.4 bits |

The benchmark prints a one-time stderr summary with the current key-size
accounting, response size, and deterministic `||e_pack||_inf` bit length.

## Latest Local Results

Attempted on 2026-05-10 in the current Cursor workspace:

```bash
cargo bench -p ipir-sp --bench end_to_end
```

Result: no Criterion medians were produced. The benchmark executable started,
then exited with `SIGKILL` before emitting the fixture summary or timing output:

```text
Finished `bench` profile [optimized] target(s) in 0.06s
Running benches/end_to_end.rs (target/release/deps/end_to_end-0416eeddac60d254)
Gnuplot not found, using plotters backend
error: bench failed, to rerun pass `-p ipir-sp --bench end_to_end`

Caused by:
  process didn't exit successfully: `/root/inspire/target/release/deps/end_to_end-0416eeddac60d254 --bench` (signal: 9, SIGKILL: kill)
```

The host had approximately `7.8 GiB` RAM and no swap:

```text
Mem: 7.8Gi total, 6.0Gi available
Swap: 0B
```

Interpretation: the full `d = 2048` target fixture exceeded this host's memory
budget during `PackPreprocessed::build` setup, before the timed offline/online
measurements began. A release benchmark should be rerun on a larger-memory host,
or after the InspiRING preprocessing cache is made leaner for benchmark mode.

After adding the smaller default profile and explicit transient-buffer drops,
the default benchmark completed on the same host:

```bash
cargo bench -p ipir-sp --bench end_to_end
```

Fixture summary:

```text
profile=ipir_sp_smaller_d64_64_128
rows=64
item_bits=128
d=64
outputs=1
db_cols=64
serialized_ks_pair=10 KiB
compressed_ks_pair=2 KiB
response=0 KiB
||e_pack||_inf_bits=12
```

Criterion medians:

| Criterion id | Median | 95% interval |
| --- | ---: | ---: |
| `ipir_sp_smaller_d64_64_128/offline_crs_extract_and_preprocess/1` | `13.692 ms` | `13.460 ms` - `13.926 ms` |
| `ipir_sp_smaller_d64_64_128/online_pack_and_serialize/1` | `1.1198 ms` | `1.1018 ms` - `1.1374 ms` |
