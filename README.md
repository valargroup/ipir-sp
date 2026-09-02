# IPIR+SP

**IPIR+SP** is a Private Information Retrieval (PIR) scheme that combines the
large-record throughput of [YPIR+SP](https://eprint.iacr.org/2024/270) with the
communication-efficient packing of
[InsPIRe](https://eprint.iacr.org/2025/1352).

Concretely, it keeps YPIR+SP's SimplePIR-style matrix-vector pipeline for the
first dimension, and replaces YPIR's CDKS ring-packing layer with a custom
implementation of `InsPIRing.Pack` (Algorithm 1 of ePrint 2025/1352).

## Why this exists

YPIR+SP applies CDKS packing on top of a SimplePIR-like matrix-vector multiply.
That packing layer is what makes YPIR+SP practical for large database records:
it compresses many LWE responses into a single RLWE ciphertext, slashing the
download.

InsPIRe took the idea one step further. Its authors observed that CDKS packing
was not optimised for the PIR threat model, where the server can absorb almost
unbounded *offline* preprocessing. They proposed a new packing protocol —
`InsPIRing.Pack` — that uploads exactly **two** key-switching matrices `(K_g,
K_h)` per query, instead of CDKS's `log d` expansion matrices, and shifts the
extra cost into a one-shot offline phase.

InsPIRe paired that packing with three new PIR constructions. Two of them are
impractical for the large-record setting we care about. The third one is
elegant — it encodes the database as polynomials and leans on RGSW — but it is
still too research-grade for production.

So we kept what works in each system:

- YPIR+SP's database/query arithmetic, which is already battle-tested for large
  records.
- InsPIRe's packing protocol, which is the part that actually moves the
  communication needle.

The result is **IPIR+SP**.

## Where it stands

All current numbers are from
[`bench-results/2026-09-02-second-optimization-pass/REPORT.md`](bench-results/2026-09-02-second-optimization-pass/REPORT.md),
measured on a Xeon Platinum 8358 (8 cores, AVX-512, the same CPU model as the
production PIR host) at the deployed shape: `28,672 × 32,768`, sixteen RLWE
output blocks, 1,792 nullifiers per row.

| Metric | current | note |
|---|---:|---|
| Total wire per query | **318,464 B** | 86,016 B packing keys + 150,528 B query up, 81,920 B down |
| Online server time | **122 ms** | 52 ms matrix-vector, 67 ms packing, 4 ms (de)serialization |
| Packing per output block | **4.2 ms** | |
| Offline preprocessing, full snapshot | **6.6 s** | `build_pack_preprocessed_blocks` over all sixteen CRS blocks |
| Offline per CRS block | **0.42 s** | |
| Decryption margin | 2^36 vs Δ/2 = 2^41 | real pipeline, production RLWE parameters, worst of 8 queries |

### How it got here

Three passes since the initial port, each with its own report and raw logs.
The wire numbers are the cleanest thread to follow:

| | shape | total wire | offline / block | report |
|---|---|---:|---:|---|
| Initial port, vs YPIR+SP | `524,288 × 2,048` | 3,780,608 B | — | [2026-05-10](bench-results/2026-05-10-ipir-ypir/REPORT.md) |
| First pass | `112,640 × 8,192` | 935,936 B (**4.04×**) | 9.39 s | [2026-09-02](bench-results/2026-09-02-optimization-pass/REPORT.md) |
| Second pass | `28,672 × 32,768` | 318,464 B (**2.94×**) | 0.42 s | [2026-09-02, second](bench-results/2026-09-02-second-optimization-pass/REPORT.md) |

Cumulatively that is **11.9× less wire** than the initial port. The offline
column is per CRS block on the Xeon; the first pass measured its own
preprocessing win on an arm64 laptop, so its Xeon figure is the second pass's
baseline measurement of that tree, and the initial port has no comparable
per-block number.

**Initial port (2026-05-10).** Against upstream YPIR+SP on the same Xeon:
end-to-end query 440 ms vs 447 ms, upload 3.77 MB vs 4.73 MB, packing public
parameters 98 KB vs 541 KB (**5.5×** — InsPIRe's two-matrix `(K_g, K_h)`
replacing CDKS's `log d` expansion matrices). Server time was 31% worse and
offline preprocessing ~10× worse; that was the trade InsPIRe opts into.

**First pass.** Mostly not cryptographic. The database was a 256:1 skew between
a 3.5 MB query and a 12 KB response; rebalancing it to four instances per row
cut wire 4× without touching the packing protocol. The first-dimension kernel
went parallel (3.6× on 8 threads), and three redundant divisions came out of
the `Θ(d³)` preprocessing loop. It also fixed a query-privacy break: the
first-dimension query carried no error term, and since the mask `a` is public,
the server could solve for the client secret by linear algebra.

**Second pass.** Three coupled changes. `InspiRING.Pack`'s `Θ(d³)` CRS
aggregate was reformulated in the NTT domain as `Θ(d² log d)`, and the online
collapse was fused into a single pass with one Barrett reduction per block
instead of one per `(step, slot)` — 4.9× per block. Those made output blocks
cheap enough to afford sixteen of them, and the wider shape, together with
serving the snapshot-constant `c1` row once from `GET /public-params` and
modulus-switching the query from 56 bits to 42, is where the 2.94× comes
from. Online server time moved only 1.14× because most of the packing win was
spent on the four-fold increase in blocks that bought the bandwidth.

**Hardening (2026-09-02, #10).** A review of the client encryption path found
the construction sound and landed the low-risk fixes: `target_row` is
bounds-checked (an out-of-range row used to encrypt the all-zero selector,
which decodes as "absent"), the selector and modular helpers are branch-free,
and the gadget carry-out term is pinned under budget by a test.

### Not yet re-baselined

The YPIR+SP comparison is still the 2026-05-10 numbers. YPIR+SP has not been
re-run at the new shape, so no current claim is made about relative server
time or end-to-end latency against it — only against this workspace's own
earlier commits.

### What the parameters assume

`d = 2048`, `q ≈ 2^56`, `σ = 6.4`, uniform ternary secret — Table 5 row 2 of
ePrint 2024/270. That sits on the HE-standard 128-bit line for `n = 2048`
rather than above it; a lattice-estimator run has not been recorded in this
repository. Every query samples a fresh secret and fresh `(K_g, K_h)`, which
is load-bearing: the server controls every byte the client decrypts, and a
reused secret would turn the client's observable behaviour into a decryption
oracle. PIR gives privacy, not integrity — the snapshot's SHA-256 is recorded
but not verified against anything, and a server can lie about content.

## Workspace layout

```
.
|-- inspiring/         # Algorithm 1 of InsPIRing.Pack, standalone crate
|-- ipir-sp/           # IPIR+SP: YPIR's SimplePIR pipeline wired to inspiring::pack
|-- simplepir-kernel/  # Backend-agnostic first-dimension SimplePIR kernels
|-- nullifier-pir/     # HTTP PIR server for 32-byte nullifier snapshots
|-- bench-results/     # Dated benchmark reports + raw logs
|-- plans/             # Implementation plans
|-- roman_notes.md     # Informal notes on the InsPIRing math
`-- Cargo.toml         # Workspace manifest (resolver = "2")
```

### `inspiring/` — InspiRING.Pack

A standalone crate exposing one primitive:

```rust
pub fn pack<'a>(b: &LweBatch, pre: &'a PackPreprocessed<'a>)
    -> Result<RlweCiphertext<'a>, InspiringError>;
```

It compresses `d` LWE ciphertexts (each of LWE dimension `d`) into a single
degree-`d` RLWE ciphertext using exactly two key-switching matrices. The
implementation tracks Algorithm 1 line by line and is cross-checked against a
Python reference oracle and the public Google reference implementation. See
[`inspiring/SPEC.md`](inspiring/SPEC.md) for the full paper-to-code contract
and [`inspiring/README.md`](inspiring/README.md) for the crate-level layout.

### `ipir-sp/` — IPIR+SP integration

Glue crate that keeps YPIR's SimplePIR database/query arithmetic and swaps the
CDKS packing boundary for `inspiring::pack`. Targets the IPIR-SP parameter set
from Table 5 row 2 of ePrint 2024/270, single-CRT on the RLWE side. See
[`ipir-sp/README.md`](ipir-sp/README.md) for the API and
[`ipir-sp/MIGRATION.md`](ipir-sp/MIGRATION.md) for the YPIR-to-IPIR+SP map.

### `simplepir-kernel/` — pluggable first-dimension kernel

Object-safe `FirstDimKernel` trait so the SimplePIR matrix-vector multiply can
be swapped for optimised CPU or future accelerator backends without touching
the InspiRING boundary. Ships with a portable `ChunkedSplitKernel` (default,
YPIR-style chunked-split accumulator) and a simple `ScalarKernel` reference.

### `nullifier-pir/` — production HTTP server

Actix-based PIR server tailored to fixed-width 32-byte nullifier snapshots.
Packs 1,792 nullifiers per SimplePIR row — sixteen RLWE output blocks — to fill
the 458,752-bit plaintext capacity at the headline parameter set. Two backends are available:

- `local-ipir` (default): the IPIR+SP path implemented in this workspace.
- `ypir-artifact`: pinned upstream YPIR+SP, used for apples-to-apples
  comparisons.

See [`nullifier-pir/README.md`](nullifier-pir/README.md).

### `bench-results/`

Each dated subdirectory contains a `REPORT.md` plus `raw/` logs reproducible
from the commands documented in the report. The YPIR+SP comparison lives in
[`bench-results/2026-05-10-ipir-ypir/REPORT.md`](bench-results/2026-05-10-ipir-ypir/REPORT.md);
the current numbers are in
[`bench-results/2026-09-02-second-optimization-pass/REPORT.md`](bench-results/2026-09-02-second-optimization-pass/REPORT.md).

## Backend

All crates share a single resolved [`spiral-rs`](https://github.com/valargroup/spiral-rs)
backend, pinned at the workspace root to Valar's fork:

```toml
[workspace.dependencies]
spiral-rs = { package = "valar-spiral-rs", git = "https://github.com/valargroup/spiral-rs.git", rev = "6f5b66c6a5a639827c6486c59d31c7ec2d4399a8" }
```

The fork keeps the scalar single-CRT multiply path correct and provides a
non-AVX-512 NTT, so the workspace builds on stable Rust without any
`target-cpu` override.

## Build, test, bench

From the workspace root:

```bash
cargo build --release
cargo test
cargo test -p inspiring
cargo test -p ipir-sp
```

Per-crate Criterion benchmarks:

```bash
cargo bench -p inspiring --bench pack
cargo bench -p ipir-sp --bench end_to_end
```

The default `ipir-sp` benchmark uses a small `d = 64` development profile.
Set `IPIR_SP_BENCH_MID=1` for the `d = 1024` mid-size profile,
`IPIR_SP_BENCH_FULL=1` for the full `params_for_simplepir(32768, 131072)`
profile (`d = 2048`, ~7+ GiB RAM during preprocessing), or
`IPIR_SP_BENCH_NULLIFIER=1` for the production nullifier shape
(`28,672 × 32,768`) — the only profile matching the deployed server. Its
constants mirror `nullifier-pir/src/encoding.rs`; nothing enforces that across
crates, so they have to be changed together.

The first-dimension kernel can also be benchmarked on its own, without paying
for offline preprocessing. Note it pins `112,640 × 8,192` — the previous
deployed shape — so that results stay comparable across this change; it no
longer matches the server:

```bash
cargo bench -p simplepir-kernel --bench first_dim
RAYON_NUM_THREADS=1 cargo bench -p simplepir-kernel --bench first_dim  # serial
```

## High-level flow

For a single SimplePIR query:

1. **Params.** `ipir_sp::params_for_simplepir(num_items, item_size_bits)`
   returns an `inspiring::RlweParams` plus YPIR transport and database
   dimensions, including the derived first-dimension query width.
2. **Server offline.** `YServer::perform_offline_precomputation_simplepir`
   computes `hint_0` from the public setup polynomials and splits it into CRS
   blocks; `build_pack_preprocessed_blocks` turns each into an
   `inspiring::QueryPackPreprocessed` (the fixed `c1` trace plus the gadget
   digit schedule), and `published_c1_rows` serializes the snapshot-constant
   `c1` rows once for `GET /public-params`.
3. **Client query.** `IPIRClient::generate_fresh_query_simplepir` samples a
   fresh ternary secret, the `(K_g, K_h)` packing-key bodies under it, and the
   encrypted one-hot selector; the selector goes on the wire via
   `to_switched_bytes` at the derived width.
4. **Server online.** `YServer::perform_full_online_computation_simplepir_measured`
   lifts the query back to `q`, runs the matrix product through
   `simplepir-kernel`, packs each intermediate `b` block against the uploaded
   key bodies, and returns only the `c2` rows, modulus-switched.
5. **Client decode.** `IPIRClient::decode_response_simplepir` pairs each `c2`
   with its published `c1` and runs standard RLWE decryption; do **not** apply
   YPIR's extra `poly_len` multiplier (InspiRING absorbs the `d^-1` scaling
   internally).

A worked example lives in
[`ipir-sp/README.md`](ipir-sp/README.md#basic-flow).

## Running the nullifier server

Download a snapshot and serve it over HTTP with the IPIR+SP backend:

```bash
cargo run --release -p nullifier-pir -- download \
  --url https://vote.fra1.cdn.digitaloceanspaces.com/snapshots/3317500/nullifiers.bin \
  --output data/nullifiers.bin

cargo run --release -p nullifier-pir -- serve \
  --snapshot-path data/nullifiers.bin \
  --backend local-ipir \
  --host 127.0.0.1 \
  --port 8080
```

The server exposes `GET /health`, `GET /meta`, `GET /public-params` (the
snapshot-constant `c1` rows, fetched once per snapshot), and `POST /query` with
backend-native query bytes.

## References

- IPIR+SP / YPIR+SP: ePrint 2024/270 — <https://eprint.iacr.org/2024/270>
- InsPIRe / InsPIRing.Pack: ePrint 2025/1352 — <https://eprint.iacr.org/2025/1352>
- Google reference implementation:
  <https://github.com/google/private-membership/tree/main/research/InsPIRe>
- Local InsPIRing spec: [`inspiring/SPEC.md`](inspiring/SPEC.md)
- Informal math walkthrough: [`roman_notes.md`](roman_notes.md)

## License

Dual-licensed under MIT or Apache-2.0, at your option. See
[`inspiring/LICENSE-MIT`](inspiring/LICENSE-MIT) and
[`inspiring/LICENSE-APACHE`](inspiring/LICENSE-APACHE).
