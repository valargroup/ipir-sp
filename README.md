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

## Headline impact

Numbers below are from the latest local run on the production
nullifier dataset (49,925,853 records, 32-byte items), measured against the
upstream YPIR+SP baseline. Full report and raw logs:
[`bench-results/2026-05-10-ipir-ypir/REPORT.md`](bench-results/2026-05-10-ipir-ypir/REPORT.md).

| Metric | YPIR+SP | IPIR+SP | Delta |
|---|---:|---:|---:|
| End-to-end query | 824 ms | 794 ms | **−4%** |
| Upload | 4.73 MB | 3.77 MB | **−20%** |
| Packing public params (per setup) | 540,672 B | 98,304 B | **−5.5×** |
| Online query bytes | 4.19 MB | 3.67 MB | **−12%** |
| Download | 12.3 KB | 12.3 KB | same |

Two things are worth highlighting:

- **Cryptographic key material is ~5.5× smaller.** InsPIRe's two-matrix
  `(K_g, K_h)` upload replaces CDKS's `log d` expansion matrices, which is the
  single largest contributor to the upload reduction.
- **End-to-end latency is comparable.** IPIR+SP's online server work is
  slightly heavier than YPIR+SP's, but the smaller upload more than absorbs
  that on a real network round-trip. On the Criterion bench
  (`IPIR_SP_BENCH_FULL=1`, `d=2048`, 5 outputs) the *pack-only* online phase
  is **17 ms** after the affine collapse cache, well below YPIR's
  199 ms ring-packing timer.

The trade-off — and it is a real one — is offline preprocessing. The full
fixture's CRS extraction and `PackPreprocessed` build takes ~100 s today,
versus YPIR+SP's ~9 s offline phase. This is the cost InsPIRe explicitly opts
into: heavier offline work in exchange for cheaper, smaller online queries.

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
Packs 112 nullifiers per SimplePIR row to fill the 28,672-bit plaintext
capacity at the headline parameter set. Two backends are available:

- `local-ipir` (default): the IPIR+SP path implemented in this workspace.
- `ypir-artifact`: pinned upstream YPIR+SP, used for apples-to-apples
  comparisons.

See [`nullifier-pir/README.md`](nullifier-pir/README.md).

### `bench-results/`

Each dated subdirectory contains a `REPORT.md` plus `raw/` logs reproducible
from the commands documented in the report. The current headline report is
[`bench-results/2026-05-10-ipir-ypir/REPORT.md`](bench-results/2026-05-10-ipir-ypir/REPORT.md).

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
Set `IPIR_SP_BENCH_MID=1` for the `d = 1024` mid-size profile, or
`IPIR_SP_BENCH_FULL=1` for the full `params_for_simplepir(32768, 131072)`
profile (`d = 2048`, ~7+ GiB RAM during preprocessing).

## High-level flow

For a single SimplePIR query:

1. **Params.** `ipir_sp::params_for_simplepir(num_items, item_size_bits)`
   returns an `inspiring::RlweParams` plus YPIR transport and database
   dimensions.
2. **Client setup.** Sample a ternary RLWE secret and generate one per-query
   `(K_g, K_h)` pair via `client::generate_ks_pair`.
3. **Server offline.** `YServer::perform_offline_precomputation_simplepir`
   computes `hint_0`, splits it into CRS blocks, and builds an
   `inspiring::PackPreprocessed` cache for each block (with the affine
   collapse output cached so the online path performs zero key-switch
   matrix products).
4. **Server online.** `YServer::perform_online_computation_simplepir` runs the
   SimplePIR matrix product through `simplepir-kernel`, packs each
   intermediate `b` block with `inspiring::pack`, and serializes the response
   with single-CRT row-wise modulus switching.
5. **Client decode.** Standard RLWE decryption on the recovered rows; do
   **not** apply YPIR's extra `poly_len` multiplier (InspiRING absorbs the
   `d^-1` scaling internally).

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

The server exposes `GET /health`, `GET /meta`, and `POST /query` with
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
