# ipir-sp

`ipir-sp` is the IPIR-SP integration crate for this workspace. It keeps YPIR's
SimplePIR database/query arithmetic and replaces the old CDKS ring-packing path
with `inspiring::pack`, the Rust implementation of `InspiRING.Pack`.

The implementation targets the IPIR-SP parameter set corresponding to Table 5
row 2 of ePrint 2024/270, using a single CRT modulus on the RLWE side. The
packing primitive and its invariants come from the sibling `inspiring` crate,
which implements Algorithm 1 from ePrint 2025/1352 and documents the math in
`../inspiring/SPEC.md`.

## Workspace Role

This crate is intentionally a glue layer:

- `params` maps YPIR SimplePIR scenario inputs to `inspiring::RlweParams` plus
  YPIR-specific transport and database dimensions.
- `client` generates the two InspiRING key-switching matrices, `K_g` and `K_h`,
  replacing YPIR's `log d` CDKS expansion matrices.
- `server` stores the SimplePIR database, computes YPIR's `hint_0`, extracts CRS
  blocks, builds `PackPreprocessed`, and runs online packing.
- `modulus_switch` serializes single-CRT packed RLWE responses into YPIR-style
  transport bytes.
- `serialize` provides a stable wire helper for uploaded key material.

`spiral-rs` is resolved once at the workspace root through Valar's
`valar-spiral-rs` fork. `ipir-sp` depends on `inspiring` by path and shares that
same resolved backend.

## YPIR-Shaped IPIR API

The high-level API uses `IPIR*` names while following the shape of YPIR's
client/server flow:

- `IPIRClient::from_db_sz` derives the same SimplePIR scenario shape as YPIR.
- `IPIRClient::generate_setup_simplepir` creates IPIR-SP setup material:
  offline query polynomials plus one per-query `(K_g, K_h)` key-switching pair.
- `IPIRClient::generate_query_simplepir` returns an `IPIRSimpleQuery`; call
  `query.to_packed_bytes(rlwe.q)` for the compact `/query` body, or
  `query.to_bytes()` for the legacy raw body.
- `YServer::perform_full_online_computation_simplepir` parses those query bytes
  and returns serialized response bytes.
- `IPIRClient::decode_response_simplepir` decodes the response with the returned
  client seed.

Unlike YPIR's CDKS path, the IPIR-SP `/query` body is only the online
first-dimension query. Key material is handled during setup/precomputation, not
embedded as `pack_pub_params` bytes in every online request.

## Basic Flow

```rust
use ipir_sp::client::IPIRClient;
use ipir_sp::server::{build_pack_preprocessed_blocks, YServer};
use ipir_sp::params_for_simplepir;

let (rlwe, ypir) = params_for_simplepir(1 << 14, 16_384 * 8)?;
let db = vec![0u16; ypir.db_rows * ypir.db_cols];
let server = YServer::new(ypir.clone(), db.into_iter(), false, true);
let client = IPIRClient::new(&rlwe, &ypir);

let setup = client.generate_setup_simplepir();
let offline = server.perform_offline_precomputation_simplepir(
    &rlwe,
    &setup.offline_query_polys,
);
let (query, client_seed) = client.generate_query_simplepir(&setup, 0);
let preprocessed = build_pack_preprocessed_blocks(
    &rlwe,
    &offline.crs_blocks,
    &setup.key_pair,
)?;

let response = server.perform_full_online_computation_simplepir(
    &rlwe,
    &query.to_bytes(),
    &preprocessed,
)?;
let _item = client.decode_response_simplepir(client_seed, &response);
# Ok::<(), inspiring::InspiringError>(())
```

## HTTP Shape

Feature-gated demo binaries mirror YPIR's raw `POST /query` transport:

```bash
cargo run -p ipir-sp --features http_server --bin server -- 16384 131072
cargo run -p ipir-sp --features http_client --bin client -- 0 16384 131072
```

Use the same `--setup-seed` on both commands so the client query matches the
server's precomputed setup.

## Tests And Benchmarks

Run the crate tests with:

```bash
cargo test -p ipir-sp
```

The integration tests cover the offline/online flow, exact row recovery for
small deterministic fixtures, single-CRT response switching, and the linear
`d - 1` key-switch count per InspiRING pack.

Criterion benchmarks live in `benches/end_to_end.rs`:

```bash
cargo bench -p ipir-sp --bench end_to_end
```

The default benchmark uses a smaller development profile. Set
`IPIR_SP_BENCH_FULL=1` to attempt the full `params_for_simplepir(32768, 131072)`
profile. See `../bench-results/2026-05-10-ipir-ypir/REPORT.md` for the latest
local run notes and the paper comparison targets.

Latest full nullifier-snapshot comparison on `ipir-avx512-32gb`:

| Metric | IPIR+SP latest | YPIR+SP last | Difference |
|---|---:|---:|---:|
| Full query | 695.698 ms | 824.032 ms | IPIR -128.334 ms |
| Server total | 580.595 ms | 549.544 ms | IPIR +31.051 ms |
| Matrix-vector | 524.467 ms | 491.667 ms | IPIR +32.800 ms |
| Packing | 40.166 ms | 54.667 ms | IPIR -14.501 ms |
| Client query generation | 82.196 ms | 266.426 ms | IPIR -184.230 ms |
| Client decode | 27.170 ms | 4.119 ms | IPIR +23.051 ms |
| Upload | 3,768,320 bytes | 4,734,976 bytes | IPIR -966,656 bytes |
| Download | 12,288 bytes | 12,288 bytes | same |

## References

- IPIR-SP: ePrint 2024/270, `https://eprint.iacr.org/2024/270`
- InspiRING / InsPIRe: ePrint 2025/1352, `https://eprint.iacr.org/2025/1352`
- Local InspiRING specification: `../inspiring/SPEC.md`
