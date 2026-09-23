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
use ipir_sp::server::YServer;
use ipir_sp::{ProductionSimplePirParams, SimplePirProfile};

let profile = ProductionSimplePirParams::new(1 << 14, 16_384 * 8, SimplePirProfile::P14)?;
let (rlwe, ypir) = (profile.rlwe(), profile.ypir());
let db = vec![0u16; ypir.db_rows * ypir.db_cols];
let server = YServer::new(ypir.clone(), db.into_iter(), false, true);
let client = IPIRClient::new(&profile);

let setup = client.generate_public_query_setup_simplepir_from_seed([7; 32]);
let offline = server.perform_offline_precomputation_simplepir(
    rlwe,
    &setup,
);
let (query, keys, seed) = client.generate_fresh_query_simplepir(&setup, 0);
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

## Public query setup

Both peers expand the offline query polynomials from the setup seed with
ChaCha20 and `sampling::uniform_u64_below`, a pinned rejection sampler that
reproduces the historical `rand` 0.8 `gen_range(0..q)` mapping. The mapping is
part of the wire format: a client in another language must reproduce it
exactly, and a `rand` upgrade cannot change it.
`generate_public_query_setup_simplepir_from_seed` returns an opaque
`PublicQuerySetup`; `generate_fresh_query_simplepir` accepts only that type,
so a client cannot encrypt against polynomials handed to it by a server.
Servers read `PublicQuerySetup::polys` for their offline precomputation.

## Client secret distribution

High-level query generation and decoding use centred discrete-Gaussian secrets
at standard deviation `sigma_chi` (6.4 in the production profile), matching
YPIR's Gaussian convention. The pinned sampler receives width
`sigma_chi * sqrt(2*pi)`. See [migration notes](MIGRATION.md) for the changed
interpretation of old client seeds.

## Versioned plaintext profiles

`ProductionSimplePirParams::new` pins the RLWE tuple and transport settings for
the selected profile; its read-only accessors keep the pair together. The
production `IPIRClient::new` accepts only this type. `IPIRClient::from_db_sz`
selects P14. Arbitrary client pairs require the `experimental-params` feature
and `IPIRClient::new_experimental`; those pairs have no production security claim.

`params_for_simplepir` remains the upstream-compatible 14-bit profile. Applications
that need full-width `u16` plaintexts opt in with
`params_for_simplepir_profile(..., SimplePirProfile::P16Q46)`. That profile keeps
the ring, ciphertext modulus, Gaussian sampler, gadget, and 20-bit response
transport unchanged, while using `p = 2^16` and at least 46 bits per transmitted
query coefficient. The extra query bit is intentional: fixed-schedule certificates
for dense 8,192-row databases exhausted the conservative proof budget at 45 bits
and achieved a weakest tested ideal-sampler bound of `2^-143` at 46 bits.

Bind `SimplePirProfile::id()` into application manifests, cached artifacts, and
client/server compatibility checks. Changing profiles requires re-encoding the
database and rebuilding preprocessing.

## Tests And Benchmarks

The opt-in `experimental-key-reuse` feature provides an in-process prototype
that amortizes evaluation keys across independent public query-matrix sets.
See [the experiment design and commands](KEY_REUSE_EXPERIMENT.md) and
[measured bandwidth and runtime results](../bench-results/2026-09-04-key-reuse/REPORT.md).
It is not enabled in the HTTP path and has not established production security.

Run the crate tests with:

```bash
cargo test -p ipir-sp
```

The integration tests cover the offline/online flow, exact row recovery for
small deterministic fixtures, single-CRT response switching, and the linear
`d - 1` key-switch count per InspiRING pack.

Criterion benchmarks live in `benches/end_to_end.rs`:

```bash
cargo bench -p ipir-sp --bench end_to_end --features experimental-params
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
