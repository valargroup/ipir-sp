# Migrating YPIR Packing Code To ipir-sp

## Authenticated responses (snapshot manifests)

Decoding now requires verified public parameters. Nothing on the PIR wire
changes: `POST /query`, the response body, `GET /public-params`, the existing
`GET /meta` fields, seeds, secrets, keys and profiles are byte-identical, and
old clients keep working against new servers. The new artefacts are additive.

API changes:

- `decode_response_simplepir` and `decode_response_simplepir_raw` take
  `&VerifiedPublicParams` instead of raw `c1` rows and return
  `Result<_, ClientError>`. They no longer panic on server-supplied lengths.
- `decode_response_simplepir_verified(seed, &verified, response, row)` also
  checks the decoded row against its signed digest and returns
  `ClientError::TamperDetected` on mismatch. Use this one.
- `modulus_switch::recover_published_c1` returns a `Result` and rejects
  coefficients outside `[0, q)`.
- The previous behaviour is `decode_response_simplepir_unverified` /
  `decode_response_simplepir_raw_unverified`, taking raw `c1` rows. Under a
  malicious server their output is key-equivalent (see
  [`SECURITY_PROFILES.md`](SECURITY_PROFILES.md#authenticating-responses)).
  They remain for one release so integrators can migrate.

Adoption order:

1. **Coordinator.** For every served snapshot, publish `manifest.json` and
   `row-digests.bin` (`nullifier-pir manifest`, or produced by `serve` at
   startup) and sign the exact `manifest.json` bytes with the coordinator
   Ed25519 key into `manifest.sig` next to them. Servers then serve
   `GET /manifest`, `GET /row-digests`, and `manifest_sha256` in `/meta`.
2. **Library release.** Ship this crate version. Integrators that are not
   ready may call the `_unverified` decoders for one release.
3. **Wallet.** Pin the coordinator public key in the wallet (never fetch it
   from the PIR server); fetch `/meta`, `/public-params`, `/manifest` and
   `/row-digests`; build `VerifiedPublicParams` before the first query and send
   nothing if it fails; decode with `decode_response_simplepir_verified`; and
   adopt response-independent polling, so the request pattern never depends on
   the decoded answer and no irreversible action follows an unverified one.

No wire, key, seed or profile change occurs at any step, so the steps can roll
out independently. A wallet that pins the key before step 1 has reached every
server will refuse to query those servers rather than fall back.

## Decryption diagnostics

`decode_response_simplepir_with_margin` and the experimental
`decode_with_margin` are renamed to `with_rounding_residual` variants. Their
returned distance is to the nearest plaintext encoding and cannot establish
correct decoding or noise headroom. Tests and benchmarks with a known plaintext
should use `decode_response_simplepir_with_expected_phase_error` (or the batch
wrapper) and compare the decoded coefficients with the expected row.

## Production parameter API

Construct `ProductionSimplePirParams::new(num_items, item_size_bits, profile)`
and pass a reference to `IPIRClient::new`. Use its `rlwe()` and `ypir()` accessors
for server setup. The old pair-based client constructor is replaced by
`IPIRClient::new_experimental`, available only with `experimental-params` and
returning a validation error for inconsistent pairs. Small test fixtures and
benchmarks must opt into that feature. P14, P16Q46, P16Q48, and P16Q49 are
pinned profiles;
this API boundary does not establish a 128-bit security claim for the single-CRT
construction.

## Gaussian client secrets

Fresh-query generation and seed-based decoding now sample centred
discrete-Gaussian secrets with standard deviation
`rlwe.sigma_chi` (6.4 at the production profile), using the existing pinned
backend sampler. Previously these paths sampled uniform ternary coefficients.
`ClientSecret::sample_ternary` remains a low-level research helper; it is not
used by the high-level query or decode paths.

`IPIRSeed` is an unversioned 32-byte seed. Its interpretation changes with this
sampler: **an old seed cannot reconstruct its old secret through the new default
decoder**. Finish outstanding requests with the old client or abandon them and
issue fresh requests after upgrading. Keep the old decoder for any deliberately
retained old responses; there is no automatic detection or migration.

Server query/key/response encodings and public preprocessing do not depend on
the secret distribution. New clients can use the existing server and public
setup, provided the generating client and its decoder use the same sampler and
parameters. No server wire-format change or database rebuild is required.

This fixes a distribution mismatch with the cited YPIR setting. It does not
replace analysis of the complete InspiRING transcript or certify a security
level. Existing benchmark records using ternary secrets do not measure the
new sampler.

This note maps the YPIR CDKS packing surface to the corresponding `ipir-sp`
entry points. The SimplePIR matrix layer remains the same conceptually; only the
LWE-to-RLWE packing boundary changes.

## Main Conceptual Changes

YPIR's original packing path uploads `log d` expansion matrices and performs a
CDKS-style recursive packing. For each fresh query/setup, `ipir-sp` uploads
exactly two InspiRING key-switching matrices total, `K_g` and `K_h`, shares them
across preprocessing blocks, then calls `inspiring::pack` once per RLWE output
block.

The RLWE side is single-CRT throughout. Response transport still uses YPIR-style
reduced moduli, but `modulus_switch` performs row-wise switching from one
InspiRING modulus rather than from two CRT limbs.

## API Mapping

`params_for_scenario_simplepir`

Use `ipir_sp::params_for_simplepir(num_items, item_size_bits)`. It returns both
the `inspiring::RlweParams` used by the packing layer and the
`YpirSchemeParams` values retained for database shape and transport.
For a client facade similar to YPIR's `YPIRClient`, use
`ipir_sp::client::IPIRClient` or the crate-level `ipir_sp::IPIRClient` re-export.

`raw_generate_expansion_params`

Use `ipir_sp::client::generate_ks_pair` for the single per-query `(K_g, K_h)`
pair shared across all preprocessing blocks. The uploaded key material is serialized with
`ipir_sp::serialize::serialize_ks_pair` and parsed with
`ipir_sp::serialize::deserialize_ks_pair`.

For the high-level path, call `IPIRClient::generate_setup_simplepir` or
`IPIRClient::generate_setup_simplepir_from_seed`. The returned
`IPIRSimpleSetup` contains the offline query polynomials and key-switching pair
needed by the server precompute step.

`pack_pub_params`

There is no separate public-parameter struct in `ipir-sp`. The CRS data is
derived from YPIR's `hint_0` and represented as `ipir_sp::server::CrsBlock`
values.

`generate_fake_pack_pub_params`

Use deterministic `hint_0` fixtures and `ipir_sp::server::offline_precompute_from_hint`
in tests. For a real server flow, use `YServer::perform_offline_precomputation_simplepir`.

`prep_pack_many_lwes`

Use `ipir_sp::server::offline_precompute_from_hint` to split `hint_0` into
CRS blocks, then `ipir_sp::server::build_pack_preprocessed_blocks` to call
`inspiring::PackPreprocessed::build` for each block.

`precompute_pack`

Use `ipir_sp::server::build_pack_preprocessed_blocks` if CRS blocks already
exist, or `ipir_sp::server::build_pack_preprocessed_from_hint` to extract CRS
blocks and build `PackPreprocessed` caches in one step.

`pack_many_lwes`

Use `ipir_sp::server::pack_intermediate_blocks`. It constructs the online
`LweBatch` values and invokes `inspiring::pack` once for each RLWE output block.

`pack_lwes_inner_non_recursive`

There is no `ipir-sp` equivalent. InspiRING's linear cascade is implemented in
the sibling `inspiring` crate and is exercised through `inspiring::pack`.

`perform_offline_precomputation_simplepir`

Use `YServer::perform_offline_precomputation_simplepir` to compute `hint_0` and
extract CRS blocks. Then pass the blocks and generated key pairs to
`build_pack_preprocessed_blocks`.

`perform_online_computation_simplepir`

Use `YServer::perform_online_computation_simplepir`. It runs the SimplePIR
matrix product, packs each intermediate block with InspiRING, and returns
serialized response bytes.

For YPIR-style raw request bytes, use
`YServer::perform_full_online_computation_simplepir`. Its request body is
`IPIRSimpleQuery::to_bytes()`: little-endian `u64` first-dimension query values.
This intentionally differs from YPIR's `first_dim || pack_pub_params` body
because IPIR-SP handles `(K_g, K_h)` key material during setup/precomputation
rather than uploading CDKS expansion parameters with every online request.

`modulus_switch` helpers for two CRT limbs

Use `ipir_sp::modulus_switch::switch_rlwe_ciphertext` or
`ipir_sp::modulus_switch::serialize_rlwe_response` for server responses. Tests
and local decoders can use `recover_rlwe_rows`.

`bits::{write_bits, read_bits}`

The helpers remain available as `ipir_sp::bits::{write_bits, read_bits}` and
are used by the single-CRT response serializer.

## Decode Note

Do not apply YPIR's extra `poly_len` multiplier to packed `b` values when
decoding `ipir-sp` responses. InspiRING absorbs the relevant `d^-1` scaling
inside its transform, so applying the old multiplier would double-scale the
message.

Use `IPIRClient::decode_response_simplepir_verified` for authenticated
plaintext bytes, or `decode_response_simplepir` / `decode_response_simplepir_raw`
for unauthenticated bytes or coefficients decoded against verified `c1`.

## Validation Checklist

After moving code to the `ipir-sp` API, run:

```bash
cargo test -p ipir-sp
cargo test -p inspiring
```

For performance checks, run:

```bash
cargo bench -p ipir-sp --bench end_to_end --features experimental-params
```

Use `IPIR_SP_BENCH_FULL=1` only on a host with enough memory for the full
`d = 2048` preprocessing fixture.
