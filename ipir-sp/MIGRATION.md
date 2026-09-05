# Migrating YPIR Packing Code To ipir-sp

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

Use `IPIRClient::decode_response_simplepir` for plaintext bytes or
`IPIRClient::decode_response_simplepir_raw` for plaintext coefficients.

## Validation Checklist

After moving code to the `ipir-sp` API, run:

```bash
cargo test -p ipir-sp
cargo test -p inspiring
```

For performance checks, run:

```bash
cargo bench -p ipir-sp --bench end_to_end
```

Use `IPIR_SP_BENCH_FULL=1` only on a host with enough memory for the full
`d = 2048` preprocessing fixture.
