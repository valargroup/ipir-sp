# Changelog

## Unreleased

- Guard the mask derivations without changing them. `inspiring` exposes the
  fixed `K_g`/`K_h` mask coefficients (`reference_mask_coeffs`), and
  `ipir_sp::server::verify_query_masks_distinct_from_key_masks` rejects a
  setup seed whose query masks coincide with a key mask directly, negated, or
  under `X -> X^-1`. The nullifier server and the demo server run it at
  startup, offline precomputation asserts it, and a test pins the reference
  seeds and the deployed setup seed. The CRS, preprocessing, published `c1`,
  and wire format are unchanged; domain-separated mask labels wait for the
  next profile ID. The `ipir-sp` README example no longer uses the `K_g`
  reference seed as its setup seed.
- Add experimental dithered native query transport
  (`NativeProfile::with_dithered_query_bits`, 43..=49 bits). The client rounds
  each query coefficient up with probability equal to its dropped fraction,
  so the certificate budgets query rounding as a Hoeffding variance instead
  of a worst-case sum. Precision and mode are bound into the setup ID. The
  default 49-bit nearest-rounding profile, its setup IDs and request bytes are
  unchanged.
- `native_noise` exports `query_l2_squared`, `query_rounding` and accepts
  `--query-bits`. Dithered reports use distinct
  `native-noise[-two-mask][-rounded]-dithered-v1` formats, so older checkers
  reject them; nearest reports keep their formats. `certify_native.py` accepts
  dithered reports only under those formats and adds a counterfactual
  `query_screen`.
- Freeze the default (sigma 6.4) discrete-Gaussian CDF table in
  `inspiring::gaussian` with a SHA-256 test, instead of rebuilding it from the
  host's `f64::exp` at every start. Client secrets, query errors and packing-key
  errors no longer depend on the platform math library, and a broken `exp`
  can no longer silently shrink the error term. The frozen values equal the
  previous runtime table on macOS ARM64 and Linux x86_64 (and the existing
  native table), so existing seeds decode unchanged. Non-default sigmas still
  build their table at runtime.

## 0.1.0-rc.6 — 2026-09-25

- Add the experimental native two-mask output mode (#24). It removes the final
  `K_h` key switch, halving native packing-key upload (55,296 to 27,648 bytes
  at d=2048, q=2^54, ell=2). Clients decode directly under both public masks.
- Add rounded, bit-packed public-mask publication (`RNP3`) for both native modes
  (#24, #25): 27..=32 bits for two-mask, 28..=32 bits for one-mask, or 54-bit
  lossless packing. Precision is bound into the setup ID.
- Add prepared native decoding, correlated-error exporters for rounded masks,
  and the `certify_native.py` rounded-mask certificate checks.
- `reinspiring` is now 0.1.2; `inspiring` and `simplepir-kernel` are unchanged.
- Existing production profiles and the default InspiRING backend are unchanged.
  Correctness certificates cover only the recorded fixtures; runtime snapshot
  certification remains a production prerequisite.

## 0.1.0-rc.5 — 2026-09-25

- Publish the distributed-serving APIs needed by wallet-pir: bounded prepared
  packing codecs, immutable mapped matrices, native query-mask access, and
  exact power-of-two CPU/CUDA matrix-vector evaluation.
- Reject empty matrix dimensions through the new fallible evaluation API.
- Supporting crate versions: `inspiring` 0.1.0-rc.2, `simplepir-kernel`
  0.1.0-rc.3, and `reinspiring` 0.1.1. Publish those before `ipir-sp` rc.5
  if publishing to crates.io; the Git release tag contains all four crates.
- Mapped artifacts require authenticated, immutable files owned by the trusted
  coordinator. Native experimental security gates remain unchanged.

## 0.1.0-rc.4 — 2026-09-25

Fourth release candidate for `ipir-sp`, adding the experimental ReinspiRING
implementation from PR #17. Existing `inspiring` rc.1 and `simplepir-kernel`
rc.2 dependency versions are unchanged.

- Add the `reinspiring` crate with an exact odd-modulus packing adapter and an
  experimental native power-of-two implementation, portable SIMD dispatch,
  bounded preprocessing concurrency, and request-local packing preparation.
- Add the opt-in `native-reinspiring` IPIR integration. Existing protocol
  profiles and the default InspiRING backend are unchanged. Native security
  and correlated-error certification gates are documented in
  `reinspiring/SECURITY.md`; merging this code does not approve a production
  cryptographic profile.
- Raise the `ipir-sp` minimum Rust version to 1.89 because its packing adapter
  depends on `reinspiring`, which uses stable AVX-512 intrinsics.
- For the next crates.io release, publish `reinspiring` before `ipir-sp`;
  `reinspiring` depends on the existing `inspiring` 0.1.0-rc.1 release.

## 0.1.0-rc.3 — 2026-09-24

Third release candidate for `ipir-sp`. It uses `simplepir-kernel`
`0.1.0-rc.2`; the `inspiring` dependency remains at `0.1.0-rc.1`.

### Added

- An optional CUDA backend for the first-dimension `u16` matrix-vector
  evaluation, selected explicitly at runtime. CPU evaluation remains the
  default, and explicit CUDA selection fails rather than silently falling back.
- Fallible backend preparation and query evaluation APIs, server backend/device
  flags, hardware-gated correctness tests, benchmarks, and validation evidence.

### Changed

- Device database and scratch buffers are retained and reused by each CUDA
  backend instance, with requests serialized per instance.

## 0.1.0-rc.2 — 2026-09-23

Second release candidate for `ipir-sp`. The `inspiring` and
`simplepir-kernel` dependencies remain at `0.1.0-rc.1`.

### Added

- Pinned `P16Q48` and `P16Q49` profiles for 16-bit plaintexts with at least
  48 or 49 query transport bits. Both reduce query rounding noise relative to
  `P16Q46` without changing the RLWE or response parameters.
- Parameter and production-flow coverage for the new profile IDs, query widths,
  packed query lengths, and decryption margin.

The historical correctness certificates cover only the evaluated 46-bit
schedules. New snapshots still need snapshot-specific correctness evidence.

## 0.1.0-rc.1 — 2026-09-23

First release candidate for the `inspiring`, `simplepir-kernel`, and `ipir-sp`
crates. The `nullifier-pir` application remains in the repository and is not
part of this crates.io release.

### Added

- Pinned production IPIR profiles, including `P16Q46` for 16-bit plaintexts.
  The P14 profile remains the default.
- Fresh Gaussian client secrets and query errors, with versioned guidance for
  decoding responses generated by older clients.
- A separate experimental key-reuse path, disabled by default and excluded
  from the production HTTP flow.
- Faster first-dimension kernels and packing preprocessing, with portable
  single-CRT NTT support through the Valargroup Spiral fork.

### Changed

- Corrected gadget decomposition so key switching retains its top carry.
- Restricted the production client to reviewed parameter profiles and made
  public query setup opaque and derived from a seed.
- Replaced the misleading decryption-margin diagnostic with a rounding
  residual and a test diagnostic that measures error against known plaintext.
- Reduced query and response transport sizes; the snapshot-constant `c1` row
  is published once at full precision.

### Release-candidate limits

- Query privacy assumes an honestly fixed public setup, private OS entropy,
  fresh client secrets, and the key-dependent RLWE assumption documented in
  [the security analysis](ipir-sp/SECURITY_ANALYSIS.md).
- The historical P16 correctness certificates predate the exact top-digit
  decomposition. They do not establish a rare decoding-failure bound for an
  arbitrary production snapshot. Use snapshot-specific validation before
  promoting this RC to a stable release.
