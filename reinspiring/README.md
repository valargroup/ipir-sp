# ReinspiRING packing

Implementation of Algorithms 1–2 and Appendices C/D.1/D.2 of
[ReinsPIRe, ePrint 2026/1934](https://eprint.iacr.org/2026/1934).

Two deliberately distinct interfaces are available:

- `preprocess_from_inspiring` / `pack`: an exact odd-modulus rewrite of the
  existing InspiRING backend, suitable for differential testing. Ciphertexts
  remain byte-identical at the same parameters, masks, key bodies and inputs.
- `native::{NativeParams, NativeSetup, NativeSecret, NativeKeys,
  NativePreprocessed, NativeCiphertext}`: a complete coefficient-domain,
  power-of-two packing implementation. The degree-2048 research configurations
  use q=2^54, signed base-2^19 decomposition, and two or three limbs. Two limbs
  round away 16 low bits; three limbs reconstruct exactly modulo q.

**The native profile is experimental, not approved for production.** Gaussian
and uniform-ternary secrets have separate profile identifiers. IPIR-SP's native
integration permits Gaussian secrets only and requires `native-reinspiring`.
It does not replace any existing production profile or the default backend.
See [SECURITY.md](SECURITY.md) for assumptions, bounds and release gates.

Experimental final-key transport compression is available through
`NativeProfile::with_kh_bits(t)` in IPIR-SP. It retains the existing gadget and
full-precision K_g. For the recorded full-size p16 benchmark snapshot, 46-bit
K_h meets the historical 2^-78 research target but fails the current 2^-128
acceptance target; 47-bit K_h meets that current target. These are snapshot-specific
results, not production approval. See the [measurement report](../bench-results/2026-09-25-reinspiring-kh-compression/README.md)
and [certificate argument](tools/security/NATIVE_CERTIFICATE.md).

An opt-in IPIR-SP native two-mask mode stops after the two `K_g` collapse
chains. It uploads only `K_g`, publishes both pre-final masks for each response
block, and decrypts the single response body under `s` and `τ_-1(s)`. Use
`NativeProfile::with_two_mask_output()`; its `RNQ3`/`RNR2`/`RNP2` wire formats
and `RNMAP002` prepared artifact are mode-specific. It is experimental and is
not a standard one-mask RLWE ciphertext. `native_noise --two-mask` exports its
snapshot-specific noise weights for `certify_native.py`; `native_e2e` selects
the mode with a final `kh_bits` argument of `0`.

The native path implements the ring FFT compiler, the integer-lift transform,
public-mask key-switch trace, compact signed matrix storage, scalar/AVX2/AVX-512
dot products, and an exact NTT/CRT remainder. Public leftover transforms are
cached offline; a checked public coefficient bound selects two auxiliary primes
when sufficient, retaining the generic three-prime path otherwise. It does not require an NTT at the power-of-two
ciphertext modulus. There is no schoolbook fallback in the
native online path. Rust 1.89 is required for stable AVX-512 intrinsics.

Packing coefficient storage is selected from the actual public coefficient
range. AVX-512/VBMI hosts use signed 27- or 28-bit storage when every coefficient fits
and the matrix geometry supports the four-row kernel; other matrices retain
signed 32- or 64-bit storage. Compression changes neither coefficients nor
cryptographic parameters. The kernel shares uploaded-key vector loads across eight rows, with a four-row
fallback when required by the matrix geometry. All CPU dispatch has exact portable fallbacks.

For a separate packing worker, call `prepare_keys` once per request, share the
immutable result across blocks, and call `prepare_pack` for each block. This
computes the matrix and leftover contributions before the database scan ends.
Call `PendingNativePack::finish` with that block's scan body when it arrives.
The dispatcher must bind setup, snapshot, request, and block identity across the
two machines; the low-level split API does not provide a network protocol or
request authentication. `NativeServer::respond` uses request-local prepared
keys and retains the existing response binding, but executes the stages
sequentially on its own host.

`NativePreprocessed::build_batch` and `NativeServer::build_with_concurrency`
accept an explicit maximum number of preprocessing blocks in flight. Each block
uses the current Rayon pool; larger batches trade peak scratch memory for setup
throughput. `NativeServer::build` retains sequential block construction. Input
mask storage owned by the caller is additional to scratch and retained packing
material. See the [packing measurements](../bench-results/2026-09-24-reinspiring-packing/README.md)
for the measured concurrency and memory tradeoff.

The integrated server uses an interleaved 16-column database layout on AVX-512
VNNI hosts. Signed radix-256 query digits and unsigned database bytes produce
exact dot products modulo q, with no loss of query precision. Each accumulator
window is limited to 65,536 rows, so even full-range u16 database entries cannot
overflow the signed 32-bit byte accumulators. Other CPUs retain exact word
kernels. The layout conversion is offline and retains the same database size.

```sh
cargo test -p reinspiring --release
cargo test -p reinspiring --release --test native_flow \
  native_paper_degree_roundtrip -- --ignored
cargo test -p ipir-sp --features native-reinspiring --release --test native_flow
RAYON_NUM_THREADS=1 cargo run --release -p ipir-sp --example packing_compare
BENCH_THREADS=1,2,4,8 RAYON_NUM_THREADS=8 cargo run --release -p ipir-sp \
  --features native-reinspiring --example native_e2e -- 28672 32768 14 2 30
```

The Python integer/schoolbook oracle runs as part of the Rust unit tests and
requires `python3`. The existing Python oracle package has additional tests.
Benchmarks use deterministic **test** seeds; production query generation uses
OS entropy. Neither benchmark seeds nor research constructors establish a
security level.

The scope is ring packing and its IPIR-SP integration, not the full ReinsPIRe,
ReinsPIRe+ or vReinsPIRe PIR constructions.

MIT OR Apache-2.0.

### Prepared client decoding

The native integration exposes `NativePublished::prepare(setup)` to cache public
mask transforms and `NativeRequest::prepare_decode(&prepared)` to compute fresh
request-local mask products. Call request preparation before sending the query;
include its cost in client generation. `decode_prepared` then validates response
bindings and decodes with those products. It also works without request
preparation, computing products on demand. Both one-mask and two-mask modes use
the same path. Cached public transforms belong to a snapshot; secret-dependent
products belong to one request and are zeroized on drop.

The offline `native_gadget_search` example and `tools/security/search_upload.py`
screen unequal gadgets and per-limb wire precisions. Their outputs are research
screens, not accepted runtime profiles or production certificates. See
[upload investigation](../bench-results/2026-09-25-upload-search/README.md).

For the experimental route with no additional snapshot download, select
`with_two_mask_output()?.with_published_mask_bits(29)?` on `NativeProfile`.
The recorded benchmark certifies this precision, but each application snapshot
requires its own certificate before use. At 29 bits, published masks are smaller
than the current single-mask u64 encoding, and key upload is halved. See
[validation and exact byte counts](../bench-results/2026-09-25-no-extra-download/README.md).

### Native review fixes (2026-09-25)

Prepared decoding now erases intermediate secret matrices and product vectors,
including error/unwind paths, and avoids the backend's unwiped thread-local
inverse-transform scratch. Native Gaussian secret/error sampling now uses a
frozen integer CDF identical to the recorded fixtures; setup and wire encodings
are unchanged. Certificates check the exact distribution and include its digest.
Future sampler changes require a new profile identity and new certificates.
The certificate CLI defaults to 128 failure bits; pass `--require-bits 78` only
for an explicitly intended historical research check. The saved 28-bit route
now fails the default command. Runtime snapshot admission and independent
native KDM approval remain separate production requirements.
