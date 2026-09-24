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
