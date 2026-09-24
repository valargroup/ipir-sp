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
public-mask key-switch trace, compact signed matrix storage, scalar/AVX2 dot
products, and an exact three-prime NTT/CRT remainder. It does not require an NTT
at the power-of-two ciphertext modulus. There is no schoolbook fallback in the
native online path.

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
