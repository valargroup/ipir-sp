# `spiral-rs` primitive inventory

Phase 3 audit of Valar's [`spiral-rs`](https://github.com/valargroup/spiral-rs)
fork at the **pinned revision** `6f5b66c6a5a639827c6486c59d31c7ec2d4399a8`
(`valar/avoid-avx512`). The fork's package is named `valar-spiral-rs`; the
Cargo dependency is aliased as `spiral-rs` so Rust imports remain
`spiral_rs::...`.

This document maps every primitive `inspiring` needs to a concrete spiral-rs
symbol or — when no suitable symbol exists — a wrapper we will add inside
`inspiring`. The Rust crate ships **no** algorithmic logic that is not either
(a) a direct call into spiral-rs, or (b) defined in a wrapper listed in this
document. New wrappers must be added here first, then implemented.

> Source of truth for paper notation: [`../SPEC.md`](../SPEC.md).
> Source of truth for the algorithm at byte-equality: the Python oracle at
> [`../tools/python-oracle/`](../tools/python-oracle/).

---

## 1. Toolchain constraints inherited from spiral-rs

spiral-rs at this revision relaxes the old AVX-512-only build constraints. The
`inspiring` crate inherits these constraints:

| Constraint | Source | Mitigation |
|---|---|---|
| Stable Rust is sufficient; the old `#![feature(stdarch_x86_avx512)]` gate is gone. | `spiral-rs/src/lib.rs:1` | Workspace [`rust-toolchain.toml`](../../rust-toolchain.toml) pins stable `1.89.0`. |
| AVX-512 is no longer a correctness requirement for the NTT path. | `spiral-rs/src/ntt/` | `inspiring/.cargo/config.toml` no longer forces `target-cpu=skylake-avx512`; CI builds without an AVX-512 preflight. |
| The scalar `multiply` fallback is correct for `crt_count == 1`. `arith::multiply_add_modular` now adds the accumulator `x` after `a*b mod q`. | `spiral-rs/src/arith.rs:28-33`, plus upstream test `multiply_add_modular_single_crt_includes_accumulator` | `inspiring` removed its `compile_error!` AVX-512 gate. The local regression test `spiral_matrix_multiply_accumulates_along_inner_dim` remains as a guard against future drift. |
| Memory alignment of polynomial buffers is 64 bytes (`AlignedMemory64`). | `spiral-rs/src/aligned_memory.rs:8` | We always allocate `PolyMatrix*` via spiral-rs constructors (`PolyMatrixRaw::zero`, etc.), never via `Vec<u64>`. |

The README, `src/lib.rs`, and `inspiring/.cargo/config.toml` document these
constraints explicitly. The old AVX-512 gate was removed after repinning to
the fork because the single-CRT accumulator bug is fixed upstream.

---

## 2. The mapping table

For each paper / SPEC.md symbol, we record:

- **Where in spiral-rs** the corresponding primitive lives (or `wrapper` if we add it).
- **What it costs us** to use it (transparent, thin wrapper, or non-trivial wrapper).

| SPEC.md / paper symbol | Notion | spiral-rs symbol | Status |
|---|---|---|---|
| `R = Z[X]/(X^d + 1)` | cyclotomic ring | `Params { poly_len: usize, .. }` with `poly_len = d` | direct |
| `R_q` | ring mod `q` | `Params { modulus: u64, moduli: [u64; 4], crt_count: usize, .. }` | direct (single-modulus uses `crt_count = 1`; double-CRT uses `crt_count = 2`) |
| `q` | RLWE modulus | `params.modulus` | direct |
| `χ ~ DG(σ_χ)` | discrete Gaussian noise | `discrete_gaussian::DiscreteGaussian::init(noise_width)` | direct (`noise_width = σ_χ · √(2π)`; spiral-rs uses the centred Gaussian convention) |
| Sample noise into `R_q` | | `PolyMatrixRaw::noise(params, r, c, &dg, &mut rng)` (constant-time) and `::fast_noise` (faster, non-CT) | direct; we use the constant-time one in setup, fast in tests |
| Polynomial matrices in coefficient form | `PolyMatrix(...)` | `poly::PolyMatrixRaw<'a>` | direct |
| Polynomial matrices in NTT form | | `poly::PolyMatrixNTT<'a>` | direct |
| Forward NTT `R_q → ẑ-domain` | | `poly::to_ntt_alloc(&PolyMatrixRaw)` and in-place `poly::to_ntt(&mut PolyMatrixNTT, &PolyMatrixRaw)` | direct |
| Inverse NTT | | `poly::from_ntt_alloc(&PolyMatrixNTT)` | direct |
| Polynomial add | | `poly::add(&mut res, a, b)` plus `Add` impls | direct |
| Polynomial scalar / matrix multiply (NTT-form) | | `poly::multiply(&mut res, a, b)` plus `Mul` impl | direct |
| Pointwise polynomial multiply (NTT) | | `poly::multiply_poly` and `poly::multiply_add_poly` | direct |
| Negate (`-p`) | | `Neg` impl on `&PolyMatrixRaw`/`&PolyMatrixNTT` | direct |
| Stack two matrices vertically (`[a; b]`) | | `poly::stack`, `poly::stack_ntt` | direct |
| **Galois automorphism `τ_t : p(X) ↦ p(X^t)`** (raw form) | Lemma 1 | `poly::automorph(&mut res, a, t)` and `poly::automorph_alloc(a, t)` | direct |
| **Galois automorphism `τ_t` (NTT form)** | | *not exposed* | **wrapper required**: `automorph::tau_ntt(&PolyMatrixNTT, t) -> PolyMatrixNTT` (round-trips through raw form for now; a faster NTT-permutation implementation is a future optimisation, gated by Phase 11). |
| **`τ_g` for `g = 5`** | Galois `Z_{d/2}` factor | `automorph_alloc(a, 5)` | direct |
| **`τ_h` for `h = 2d − 1`** | Galois `Z_2` factor | `automorph_alloc(a, 2 * d - 1)` | direct (spiral-rs is generic in `t`; `h` is just a different `t`) |
| `τ_g^j(p)` | iterated automorphism | none | **wrapper required**: `automorph::tau_g_pow(j, &p)`. Internally compose `τ_g` `j` times — at small `d` the cost is negligible; at `d = 2048` we cache the `j ↦ pow_mod(5, j, 2d)` exponent table and call `automorph_alloc(a, exponent)` once. |
| `g_z`, `g_z^{-1}` (gadget vector / decomposition) | base-`z` digit decomposition | `gadget::build_gadget(params, rows, cols)` and `gadget::gadget_invert(out, inp)` / `gadget::gadget_invert_alloc(mx, &inp)` | **constraint to document**: spiral-rs derives `bits_per ≈ ⌊log₂(q) / ℓ⌋ + 1` from the `(rows, cols)` shape via `gadget::get_bits_per`, *not* from a user-supplied `z`. We must ensure `z = 2^bits_per` matches the InspiRING `(z, ℓ)` choice. Verified against paper Table 5: param set 1 `(log q = 28, ℓ = 8) ⇒ bits_per = ⌊28/8⌋ + 1 = 4 ✓`; param set 2 `(log q = 56, ℓ = 3) ⇒ bits_per = ⌊56/3⌋ + 1 = 19 ✓`. Codified as an `assert!` in `RlweParams::new`. |
| `KS.Setup(s' → s)` | RLWE-to-RLWE key-switch matrix | *not directly exposed* — components are: `client::Client::encrypt_matrix_reg`, `gadget::build_gadget`, `poly::scalar_multiply` | **wrapper required**: `key_switching::ks_setup(s_from: &PolyMatrixNTT, s_to: &PolyMatrixNTT, params, dg, rng) -> KeySwitchingMatrix`. Implementation: build `g = build_gadget(params, 1, ℓ)`, scale `s_from * g` (NTT-form scalar multiply), encrypt under `s_to` using a hand-rolled regev encryption (we cannot reuse `Client::encrypt_matrix_reg` because it owns the secret key as `Client` state; we replicate its `get_regev_sample` body inside our wrapper, taking the secret as a `PolyMatrixNTT` parameter). |
| `KS.Switch(K, c)` | apply a KS matrix to a ciphertext | not exposed; the equivalent is hidden inside `server::coefficient_expansion` | **wrapper required**: `key_switching::ks_switch(k: &KeySwitchingMatrix, c1, c2) -> (c1', c2')`. Reads gadget width from `k.params.gadget.ell` (parameters are bundled onto the matrix — see §3). Implementation pattern follows `server.rs:80-103`: gadget-invert `ct.c1` (raw), NTT-forward, multiply by the KS matrix, add `(0, ct.c2)`. |
| `IRCtx` (the `(â, b̃)` intermediate) | Stage 1 / Stage 2 | not in spiral-rs | **type defined here**: `intermediate::IRCtx { a_hat: Vec<PolyMatrixNTT>, b_tilde: PolyMatrixRaw }`. |
| `RlweCiphertext` (final pack output) | | spiral-rs uses bare `PolyMatrixNTT` of shape `(2, 1)` to mean an RLWE pair `(c1, c2)` | **type alias defined here**: `pack::RlweCiphertext = PolyMatrixNTT<'a>` with rows = 2, cols = 1, plus a thin newtype for type-safety. |
| `PackPreprocessed` (CRS-side cache) | offline state | not in spiral-rs | **type defined here**: `preprocess::PackPreprocessed`. |
| `RlweParams` (our public params) | | superset of `Params` | **type defined here**: `params::RlweParams { d, q, p, sigma_chi, z, ell, ... }` plus a `RlweParams::to_spiral_params(&self) -> spiral_rs::params::Params` conversion that fills in spiral-rs's PIR-specific fields (`t_conv`, `t_gsw`, etc.) with safe no-op defaults. |
| Discrete-Gaussian sampler | | `discrete_gaussian::DiscreteGaussian` | direct |
| ChaCha20 RNG | reproducible randomness | `rand_chacha::ChaCha20Rng` (spiral-rs depends on it) | direct (we re-export through our own dependency) |

---

## 3. Wrapper inventory (the things `inspiring` adds)

These wrappers will live inside the `inspiring` crate. Listed here so this
document is the *complete* picture of "what spiral-rs gives us vs. what we
build on top".

```text
src/automorph.rs
    pub fn tau_g_pow(j: usize, d: usize) -> usize
        // Returns 5^j mod 2d. Pure helper; the actual automorphism call is
        // poly::automorph_alloc(a, tau_g_pow(j, d)).

    pub fn tau_h_exponent(d: usize) -> usize
        // Returns 2d - 1. Trivial helper for h.

    pub fn tau_ntt(a: &PolyMatrixNTT, t: usize) -> PolyMatrixNTT
        // Round-trip through raw form. Sub-optimal but byte-correct.
        // Phase 11 hardening will replace this with an NTT-slot permutation.

src/key_switching.rs
    pub struct KeySwitchingMatrix<'a> {
        pub mat:    PolyMatrixNTT<'a>,   // shape [2 × ℓ]
        pub params: &'a RlweParams,      // params the matrix was built under
    }
        // The `params` field is bundled directly so `ks_switch`, `collapse_one`
        // and `collapse_half` do not need a parallel `&RlweParams` argument
        // *and* so a key matrix can never be paired with mismatched gadget
        // settings — both `params.spiral` (the inner allocator `mat` borrows
        // from) and `params.gadget.ell` (the gadget width `mat` was built
        // for) come from the same `&RlweParams` reference, by construction.

    pub fn ks_setup(params: &'a RlweParams,
                    s_from: &PolyMatrixNTT, s_to: &PolyMatrixNTT,
                    rng: &mut ChaCha20Rng) -> KeySwitchingMatrix<'a>
        // Builds an ℓ-column RLWE encryption of s_from · g_z under s_to.
        // Replicates the body of spiral-rs Client::get_regev_sample so we can
        // pass the secret as a parameter rather than holding it in Client.
        // Pulls σ_χ, ℓ, and the spiral-rs allocator from `params`, then stores
        // the same `&'a RlweParams` reference on the returned matrix.

    pub fn automorphic_image(k: &KeySwitchingMatrix<'a>, t: u64)
                             -> KeySwitchingMatrix<'a>
        // Forwards `k.params` to the image — local images of a KS matrix
        // share its parameter set by definition.

    pub fn ks_switch(k: &KeySwitchingMatrix<'a>,
                     c1: &PolyMatrixNTT<'a>, c2: &PolyMatrixNTT<'a>)
                     -> (PolyMatrixNTT<'a>, PolyMatrixNTT<'a>)
        // Implements the KS body of server::coefficient_expansion (lines
        // 80-103) abstracted out of the coefficient-expansion loop.
        // Reads gadget shape from `k.params.gadget.ell`; asserts
        // `k.mat.cols == k.params.gadget.ell` so a malformed key matrix
        // cannot silently miscompute. No separate `params` argument — the
        // matrix carries it.

    pub(crate) fn ks_call_count_inc()
        // #[cfg(test)] only. Increments a thread-local counter so
        // tests/inspiring_vs_cdks_recursion.rs can assert d-1 calls per pack.
```

No other wrappers are anticipated. Anything else we need is a direct call to a
spiral-rs symbol.

---

## 4. Symbols we will NOT use from spiral-rs

For clarity, recording the spiral-rs API surface that has *no* role in the
`inspiring` crate. If a future PR finds itself reaching for any of these,
reviewers should treat that as a strong signal that the change is drifting
into Spiral-PIR territory rather than InspiRING territory.

- `client::Client`, `client::PublicParameters`, `client::Query` — Spiral-PIR client / query orchestration.
- `server::*` — Spiral-PIR server, including `coefficient_expansion`, `regev_to_gsw`, `multiply_reg_by_database`. We pattern-match on `coefficient_expansion`'s body for our `ks_switch` implementation, but the function itself is *not* called.
- `key_value::*` — Spiral-PIR key-value sub-API.
- `params::Q2_VALUES`, `params::MIN_Q2_BITS` — RLWE-quotient `q2`, only meaningful for Spiral-PIR's modulus-switch step.
- `params::Params { t_conv, t_exp_left, t_exp_right, t_gsw, db_dim_1, db_dim_2, instances, db_item_size, version, .. }` — Spiral-PIR scheme fields. Filled with safe defaults in `RlweParams::to_spiral_params`.
- `arith::*`, `number_theory::*` — used transitively; we never depend on these directly.

---

## 5. Verification plan

This document is verified by:

1. `cargo check` on the Phase 4 skeleton: must succeed against the pinned
   spiral-rs revision. Drift in spiral-rs's API will surface here first.
2. Phase 5–8 implementation: every call site that uses spiral-rs must reduce
   to one of the symbols listed in §2 or a wrapper listed in §3. PR reviews
   enforce this against the table.
3. Phase 9 test 6 (`python_oracle_match.rs`): asserts byte-equality between
   the Rust and Python implementations at `d = 8`. Catches semantic drift in
   any of the wrappers — a wrapper that returns the right *shape* but the
   wrong values cannot survive this test.
4. Phase 9 test 10 (`inspiring_vs_cdks_recursion.rs`): asserts preprocessing
   evaluates exactly `d − 1` logical `KS.Switch` calls, while online `pack`
   evaluates zero key-switch products. A reviewer adding a spurious online
   `ks_switch` call (e.g. as part of a CDKS-style merge) breaks this test.
