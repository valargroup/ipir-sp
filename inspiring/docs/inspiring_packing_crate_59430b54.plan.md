---
name: inspiring packing crate
overview: Build a production-ready Rust crate implementing only Algorithm 1 (InspiRING.Pack) from the InsPIRe paper, on top of spiral-rs. Splits into a deep-understanding phase first, then faithful production implementation with offline/online split, full tests, noise validation, benchmarks, and CI.
todos:
  - id: spec
    content: "Write SPEC.md: Galois group, Lemma 1 (with proof), Stage 1 derivation (App. B), Stage 3 telescoping (App. C), Theorem 2 noise, offline/online split, comparison with CDKS [18] (Section 3.1 + Section 7.4), symbol table"
    status: completed
  - id: oracle
    content: Build Python reference oracle in tools/python-oracle/ at d=8/16 with sympy, used as byte-equal correctness ground truth
    status: completed
  - id: spiral_audit
    content: Audit spiral-rs (pinned to rev 6929441) for needed primitives; document mapping in docs/spiral-rs-mapping.md; add wrappers for any missing automorphism
    status: completed
  - id: skeleton
    content: "Set up crate skeleton: Cargo.toml with spiral-rs pin, module layout (params/lwe/automorph/intermediate/collapse/key_switching/preprocess/pack/error), README"
    status: completed
  - id: stage1
    content: Implement Stage 1 (intermediate::transform) per Algorithm 1's TRANSFORM
    status: completed
  - id: stage2
    content: "Implement Stage 2 (intermediate::aggregate): Sum IRCtx . X^k aggregation"
    status: completed
  - id: stage3
    content: Implement Stage 3 (collapse::{one,half,collapse}) using K_g automorphic images and final K_h step
    status: pending
  - id: offline_online
    content: Wire up PackPreprocessed offline cache and online pack(b, pre) entry point per CRS-model split
    status: pending
  - id: tests
    content: "Implement test suite: Lemma 1, Transform, Aggregate, Collapse, full roundtrip, oracle match, noise (Theorem 2), offline/online equivalence, parameter validation"
    status: pending
  - id: benches
    content: Add criterion benchmarks reproducing Table 5 (both parameter sets); produce bench/REPORT.md comparing to paper numbers
    status: pending
  - id: hardening
    content: "Production hardening: rustdoc + missing_docs lint, clippy/fmt, cargo-fuzz target, constant-time review, GitHub Actions CI, SECURITY.md, paper attribution"
    status: pending
isProject: false
---

## Goal

A standalone Rust crate `inspiring` exposing one primitive: `pack(lwe_b, preprocessed) -> RlweCiphertext` that compresses `d` LWE ciphertexts (each LWE dim `d`) into a single RLWE ciphertext under the base secret, using two key-switching matrices (`K_g`, `K_h`) per Section 3.2 of the paper. Built on `spiral-rs` (pinned to `rev = 6929441`, matching the reference Google implementation).

## Locked-in scope

- Algorithm 1 only (`InspiRING.Pack`, full `d -> 1` packing). No `PartialPack`, no PIR layers.
- Rust + `spiral-rs` for the RLWE substrate (NTT, gadget decomposition, automorphisms, key switching).
- Production posture: library API, offline/online split, full unit and integration tests, statistical noise validation against Theorem 2, benchmarks reproducing paper Table 5, CI, rustdoc.

## Phase 1 - Deep understanding (`SPEC.md`, no code)

A self-contained `SPEC.md` with paper-notation to code-symbol mapping. Contents:

1. Cyclotomic ring and Galois group: `R = Z[X]/(X^d+1)`, group isomorphic to `Z_{d/2} x Z_2`, generators `g = 5` and `h = 2d-1` (paper Section 2 plus Lemma 3).
2. Lemma 1 (trace): why summing `tau_g^j(p) + tau_h . tau_g^j(p)` for `j` in `[0, d/2)` zeros out everything but the constant coefficient (scaled by `d`). Include proofs of Lemmas 3, 4, 5 from Appendix D.
3. Stage 1 derivation (Appendix B): how the trace operator turns the LWE-to-RLWE embedding into the MLWE-like intermediate; why `a_hat[j] = d^{-1} . tau_g^j(a_tilde)` and `a_hat[j+d/2] = d^{-1} . tau_h(tau_g^j(a_tilde))`.
4. Stage 2: why `Sum_k IRCtx(m_k) . X^k = IRCtx(Sum_k m_k . X^k)` is well-defined homomorphically.
5. Stage 3 (Appendix C): telescoping collapse; `tau_g^{k-1}(K_g)` switches `tau_g^k(s_tilde)` to `tau_g^{k-1}(s_tilde)`. Exactly `d/2 - 1` `CollapseOne` calls per half-plane plus a final `K_h` step.
6. Theorem 2 (noise): subgaussian bound `sigma_pack^2 <= ell . d^2 . z^2 . sigma_chi^2 / 4`; only key switchings add noise.
7. Offline/online split (Section 2.2): which quantities depend only on `(A, K_g, K_h)` (preprocessable) vs. on `b` (online). This drives the API.
8. Comparison with CDKS [18] (paper Section 3.1 + Section 7.4) - see expanded breakdown below. This is what justifies the existence of the crate; the spec must make crystal clear what InspiRING is replacing and why.
9. Symbol table mapping every paper symbol to a Rust type/field. Contract that code and tests must satisfy.

### CDKS comparison subsection (item 8 above)

This is the longest single section of `SPEC.md`. It is structured as: walk through CDKS, then point out exactly where InspiRING diverges, then quantify the wins.

Sub-sections:

a. CDKS recap (paper Section 3.1).
   - Embed each LWE `(a, b)` as RLWE `(a_tilde, b_tilde)` with `a_tilde = Sum_i a[i] . X^{-i}`, `b_tilde = b . X^0` so `b_tilde = -a_tilde . s_tilde + m_tilde mod q`. Note: this is the SAME embedding InspiRING uses (Equation 1) - so we keep this primitive verbatim.
   - The constant term of `m_tilde` is the LWE message `m`; the other `d-1` coefficients are arbitrary "junk" from the embedding.
   - CDKS packs by an incremental binary-tree merge of depth `lg(d)`. At each level, pairs of RLWE ciphertexts are combined: an automorphism is applied to one of them to flip the sign on the "junk" coefficients of the partner, the two are added (junk cancels), and a key-switching removes the extraneous secret-key term that the automorphism introduced.
   - Crucially, the automorphism used at level `k` is different from the one at level `k-1` (each level halves the active coefficient set). So each level needs its own `K_{g_k}` key-switching matrix. Total: `lg(d)` matrices.

b. Why InspiRING needs only 2 KS matrices.
   - Structural shift: InspiRING does not merge incrementally. Stage 1 transforms each input LWE upfront into a wider MLWE-like intermediate where the message lives as a clean constant polynomial `m_hat(X) = m`. This eliminates the "junk coefficients" problem entirely - there is no more zeroing-out to do during merging.
   - Stage 2 aggregation is then a plain `Sum X^k . IRCtx(m_k)` - no automorphisms involved.
   - Stage 3 collapse uses a linear cascade of key-switchings, but each step uses an automorphic IMAGE `tau_g^{k-1}(K_g)` of the SAME base matrix `K_g`. We compute these images locally with no extra key material. So we need exactly one base matrix `K_g` for the `tau_g`-cycle, plus one final `K_h` to fold the `tau_h(s_tilde)` share into `s_tilde`. Total: 2 matrices.
   - The cost we pay for this is that the intermediate ciphertext is much wider (`d+1` ring elements vs `2`). But in the CRS model the wide part depends only on the public random components and `K_g`, `K_h`, so it's all preprocessable.

c. Recursion structure side-by-side. Include a small mermaid diagram contrasting CDKS's binary tree (depth `lg d`, distinct KS matrix per level) against InspiRING's "fan-out then linear cascade" (Stage 1 transforms in parallel, Stage 2 sums in one pass, Stage 3 cascades `d-2` `CollapseOne` calls + 1 final).

d. Noise growth comparison (paper Theorem 2 + Section 7.4 last paragraph).
   - InspiRING analytic bound: `sigma_pack^2 <= ell . d^2 . z^2 . sigma_chi^2 / 4`.
   - CDKS does not have a tighter analogous bound, and at `d = 2048` the paper measures empirical `log2 ||e_pack||_inf = 38.5` bits for CDKS vs `33.4` for InspiRING - approx 5 bits less noise.
   - The spec records both bounds and explains the structural reason: CDKS accumulates noise across `lg(d)` levels of nested key-switchings, each level seeing the previous level's noise multiplied by gadget-decomposition factors; InspiRING's collapse adds noise from `d/2 - 1` independent key-switchings of comparable size, but no nested amplification.

e. Concrete cost comparison at the two paper-reported parameter sets (Table 5).
   - Param set 1 `(log d, log q, log p, ell, z) = (10, 28, 6, 8, 2^4)`: CDKS not benchmarked at this size in the paper; HintlessPIR is. Record HintlessPIR vs InspiRING here (key material 360 KB vs 60 KB; online time 141 ms vs 16 ms).
   - Param set 2 `(11, 56, 15, 3, 2^19)`: CDKS 462 KB key material, 56 ms online vs InspiRING 84 KB / 40 ms (~28% lower online time, 84% smaller key material). Note the trade-off: InspiRING's offline time is higher (~36 s vs ~11 s) due to the wider intermediate.

f. What we keep from CDKS.
   - The LWE-to-RLWE embedding `(a_tilde, b_tilde)` of Equation 1 - byte-identical.
   - `KS.Setup` and `KS.Switch` algorithms - same primitives, just used differently.
   - Gadget decomposition - same.

g. What we explicitly do NOT implement.
   - The CDKS binary-tree recursion. The crate has no `lg(d)` KS matrices and no level-indexed automorphism schedule. If a future caller wants to compare against CDKS empirically, they should pull in HintlessPIR or a separate CDKS implementation - we will not embed one for benchmarking.

h. Risk: confusing the two structures during implementation.
   - The off-by-one risk in Stage 3's nested loop is exactly the place where someone reading CDKS first might insert a CDKS-style level-indexed switch. The Python oracle (Phase 2) and the `inspiring_vs_cdks_recursion.rs` test (Phase 9) guard against this.

## Phase 2 - Reference oracle (`tools/python-oracle/`)

Tiny-parameter Python prototype using `sympy` (exact arithmetic over `Z_q`), no NTT, at `d = 8` and `d = 16`. Implements every algorithm verbatim from the paper pseudocode. Used as a byte-equal correctness oracle for the Rust impl under fixed RNG seeds, and as a noise-sample generator for Phase 9. Lives in `tools/`, not shipped.

## Phase 3 - `spiral-rs` primitive inventory (`docs/spiral-rs-mapping.md`)

Brief audit of what we need vs. what `spiral-rs` provides at the pinned revision. From the reference impl, the building blocks we need are: `PolyMatrixRaw` and `PolyMatrixNTT`, NTT round-trips, gadget matrix and decomposition, automorphism `tau_g` for arbitrary `g` in `Z*_{2d}` (must support `g = 5, 25, 125, ...` and `g . h mod 2d`), discrete-Gaussian sampler, and `KS.Setup` and `KS.Switch`. Output is a doc listing every spiral-rs symbol we depend on plus a stub for any wrapper we need to add.

## Phase 4 - Crate skeleton

Layout under `inspiring/`:
- `Cargo.toml`: deps spiral-rs (rev=6929441), rand_chacha, thiserror; dev-dep criterion
- `README.md`, `SPEC.md` (Phase 1), `docs/spiral-rs-mapping.md` (Phase 3)
- `src/lib.rs` (public API + crate docs)
- `src/params.rs` (`RlweParams`, `GadgetParams`, validators: `d` power of two, `q` odd, `d^{-1} mod q` precomputed)
- `src/lwe.rs` (`LweCiphertext` type, batch type, embedding into `R_q` per Eq. 1)
- `src/automorph.rs` (`tau_g`, `tau_h`, `tau_g^j` wrappers + cached automorph indices)
- `src/intermediate.rs` (`IRCtx` type, Stage 1 `transform`, Stage 2 `aggregate`)
- `src/collapse.rs` (`collapse_one`, `collapse_half`, `collapse`)
- `src/key_switching.rs` (`KS.Setup`, `KS.Switch`, automorphic images of `K_g`/`K_h`)
- `src/preprocess.rs` (`PackPreprocessed`: caches all CRS-model offline data)
- `src/pack.rs` (top-level `pack` with offline + online passes)
- `src/error.rs` (`InspiringError`)
- `tests/`, `benches/pack.rs`, `examples/roundtrip.rs`
- `tools/python-oracle/` (Phase 2)
- `.github/workflows/ci.yml`

## Phase 5 - Stage 1 (`intermediate::transform`)

Per Algorithm 1 `TRANSFORM`: build `a_tilde = Sum_i a[i] . X^{-i}`, set `b_tilde` = constant polynomial of `b`, then for `j` in `[0, d/2)` set `a_hat[j] = d^{-1} . tau_g^j(a_tilde)` and `a_hat[j+d/2] = d^{-1} . tau_h(tau_g^j(a_tilde))`. `a_hat` always lives in NTT form internally for downstream efficiency. The `b_tilde` slot is online-only; `a_hat` is fully preprocessable.

## Phase 6 - Stage 2 (`intermediate::aggregate`)

Compute `(a_agg, b_agg) = Sum_{k=0..d-1} IRCtx(m_k) . X^k` as component-wise additions of the `a_hat[j]` slots, with `X^k` as a coefficient shift in coefficient form (cheap there) or constant-monomial multiply in NTT form (cheap there). Pick the form that minimizes round-trips. `a_agg` is fully preprocessable; only assembly of `b_agg` from the `d` scalar `b_k` values is online.

## Phase 7 - Stage 3 (`collapse`)

Three layered subroutines exactly as in Algorithm 1's pseudocode plus Appendix C: `collapse_one` (one key-switch step), `collapse_half` (loop of `d/2 - 1` `collapse_one` calls applied to one half of `a_agg` using automorphic images of `K_g`, optionally pre-composed with `tau_h`), and `collapse` (run `collapse_half` twice, then a final `KS.Switch` with `K_h` to fold the `tau_h(s_tilde)` share into `s_tilde`). Invariant: the running random component depends only on `(A, K_g, K_h)`, so its NTT-form values are precomputed once during `PackPreprocessed::build()`.

## Phase 8 - `pack.rs` and offline/online split

`PackPreprocessed::build(crs, kg, kh)` does Phase 5 `a_hat` precomputation, Phase 6 `a_agg` precomputation, and as much of Phase 7 as does not depend on `b`. The online entry point `pack(lwe_b, pre)` only takes the `d` scalar `b_k` values and a reference to `pre`. This API shape is what PIR callers will want.

## Phase 9 - Test suite (`tests/`)

Each test runs at multiple parameter sets, including the two from paper Table 5: `(log d, log q, log p, ell, z) = (10, 28, 6, 8, 2^4)` and `(11, 56, 15, 3, 2^19)`.

Tests:
1. `lemma1_trace.rs` - random `p` in `R_q`, assert `Tr(p) = d . c_0`. Catches Galois-group / `g`, `h` bugs.
2. `transform_correctness.rs` - `transform(LWE(m))` decrypts under `s_hat` to a constant polynomial equal to `m`.
3. `aggregate_correctness.rs` - aggregating `d` IRCtx encrypting `m_0..m_{d-1}` decrypts to `Sum m_k X^k`.
4. `collapse_correctness.rs` - collapse output decrypts under `s_tilde` to the same plaintext.
5. `pack_roundtrip.rs` - full Algorithm 1 over many seeds, asserts decryption recovers `(m_0, ..., m_{d-1})`.
6. `python_oracle_match.rs` - for `d = 8` and a fixed RNG seed, the Rust impl produces byte-identical NTT-form intermediates to the Python oracle.
7. `noise_theorem2.rs` - sample 1000+ packs, measure empirical subgaussian parameter of `e_pack` coefficients, assert `sigma_hat^2 <= ell . d^2 . z^2 . sigma_chi^2 / 4` within tolerance.
8. `offline_online_equivalence.rs` - `pack(b, pre)` equals the all-online execution. Catches CRS-model preprocessing bugs.
9. `parameter_validation.rs` - `RlweParams::new` rejects `d` not a power of two, `q` even, etc.
10. `inspiring_vs_cdks_recursion.rs` - structural / behavioural guards against accidentally implementing a CDKS-style scheme:
    - Static API check: `PackPreprocessed::build` accepts exactly two key-switching matrices (`K_g`, `K_h`) - documented invariant + a compile-time-style assertion.
    - Behavioural check: instrument `collapse` (behind a `#[cfg(test)]` counter) and assert that the number of `KS.Switch` calls during a single `pack` equals `(d/2 - 1) + (d/2 - 1) + 1 = d - 1` (linear cascade), NOT `lg(d)` per level (binary tree).
    - Noise upper-bound regression: assert empirical `log2 ||e_pack||_inf` at `d = 2048` is below 36 bits (paper's CDKS measurement was 38.5; InspiRING was 33.4; a value above 36 means we have likely accidentally introduced CDKS-like nested noise amplification).

All tests use a deterministic `ChaCha20Rng` seed so failures are reproducible.

## Phase 10 - Benchmarks (`benches/pack.rs`)

Criterion benchmarks reproducing the relevant rows of Table 5. Pack `2^12 = 4096` LWE ciphertexts using both parameter sets above. Report offline runtime, online runtime, packing-key size, packed ciphertext size, observed `||e_pack||_inf`. Sanity targets from paper: online ~16 ms (param set 1) and ~40 ms (param set 2) on Xeon @ 2.6 GHz single-thread. A `bench/REPORT.md` summarizes observed vs. paper-reported numbers so future regressions are visible.

## Phase 11 - Production hardening

- Docs: every public item has rustdoc with paper section/equation references; `cargo doc` generates a usable manual; `SPEC.md` linked from crate root.
- Lints: `cargo clippy -- -D warnings`, `cargo fmt --check`, `#![deny(missing_docs)]` in `lib.rs`.
- Fuzzing: `cargo-fuzz` target that calls `pack` with arbitrary `b_k` inputs and asserts no panic.
- Constant-time review: tag every function that touches `s_tilde` or `s` with `// CT-sensitive` and audit them. Algorithm 1's online path operates on public values plus `b_k` only - secrets only appear during setup, which is fine for non-CT-critical key-gen.
- CI (`.github/workflows/ci.yml`): on PR run fmt + clippy + tests on stable Rust; on push to main additionally run benchmarks and upload `bench/REPORT.md` as an artifact.
- License + paper attribution: MIT or Apache-2.0; README cites eprint 2025/1352 and the reference Google implementation.
- Security checklist in `SECURITY.md`: parameter sets known to be 128-bit secure per `lattice-estimator`, circular-security assumption, `q` much greater than noise budget per Theorem 2.

## Acceptance criteria

The crate is "production-ready for eventual use" when: (a) all Phase 9 tests are green on both parameter sets; (b) the noise test matches Theorem 2 within 5%; (c) benchmarks land within 2x of paper Table 5 single-threaded numbers; (d) CI is green; (e) `cargo doc` produces complete docs with no warnings.

## Risk register

- spiral-rs API drift: pinned to `rev = 6929441`. If the pinned revision lacks an automorphism we need (e.g. `tau_h = tau_{2d-1}`), add it as a thin wrapper in `src/automorph.rs` rather than forking.
- `d` invertibility mod `q`: requires `q` odd; enforced in `RlweParams::new`.
- Subtle off-by-one in Stage 3: pseudocode has nested loop indices; the Python oracle (Phase 2) is the firewall.
- CRS preprocessing correctness: Phase 9 test 8 specifically guards offline/online equivalence.
- Accidental CDKS-style implementation: the embedding step `(a_tilde, b_tilde)` is identical to CDKS, which makes it tempting to fall back to CDKS's binary-tree merge once the embedding works. SPEC.md section 8 documents the divergence point explicitly; Phase 9 test 10 guards it at runtime by asserting the linear-cascade `KS.Switch` count (`d - 1`) and the empirical noise upper bound (5+ bits below CDKS's measured noise).