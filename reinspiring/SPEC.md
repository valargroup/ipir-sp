# `reinspiring` — Specification of the ReinspiRING ring-packing algorithm

This document is the design specification and mathematical companion for the
`reinspiring` Rust crate, which implements **Algorithm 2 (`ReinspiRING`)** from
the ReinsPIRe paper:

> R. A. Mahdavi, S. Patel, J. Y. Seo, K. Yeo. *ReinsPIRe: High-Throughput,
> Low-Communication PIR with Server Preprocessing.* ePrint 2026/1934.
> <https://eprint.iacr.org/2026/1934>

ReinspiRING is a **recompilation** of InspiRING’s online phase
([ePrint 2025/1352](https://eprint.iacr.org/2025/1352), Algorithm 1), not a new
algebraic packing. The sibling crate [`inspiring`](../inspiring/) remains the
NTT-domain reference implementation; for odd NTT-friendly `q`, ReinspiRING must
produce **byte-identical** packed ciphertexts.

The scope of this crate is intentionally narrow:

- **Algorithm 2 only** — `Preprocess` + `Pack` for full `d → 1` packing.
- No vReinsPIRe, no ReinsPIRe+, no PIR layers, no single-KS prime cyclotomics
  (Appendix G).

---

## Table of contents

1. [Relationship to InspiRING](#1-relationship-to-inspiring)
2. [Notational conventions](#2-notational-conventions)
3. [Lemma 1: matrix view of polynomial multiplication](#3-lemma-1-matrix-view-of-polynomial-multiplication)
4. [Lemma 2 and Algorithm 1: Compile](#4-lemma-2-and-algorithm-1-compile)
5. [Corollary 1: compiling InspiRING’s online sum](#5-corollary-1-compiling-inspirings-online-sum)
6. [Algorithm 2: ReinspiRING](#6-algorithm-2-reinspiring)
7. [Leftover term via lifted NTT](#7-leftover-term-via-lifted-ntt)
8. [Appendix D.1: even (power-of-two) modulus](#8-appendix-d1-even-power-of-two-modulus)
9. [Noise and storage](#9-noise-and-storage)
10. [Fast Compile (Lemma 9)](#10-fast-compile-lemma-9)
11. [Symbol table (paper ↔ code ↔ inspiring)](#11-symbol-table-paper--code--inspiring)
12. [Spec acceptance checklist](#12-spec-acceptance-checklist)

---

## 1. Relationship to InspiRING

After CRS-side preprocessing, InspiRING’s online phase (gadget length `ℓ`) is

```text
Σ_{j=0}^{ℓ-1} (
  Σ_{i=0}^{d/2-2} t_{i,j}(X) · y_j(X^{5^i})
               + t'_{i,j}(X) · y_j(X^{-5^i})
               + t''_j(X) · y'_j(X)
)                                          (ReinsPIRe Eq. 2)
```

plus the online `b̃` contribution. In this repository the same sum appears as

```text
b_final = NTT(b̃)
        + Σ_steps τ_step(kg_body) · digits_step
        + kh_body · digits_last
```

in [`inspiring::preprocess::collapse_uploaded_body_b`](../inspiring/src/preprocess.rs).

ReinspiRING rewrites the `K_g` half of that sum as a single matrix–vector
product `H' · vec(y)` in the **coefficient** domain, so:

- the ciphertext modulus need not be NTT-friendly (hardware-native `q = 2^k`
  becomes usable after Appendix D.1);
- gadget digits keep small infinity-norm in coefficient form, so `H'` is more
  compact than NTT-domain digit streams (Lemma 5).

The leftover `Σ_j t''_j · y'_j` is **not** compiled into a second `d × d`
matvec; it stays a polynomial product evaluated via a large auxiliary modulus
`Q` (Section 7).

**Correctness contract (odd `q`):** Compile is an exact rewrite. Packing output
must match `inspiring::QueryPackPreprocessed::pack_b` bit-for-bit after
converting representations. No extra noise.

---

## 2. Notational conventions

| Symbol | Meaning |
|---|---|
| `d` | Power of two. LWE dimension and RLWE degree. |
| `q` | Ciphertext modulus. Odd for the byte-equal path; may be `2^k` after D.1. |
| `Q` | Auxiliary NTT-friendly modulus with `Q > d · q²` for the leftover mul. |
| `R_q` | `Z_q[X]/(X^d + 1)`. |
| `ℓ`, `z` | Gadget length and base (from InspiRING). |
| `y_j` | Body of `K_g`, limb `j` (client upload). |
| `y'_j` | Body of `K_h`, limb `j` (client upload). |
| `t_{i,j}`, `t'_{i,j}` | Preprocessed gadget-digit polynomials for the `τ_g` / `τ_h∘τ_g` collapse steps. |
| `t''_j` | Preprocessed gadget-digit polynomials for the final `K_h` step. |
| `ã` | Final RLWE `c1` from collapsing the CRS / fixed-mask trace. |
| `Neg(a)` | Negacyclic Toeplitz matrix of polynomial `a` (Lemma 1). |
| `P_τ` | Signed permutation matrix realising `vec(τ(y)) = P_τ · vec(y)`. |
| `H'` | Compiled packing matrix. |

Bold lower-case = vectors; bold upper-case = matrices. Coefficients are stored
lowest-degree-first: index `0` is the constant term.

---

## 3. Lemma 1: matrix view of polynomial multiplication

> **Lemma 1 (ReinsPIRe §3.3).** Let `a(X), b(X) ∈ R_q`. Define
>
> ```text
> Neg(a) = [
>   [ a_0,  -a_{d-1}, -a_{d-2}, …, -a_1 ],
>   [ a_1,   a_0,     -a_{d-1}, …, -a_2 ],
>   …
>   [ a_{d-1}, a_{d-2}, …, a_0 ]
> ]
> ```
>
> and `vec(b) = [b_0, …, b_{d-1}]^⊤`. Then
> `a(X)·b(X) ≅ Neg(a) · vec(b)` as coefficient vectors.

Proof sketch: schoolbook multiplication followed by the negacyclic wrap
`X^d ≡ −1` is exactly left-multiplication by this Toeplitz matrix.

In code (`compile::negacyclic_matrix`): row `r`, column `c` is
`a[(r − c) mod d]` with a sign flip when the index wraps (i.e. when
`c > r`).

---

## 4. Lemma 2 and Algorithm 1: Compile

> **Lemma 2 (Compilation).** Let `[t_i]_{i∈[k]} ⊂ R_q` with `∥t_i∥_∞ ≤ B`,
> and let `[τ_i]_{i∈[k]}` be automorphisms of `R_q`. Then there exists
> `M ∈ Z_q^{d×d}` depending only on the `t_i` and `τ_i`, with `∥M∥_∞ ≤ kB`,
> such that
>
> ```text
> Σ_i t_i(X) · τ_i(y(X)) ≅ M · vec(y(X)).
> ```
>
> `M` is computable in `O(k d²)` time (naive) or `O(d² log d)` (Lemma 9).

**Derivation.** Autormorphisms of power-of-two cyclotomics are signed
permutations of coefficients: `vec(τ(y)) = P_τ · vec(y)`. Combined with
Lemma 1,

```text
t_i · τ_i(y) ≅ Neg(t_i) · P_τ_i · vec(y).
```

Summing over `i` yields `M = Σ_i Neg(t_i) P_τ_i`.

**Algorithm 1 (`Compile`):**

```text
Input:  [t_i]_{i∈[k]}, [τ_i]_{i∈[k]}
Output: M ∈ Z_q^{d×d}
M ← 0
for i = 0 .. k−1:
    M ← M + Neg(t_i) · P_τ_i
return M
```

`P_τ` for `τ: X ↦ X^g` (`g` odd mod `2d`): coefficient `i` maps to exponent
`(i·g) mod 2d`; if the reduced exponent is `≥ d`, land at `e − d` with a
minus sign (same rule as `inspiring::automorph` / the Python oracle).

---

## 5. Corollary 1: compiling InspiRING’s online sum

> **Corollary 1.** If `∥t_{i,j}∥_∞, ∥t'_{i,j}∥_∞ ≤ B`, then for each limb `j`
> there is `H'_j ∈ Z_q^{d×d}` with `∥H'_j∥_∞ ≤ (d−2)B` such that the inner
> double sum of Eq. 2 equals `H'_j · vec(y_j)`, leaving only `t''_j · y'_j`.

Stack limbs horizontally:

```text
H' = [H'_0 | H'_1 | … | H'_{ℓ−1}] ∈ Z_q^{d × ℓd}
y  = [vec(y_0)^⊤ | … | vec(y_{ℓ−1})^⊤]^⊤ ∈ Z_q^{ℓd}
```

so `Σ_j H'_j · vec(y_j) = H' · y`.

### Mapping onto this repository’s digit schedule

`QueryPackPreprocessed::digits_ntt` has length `d − 1` and is recorded in
collapse execution order ([`build_query_reference`](../inspiring/src/preprocess.rs)):

| Index range | Count | Body | Automorphism | Paper symbol |
|---|---|---|---|---|
| `[0, d/2−2]` | `d/2 − 1` | `kg_body` | `τ_g^{image}` (left tables, reverse order) | `t_{i,j}` with `τ = X ↦ X^{5^{·}}` |
| `[d/2−1, d−3]` | `d/2 − 1` | `kg_body` | `τ_g^{image} ∘ τ_h` (right tables, reverse) | `t'_{i,j}` with `τ = X ↦ X^{-5^{·}}` |
| `[d−2]` | 1 | `kh_body` | identity | `t''_j` |

Each `digits_ntt[step]` is an NTT matrix of shape `ell × 1`. Limb `j` is
row `j`. For Compile we take the **inverse-NTT** coefficient polynomial of
each limb (gadget digits → small norm).

`PackingKeys.kg_body` / `kh_body` are NTT `1 × ell` rows. Online Pack uses
their coefficient forms as `y_j` / `y'_j`.

`QueryPackPreprocessed.collapse_a_final_ntt` is `ã` (final `c1`).

---

## 6. Algorithm 2: ReinspiRING

```text
ReinspiRING.Preprocess(Ĥ, [w_j], [w'_j]):
    st ← InspiRING.Preprocess(Ĥ, [w_j], [w'_j])
    parse st as (ã, [t_{i,j}], [t'_{i,j}], [t''_j])
    aut ← [X ↦ X^{5^i}]_{i} ‖ [X ↦ X^{-5^i}]_{i}   // matching digit schedule
    for j = 0 .. ℓ−1:
        H'_j ← Compile([t_{*,j}] ‖ [t'_{*,j}], aut)
    H' ← [H'_0 | … | H'_{ℓ−1}]
    return (ã, H', [t''_j])

ReinspiRING.Pack(ĉ_LWE_b, [y_j], [y'_j], ã, H', [t''_j]):
    y ← concat_j vec(y_j)          // length ℓd
    z ← Σ_j t''_j · y'_j           // via Section 7
    c2 ← H' · y + z + b̃           // b̃ = Σ_k b_k X^k
    return (ã, c2)
```

In this crate, `InspiRING.Preprocess` is **not** reimplemented for odd `q`:
callers pass an existing `inspiring::QueryPackPreprocessed` (or the extracted
coefficient limbs). Even-`q` D.1 is the only place ReinspiRING owns a
modified transform.

Public API shape:

```rust
pub fn preprocess_from_inspiring(pre: &QueryPackPreprocessed, schedule: &AutomorphSchedule)
    -> ReinspiringPreprocessed;

pub fn pack(b_scalars: &[u64], keys: &PackingKeys, pre: &ReinspiringPreprocessed)
    -> RlweCiphertext;
```

---

## 7. Leftover term via lifted NTT

Compiling `t'' · y'` would cost another `O(d²)` matvec. Instead (YPIR-style):

1. Choose NTT-friendly `Q` (or a product of NTT primes) with `Q > d · q²`.
2. Lift coefficients of `t''_j` and `y'_j` from `Z_q` into `Z_Q` (centered
   representatives in `(-q/2, q/2]`).
3. Multiply in the NTT domain over `R_Q`.
4. Inverse-NTT; reduce each coefficient mod `q`.

Because `Q` is large enough that the integer product does not wrap, reduction
mod `q` recovers the product in `R_q`. Cost `O(ℓ d log d)`.

spiral-rs is used **only** for arithmetic at `Q`, never as the native-`q`
substrate when `q` is a power of two.

---

## 8. Appendix D.1: even (power-of-two) modulus

InspiRING’s Stage 1 multiplies by `d^{-1}`. That inverse does not exist when
`q` is even. ReinsPIRe Appendix D.1 replaces exact division by:

1. Interpret the traced ciphertext over `R_{d q}` with message scale `d Δ`
   (keep the factor of `d` on the message / random components).
2. Aggregate `d` intermediates in that larger ring.
3. Modulus-switch down to `R_q`.

This introduces additive noise `e_div` with `∥e_div∥_∞ ≤ d²` for ternary
secrets (Lemma 10 / ReinspiRING Lemma 4). It is **not** used on the odd-`q`
byte-equal path; [`inspiring::RlweParams::new`](../inspiring/src/params.rs)
continues to reject even `q`.

---

## 9. Noise and storage

> **Lemma 4 (ReinspiRING noise).** Packing noise is `e_ks + e_div` where
> `σ_pack² ≤ ℓ d² z² σ_ks² / 4` (same as InsPIRe Theorem 2) and, for ternary
> secrets, `∥e_div∥_∞ ≤ d²`. On the odd-`q` path `e_div = 0` and the packed
> ciphertext equals InspiRING’s.

> **Lemma 5 (server storage).** `H'` has size at most
> `ℓ d² (log₂(d z) + 1)` bits (worst-case norm); `[t''_j]` costs
> `ℓ d log₂ q` bits. In memory we store entries as native `u32`/`u64` words
> (paper remark): bit-packing is not worth the runtime on the hot matvec.

The `d B` bound on `∥H'∥_∞` is loose; under a uniform digit heuristic the
norm is closer to `O(√(d log d) · B)`.

---

## 10. Fast Compile (Lemma 9)

Naive Compile is `Θ(k d²)` with `k = d − 2` per limb → `Θ(d³)` per limb.
Lemma 9 reduces this to `O(d² log d)` by observing that each column of `M`
is an evaluation of a degree-`d` polynomial `P(Z) ∈ R_q[Z]` at powers of
`ω = X²` (a `d`-th root of unity in `R_q`). The FFT butterflies only rotate
coefficients (multiply by powers of `X²`); **`q` need not be NTT-friendly**.

This optimisation is required before production `d = 2048` preprocess in
`ipir-sp`. Tiny-parameter tests may use the naive algorithm.

---

## 11. Symbol table (paper ↔ code ↔ inspiring)

| Paper | `reinspiring` | `inspiring` counterpart |
|---|---|---|
| `d`, `q`, `ℓ`, `z` | `params::ReinspiringParams` | `RlweParams` / `GadgetParams` |
| `Q` | `params::LiftModulus` | (none; leftover-only) |
| `Neg(t)` | `compile::negacyclic_matrix` | — |
| `P_τ` | `compile::signed_perm_matrix` / apply-perm | `automorph::tau_*` |
| `Compile` | `compile::compile_naive` / `compile_fast` | — |
| `H'` | `matrix::PackingMatrix` | — (implicit in NTT products) |
| `t_{i,j}`, `t'_{i,j}` | `preprocess::DigitSchedule` coeff limbs | `digits_ntt[0..d-2]` inv-NTT |
| `t''_j` | `ReinspiringPreprocessed::t_double_prime` | `digits_ntt[d-2]` inv-NTT |
| `y_j` | coeff form of `PackingKeys.kg_body` col `j` | NTT `kg_body` |
| `y'_j` | coeff form of `PackingKeys.kh_body` col `j` | NTT `kh_body` |
| `ã` | `ReinspiringPreprocessed::a_tilde` | `collapse_a_final_ntt` |
| `b̃` | online from `b_scalars` | online from `b_scalars` |
| `Pack` | `pack::pack` | `QueryPackPreprocessed::pack_b` |
| D.1 mod-switch | `modswitch::*` | (rejected: odd `q` only) |

**Public API invariants:**

1. For odd NTT-friendly `q` matching an `inspiring` parameter set,
   `pack(...)` equals `pack_b(...)` on the same `(b, keys, CRS digits)`.
2. Online `pack` is deterministic: no fresh randomness.
3. `H'` is built only from CRS-side digits and the automorphism schedule —
   never from client key bodies.

---

## 12. Spec acceptance checklist

Phase 1 is complete when:

- [x] §1 states the exact-rewrite contract vs InspiRING.
- [x] §3 defines `Neg` with the negacyclic sign convention.
- [x] §4 states Lemma 2 and Algorithm 1.
- [x] §5 maps digit indices onto `digits_ntt` / `PackingKeys`.
- [x] §6 gives Algorithm 2 and the Rust API shape.
- [x] §7 specifies the lifted-`Q` leftover multiply.
- [x] §8 isolates D.1 from the odd-`q` path.
- [x] §9 records Lemmas 4–5.
- [x] §10 records Lemma 9 for later phases.
- [x] §11 enumerates every symbol used in code.

Subsequent phases (oracle, Rust, tests, `ipir-sp` backend) derive assertions
from this document.
