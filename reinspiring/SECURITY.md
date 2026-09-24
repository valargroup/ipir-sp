# Security and production status

**Native ReinspiRING remains an experimental cryptographic profile.** The odd-q
adapter is an exact rewrite of current InspiRING; that statement does not transfer
to a new modulus, approximate gadget or sampler. The IPIR-SP native path is opt-in
and cannot be passed to `IPIRClient::new` as a production profile.

## Threat model

Assume a passive server, a fixed public snapshot/setup, secure OS entropy and
ChaCha20, fresh secret/key randomness per query, and key-dependent RLWE hardness
for scaled automorphic secret functions. Uniform native masks use a power-of-two
mask with no modulo bias. Domain-separated setup hashes bind profile, dimensions
and snapshot identifier. Client query polynomials are locally seed-expanded.

This does not provide authenticated responses, malicious-database security,
verifiable PIR, a decryption oracle, cross-query secret reuse guarantees, or a
multi-target fleet-wide work bound. Transport digests are public consistency
checks, not MACs. Applications must not expose secret-dependent response-validation
behaviour to a malicious server.

The lifted arithmetic uses the pinned Spiral NTT. Generic products retain three
primes. Cached public operands may use two only when their product exceeds
`2*d*max_abs(public_operand)*floor(q/2)`; limbs are reconstructed separately.
Prime selection depends only on public preprocessing, never on a client secret. CRT reconstruction and
coefficient conversions have not received a constant-time machine-code audit;
local timing/cache adversaries are excluded from the current claim. The Gaussian
sampler uses the dependency's fixed CDF scan, not its variable-time fast sampler.
Ternary rejection sampling is confined to the explicitly labeled research profile.

## Noise accounting

Let B_s bound the secret's absolute coefficients. Appendix D.1 gives

    ||e_div||_infinity <= d² B_s.

Uniform ternary uses B_s=1. The current Gaussian CDF has finite support B_s=65,
so a deterministic bound is 65*d², not the ternary d² bound. `NativeParams`
exposes this bound explicitly. The nominal Gaussian standard deviation is 6.4;
its backend width is 6.4*sqrt(2*pi), matching main.

For r discarded gadget bits, every decomposition residue has magnitude <=2^(r-1).
A conservative bound over d-1 key switches is

    ||e_decomp||_infinity <= (d-1)*d*2^(r-1)*B_s,

and is zero with exact decomposition. At d=2048, q=2^54, ell=2, r=16 this
worst-case bound alone exceeds the decoding interval. Passing measured decryption
tests therefore does NOT prove a negligible failure probability. Three limbs
remove this decomposition error but still require a bound on packing errors.

Under the paper's independence heuristic, key-switch variance is bounded by
ell*d²*z²*sigma_ks²/4. An implementation-specific certificate must instead collect
weights on the **original** base key-error variables: automorphic copies are not
independent samples. Approximate-decomposition and D.1 errors reuse secret
coefficients and need analogous accounting, or valid deterministic budgets.

The first dimension also contributes database-weighted query errors and rounding.
The native query rounding magnitude is <=q/2^(query_bits+1) per coefficient;
response-body rounding is <=q/2^(response_bits+1). p divides q in native profiles,
so there is no q mod p encoding residual. Tests report centered distance from the
known encoded row and compare decoded rows exactly. Historical InspiRING snapshot
certificates do not cover these native schedules.

## Concrete lattice diagnostics

`tools/security/estimate.py` reproduces generic scalar-LWE estimates with
lattice-estimator 53da5982597709ba0fdf94ea37a84d822310fd84 and SageMath 10.9.
It grants full-precision query bodies to the adversary and counts uploaded key
samples once, not once per automorphic image. These estimates model structured
KDM-RLWE as generic LWE; they do not prove the reduction or exhaust all attacks.

The minimum over primal uSVP, primal BDD, dual and dual-hybrid was:

| Configuration | MATZOV log2 work | ADPS16 core-SVP log2 work |
| --- | ---: | ---: |
| Main: Gaussian, q approximately 2^56 | 131.219 | 103.368 |
| Native: Gaussian, q=2^54, two limbs | 136.829 | 109.500 |
| Native: ternary, q=2^54, two limbs | 128.789 | 100.355 |

The ternary estimate has less than one bit of margin over 128 under MATZOV.
Neither model result establishes an unconditional 128-bit claim. Raw estimates,
including block sizes, sample counts and model details, accompany the benchmark
report. Other parameter tuples need their own estimates. BKW, algebraic attacks,
all hybrid variants and quantum cost models were not exhaustively rerun here.

## Release gates

Completed implementation gates: independent exact-arithmetic oracle, complete
native encryption/decryption, degree-2048 validation for both sampler/limb choices,
odd-q equivalence, bounded transport parsing, setup/profile/request binding,
scalar/SIMD differentials, fresh OS-seeded integrated queries, and measured full
IPIR-SP row recovery. Refer to the report for exact test and fuzz coverage.

Still required before production activation:

1. An independent cryptographic review of the power-of-two/KDM composition,
   sampler and approximate-decomposition profile. The runbook requires a second
   reviewer for changes to key material; the implementation author's tests do
   not satisfy that requirement.
2. A conservative correctness certificate for each served snapshot/profile, or
   a reviewed general failure bound, including the correlated rounding terms.
   Statistical smoke tests cannot certify cryptographic failure probabilities.
3. If local timing/cache attackers are in scope, audit or replace the client-side
   CRT/conversion path before deployment.

No deployment or default-backend change is part of this refresh. Benchmark
performance is not evidence that these approval gates have been met.
