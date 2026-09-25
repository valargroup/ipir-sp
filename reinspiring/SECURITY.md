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
sampler uses the dependency's fixed CDF scan with the frozen integer table in
`src/native_gaussian_cdf.txt`, not its variable-time fast sampler. Native secret
and error draws share that table. The certificate checker verifies its exact
multiplicities and records its SHA-256; floating-point table generation no longer
affects native sampling. Changing the table requires a new profile identity.
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

An opt-in public-weight analysis and exact-rational finite-sampler certificate
now cover the recorded p16 benchmark snapshots, including reduced-precision
K_h transport. See [the argument and reproduction instructions](tools/security/NATIVE_CERTIFICATE.md)
and [retained results](../bench-results/2026-09-25-reinspiring-kh-compression/README.md).
These conditional calculations are not an independent cryptographic review or
a certificate for another application snapshot. They do not approve the native
KDM composition for production.

The opt-in two-mask mode uses only K_g and retains the pre-final masks under
`s` and `τ_-1(s)`. The client adds both mask products before decoding. Its
noise exporter omits the final K_h error and residue and binds the mode into a
distinct setup identifier. The certificate checker accepts a separate
`native-noise-two-mask-v1` report. This mode still requires an independent
native KDM/RLWE review and a certificate for each served snapshot; the
recorded one-mask certificates do not transfer to it.

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

## Packing performance invariants

The packing optimizations do not change decomposition, rounding, ciphertext
moduli, samplers, or wire precision. Signed 27- or 28-bit storage is selected only after
checking every public matrix coefficient against [-2^26, 2^26-1] for 27 bits,
or [-2^27, 2^27-1] for 28 bits; the decoder
sign-extends the exact value. Packed row kernels compute the same wrapping u64
sum, whose low bits equal the desired result modulo the native power-of-two q.
Fallback storage retains out-of-range coefficients exactly.

Integer mask aggregation starts with i64 only while the public bound
`stage_length * (q-1) <= i64::MAX` holds. It widens to i128 before any stage that
could exceed that bound. D.1 division is performed on the signed integer result
before reduction modulo q; reducing earlier would change the algorithm.

Cached online leftover products are combined before CRT reconstruction only
when twice the bound on their entire signed sum is strictly smaller than the
product of the two auxiliary primes. Otherwise each product is reconstructed
separately. Request-wide key transforms select enough primes from the profile's
public digit bound, independently of the first block's actual coefficients.

Prepared key bodies are public uploaded ciphertexts and request-local data.
They can be shared immutably across blocks from the same setup. The split
packing API borrows the corresponding preprocessing block and consumes its
pending result when adding a scan body, but does not authenticate that body's
request or block identity. A distributed dispatcher must enforce those bindings;
it must not treat a matching setup ID as a matching request. The integrated
server keeps these objects local to a single validated request and preserves
its existing request-hash response binding.

## Prepared client decoding and upload search

The prepared decoder changes only exact client arithmetic. It caches public mask
transforms and computes `a*s + a_other*tau_-1(s)` as one integer sum before CRT.
For Gaussian secrets the public support is read from the same sampler's
`max_val`; ternary uses 1. Prime selection depends on that support and public
masks, not observed secret coefficients. Two primes are used only when their
product strictly exceeds twice `d * support * sum(max_abs(mask))`. The decoder
rejects insufficient capacity. The conjugate transform reverses Spiral's
bit-reversed evaluation array; tests compare it with coefficient-domain
conjugation through degree 2048 and at support/modulus boundaries.

Request preparation computes these products before receipt of the response.
They remain secret-dependent, request-local state and are zeroized on drop;
retained secret transforms and temporary matrix/vector allocations are also
zeroized. Borrowed matrix guards cover return and unwinding; inverse transforms
run in guarded storage rather than copying into the dependency's thread-local
scratch. Per-block products are erased after copying into the final protected
state, which also erases partial results on error. This is heap-buffer hygiene,
not a claim to erase CPU registers, stack spills, or operating-system copies.
These products must never be published or
reused with another request. The integrated API validates setup/profile and
response/request bindings, and binds cached products to a digest of the actual
published masks. This digest is a consistency check, not authentication.
All request preparation is online client work, charged to generation in the
comparison benchmark. The one-mask comparator gets the same optimizations.
The existing exclusion of local timing/cache attackers still applies.

The gadget search is counterfactual and does not enable new runtime gadgets.
It uses per-limb K_g row-norm envelopes and the combined collapse-secret matrix.
For a candidate final gadget, the secret family is combined using triangle
inequalities (including an upward integer square-root bound on the L2 cross
term), never by assuming independent reuse of the secret. Transport residuals
are budgeted deterministically. Failure on the first block under this bound
rejects certification by this screen; it is not a lower bound on actual failure
probability. Passing a screen would still require all blocks, regeneration for
an executable bound setup, and independent review.

Omitting K_h releases a subset of the original uploaded key material. For a
passive server, the extra published masks are public preprocessing and the
response is computed from its existing view. Under the same public-mask
experiment, a distinguisher for this view can be applied to the original view
with K_h discarded. Therefore the original full-key generic lattice diagnostics
are conservative for this omission; no improved security-bit claim is made.
Likewise deterministic rounding of an existing upload is public postprocessing.
Neither observation resolves the native profile's underlying KDM assumptions,
nor justifies unrelated gadget changes. Production review gates remain in force.

## Rounded public-mask validation

The RNP3 two-mask publication rounds public preprocessing, not secret key material.
It introduces no new secrecy assumption beyond the underlying passive-server
native profile: the server can already compute these masks from its view. It
does introduce decoding error. The certificate exporter combines both public
rounding-error operators with the existing matrix on the same original secret
coefficients. It does not assume independence between those terms. See the
[certificate argument](tools/security/NATIVE_CERTIFICATE.md) and
[no-extra-download evidence](../bench-results/2026-09-25-no-extra-download/README.md).
The native production review and per-snapshot correctness requirements continue
to apply; the rounded transport is opt-in and does not enforce a certificate at
runtime. Decode-state mask digests bind the actual encoded public masks as well
as the profile, preventing reuse of products prepared from different masks.
