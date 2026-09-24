# ReinspiRING implementation contract

Source: [ReinsPIRe, ePrint 2026/1934](https://eprint.iacr.org/2026/1934),
Algorithms 1–2, Lemmas 2–5 and 9–11, Appendices C, D.1, D.2, E.1 and E.2.
Reference: [InsPIRe, ePrint 2025/1352](https://eprint.iacr.org/2025/1352).
This contract describes the refreshed implementation, superseding the PR #17
prototype's incomplete power-of-two benchmark and misleading fast-path labels.

## Algebra and conventions

Work in R_q = Z_q[X]/(X^d+1). Coefficients are constant-term first; ciphertexts
satisfy b + a*s = Delta*m + e. LWE masks embed as sum_i a[i] X^(-i).
Automorphisms tau_g substitute X^g for odd g modulo 2d.

For polynomials t_i and automorphisms tau_i, Compile returns

    H = sum_i Neg(t_i) P_tau_i
    H vec(y) = vec(sum_i t_i tau_i(y)) mod q.

The generating polynomial coefficient for exponent g is p_hat[(g-1)/2] += t_g.
A length-d ring FFT evaluates P(X^(2j)); multiplication by X^j gives column j.
Butterfly twiddles are signed coefficient rotations. Missing exponents are zero;
repeated exponents add. Complexity is O(d² log d) per limb, with O(d²) scratch.
The reference compiler and schoolbook products remain test oracles.

Native packing returns

    (a_final, b + H' vec(kg_body) + sum_j t''_j kh_body_j).

All key bodies include fresh errors. H', leftover digits, and a_final depend
only on the public masks and parameters, not on the query secret or key bodies.

## Native transform and decomposition

`NativeParams` bounds d to powers of two in 2..=2048, q to 2^k with
16<=k<=56, p to a smaller power of two, base bits to 1..=24, and limbs to 1..=8.
These are arithmetic/allocation limits, not security approval for every tuple.
The paper research configuration is d=2048, q=2^54, p=2^14, base=2^19.

D.2 aggregation uses an integer ring FFT. Its exact integer coefficients can
exceed u64 (d*q=2^65 in the paper configuration), so they are stored in i128.
For each odd exponent, the aggregated mask is divided by d with mathematical
floor, then reduced modulo q, as in D.1. Reducing modulo q *before* division is
incorrect. The integer lift of an embedded negative coefficient remains negative.
No d inverse modulo q is used.

Let r=max(0, log2(q)-ell*bits). Round a coefficient to the nearest multiple of
2^r (ties upward), then decompose it into centered base-z digits in
[-z/2,z/2). The key weights are 2^(r+j*bits). Thus reconstruction is exact modulo
q for r=0 and differs by at most 2^(r-1) in centered distance otherwise.
For q=2^54, ell=2 discards 16 bits; ell=3 discards none.

The mask trace collapses each half in reverse powers-of-five order, followed
by the final h=-1 switch. A limb's recorded digits are compiled against the
corresponding automorphism of the base kg body. The final kh digits are retained
as polynomial coefficients. Native keys and preprocessing carry a setup digest.

## Exact lifted products and storage

The auxiliary primes are 4398046568449, 4398046666753 and 4398046781441.
Each is prime and 1 modulo 8192. Spiral 0.5.3-rc.1 supplies each single-prime
NTT and polynomial multiplication. Separate contexts avoid its u64 combined
modulus limit. Their product Q fits i128 and exceeds d*q² at supported inputs.

Operands use centered lifts. A negacyclic coefficient has absolute value at
most d*q²/4. Consequently Q>d*q² suffices for unique signed reconstruction.
Garner CRT reconstructs each individual polynomial product before reduction
modulo q. Limb products are summed only *after* reduction; this avoids assuming
the bound covers an arbitrary sum of limbs. Invalid dimensions/noncanonical
coefficients are rejected. The legacy single-prime helper now rejects insufficient
capacity instead of silently performing a schoolbook fallback.

Native H' uses i32 when every centered entry fits, otherwise i64. Its dimensions
and words are private. The 32-bit path dispatches to AVX2 on supported x86 hosts;
other hosts and wide matrices use wrapping scalar arithmetic. The low 64 bits
of each dot product suffice because q divides 2^64. Vector tails and negative
coefficients are tested against scalar integer arithmetic. Parallelism follows
the caller's Rayon pool; no global thread-count override is made by the library.

## IPIR-SP interface and transport

The `ipir-sp/native` module requires feature `native-reinspiring`; it is separate
from `ProductionSimplePirParams`. Its immutable profile selects Gaussian secrets,
bounded dimensions that are multiples of d, and plaintexts fitting u16.

Public setup expands ChaCha20 masks from SHA-256 domain-separated profile,
shape, seed and snapshot identifiers. Callers cannot substitute query polynomials
in the high-level setup object. Every request samples a new secret and key errors.
A deterministic RNG entry point exists explicitly for research/reproducibility.

Online query precision is min(49, log2 q). Response body precision is
min(log2 p+6, log2 q). Keys use full log2 q bits; published c1 uses full u64 words.
All bit packing reuses IPIR-SP's existing contiguous encoder, and parsers reject
wrong lengths and noncanonical padding before accepting payloads.

- RNQ1: 4-byte version, 32-byte setup ID, fixed-length kg/kh bodies, query words.
- RNR1: 4-byte version, 32-byte setup ID, SHA-256 of the request bytes, body words.
- RNP1: 4-byte version, 32-byte setup ID, column-count full-precision c1 words.

Dimensions and profile are locally known, not read from attacker-controlled
length fields. Setup/request digests prevent accidental mix-ups and stale
responses; they are not authentication. Snapshot IDs identify versions, not
proofs of database honesty. Existing InspiRING wire formats remain unchanged.

The server uses the existing IPIR-SP polynomial-block first dimension: public
hint columns are sums of negacyclic database/query-mask products, and online
answers are column-major u16-by-u64 dot products. It preprocesses output blocks
sequentially to bound memory, while parallelizing columns and online blocks.
This implementation prioritizes correctness of the native hint path; it does
not yet cache every transformed public hint operand across columns.

## Validation and comparison contract

Odd-modulus adapters must match current InspiRING byte-for-byte. Native packing
must match the independent Python integer/schoolbook sequential trace, recover
encrypted messages under both sampler configurations, and preserve signed CRT
products on boundary inputs. Full IPIR-SP tests include serialization and true
phase error against known plaintext, not nearest-encoding residual.

ReinsPIRe Table 5 has separate columns: ell=2 preprocessing 3.9 s, matrix 13.6 ms,
remainder 1.2 ms; ell=3 preprocessing 6.0 s, matrix 20.6 ms, remainder 1.8 ms.
The old benchmark incorrectly assigned 1.2 ms to the matrix operation.
InsPIRe Table 5's 40 ms is for 4096 LWEs, i.e. two degree-2048 outputs.
Both papers report single-threaded Xeon measurements; multi-worker measurements
must be labeled separately. Full-paper PIR throughput is not IPIR-SP throughput.

See SECURITY.md for the threat model and unclosed production approval gates,
and the benchmark report for concrete measurements and reproducibility records.
