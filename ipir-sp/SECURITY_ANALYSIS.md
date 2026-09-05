# Gaussian profile: security analysis and correctness bounds

Assessed implementation: `eef8d55f551c616eda326265c86d486ed0dd3f1d` (PR #14).
This note supports **conditional 128-bit classical single-target security under MATZOV,
including attacker preprocessing**. This is a concrete-security assessment under
stated assumptions, not an unconditional hardness proof or an external audit.
Merging the sampler change does not certify every production snapshot.

## Profile and assumptions

The ring is R = Z[X]/(X^2048 + 1), with q = 72057594037641217,
p = 16384, and Delta = floor(q/p). Secrets and errors use the pinned backend's
finite discrete-Gaussian CDF, nominal standard deviation 6.4 (backend width
6.4 sqrt(2 pi)), with absolute coefficient bound 65. The gadget has three digits
in base z = 2^19. Query precision remains shape-dependent; response bodies use
20 bits and published c1 retains full precision.

The assessment assumes:

- A passive server, honestly fixed public setup, private OS entropy and secure
  ChaCha20 expansion. Every query gets a fresh secret and fresh evaluation keys.
- Key-dependent RLWE pseudorandomness for scaled Galois automorphisms, as used by
  [InsPIRe](https://eprint.iacr.org/2025/1352.pdf) and
  [YPIR, Appendix A](https://www.cs.utexas.edu/~dwu4/papers/YPIR.pdf).
- Publicly seeded matrices are representative hard instances under the
  transparent/random-oracle-style setup heuristic. Known fixed seeds are not
  secret-seed PRG challenges; backend modulo reduction is not exactly uniform.
- MATZOV's classical reduction-cost model and the estimator's GSA shape model
  appropriately estimate the relevant generic attacks on this structured instance.

This excludes malicious setup, decryption oracles, response authentication,
implementation side channels, cross-query secret reuse, free attacker
preprocessing, and an unrestricted multi-target/fleet-wide security claim.
Old unversioned client seeds require their original decoder; see [MIGRATION.md](MIGRATION.md).

## Privacy argument and concrete estimates

Let tau_a(s) = s(X^a). The six key bodies and each query block have the forms

```text
y[a,j] = A[a,j] s + e[a,j] + z^j tau_a(s),  a in {5,4095}, j in {0,1,2}
b[v]   = (-A[v](X^-1)) s + e[v] + Delta m[v].
```

Here m encodes the target row. The key functions belong to the published family.
In the key-dependent RLWE game, replace challenge query bodies by uniform ring
elements while retaining the allowed auxiliary key samples. Adding either target
indicator preserves uniformity; rounding and serialization preserve index
independence. This proves privacy conditional on the assumption, not its hardness.
Public automorphic expansion creates no independent samples. The sign/inversion
transformation acts on the public mask, requiring no sampler-symmetry assumption.

With lattice-estimator commit
[`53da598`](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84),
SageMath 10.9 and `RC.MATZOV`, the four primary attacks below give identical displayed
costs at 12,288 scalar equations (keys only), 40,960 (28,672 query rows plus keys),
and 126,976 (114,688 rows plus keys). Granting unrounded query bodies strengthens
the attacker. The generic scalar abstraction remains a modeling assumption.

| Attack | log2 estimated operations |
|---|---:|
| Primal BDD | 131.219 |
| Primal uSVP | 132.062 |
| Dual hybrid | 134.195 |
| Dual | 134.232 |

Additional primal hybrid estimates at 126,976 samples are 131.239 (without MITM)
and 246.306 (MITM/Babai). The minimum exceeds 128 by 3.219 bits, a modest estimated
margin. A bounded-algebraic diagnostic returned infinity, not a proof of
impossibility. Coded-BKW optimization timed out; separately, the pinned model's
cost formulas exclude sub-2^128 costs in its default search domain: b >= 3 costs
more than 2^165; for b = 2, noise amplification or remaining coordinate guessing
costs more than 2^154. This does not exclude every alternative attack.

The actual sampler sigma is approximately 6.39999999999999167; substituting it
leaves BDD unchanged. Its measured per-coefficient total variation from ideal
DG(6.4) is approximately 9.30181e-16.
Coupling all 129,024 secret/error draws at the larger shape bounds whole-experiment
distance by approximately 1.2002e-10 in the independent-draw model. Thus a fixed-work
attack's success probability changes by at most that amount. This supports a
**constant-success work estimate**; it is not a universal 2^-128 advantage bound.
Private-PRG replacement remains a separate computational assumption.

## Correctness certificate: proof method and scope

For output coefficient k, collect all signed contributions onto the original
base key-error variables before computing weights W[k,i]. Then key noise is
sum_i W[k,i] X[i]; automorphic images must not be treated as fresh errors.
The finite CDF has mean mu = -80967/2^64. Exact rational Taylor bounds establish

```text
log E exp(u (X-mu)) <= 100 u^2,  for |u| <= 1/4.
```

Here |mu| < 1/1024. The CDF-weighted quantity
16 E[exp((|X|+1/1024)/4)-1-(|X|+1/1024)/4] has a rational upper bound below 73.
For x = (|X|+1/1024)/4, expand exp(x) through degree 128 and bound its
remainder by term_129/(1-x/130), yielding the conservative constant 100.

Let L_k be the actual canonical database-column sum, C_k its packing block's
number of discarded top carries, and b the query precision. A deterministic
budget for input noise, query rounding, carries, response rounding and encoding is

```text
D_k = (65 + ceil(q/2^(b+1)) + 1) L_k
      + 573438 * 65 * C_k + ceil(q/2^21) + 1 + (q mod p).
T_k = floor(Delta/2) - D_k - ceil(|mu sum_i W[k,i]|).
```

The carry factor uses z^3 mod q = 573438. For T_k > 0, choose lambda = 2^-31
and check lambda max_i |W[k,i]| <= 1/4. Chernoff and a union bound give

```text
Pr[any decoding failure] <= sum_k 2 exp(-lambda T_k
                                      + 100 lambda^2 sum_i W[k,i]^2).
```

Independence is required only for original sampler draws; query rounding uses
a deterministic bound.
Two fully inspected synthetic 28,672 x 32,768 snapshots satisfy a per-query bound
of 2^-70 in this model, plus the implementation's PRG replacement term. Grouped
weights were crosschecked against backend NTT packing and independently reviewed;
certificate decisions use integer/rational arithmetic.

**Production limitation:** these are certificates for those exact synthetic
snapshots. Dense maximum-value and larger dense-row fixtures remain uncovered by
this bound; no decoding failure was demonstrated. Actual served snapshots require
their own verified certificates or a broader correctness theorem. This note does
not assert that production activation enforces such a check.

## Validation

The evaluated source passed 137 Linux debug tests and 144 optimized native-CPU
tests including the AVX-512 comparison, with one existing documentation example
ignored in each suite. All 131 CDF thresholds and a complete seeded secret matched
on tested macOS ARM64 and Linux x86_64 builds. The stress suite decoded 768 responses
with zero failures; these share secrets/setups and do not establish a rare-failure
bound. Four certificate-verifier tests cover valid and malformed/incomplete evidence.

See the [implementation CI](https://github.com/valargroup/ipir-sp/actions/runs/33935407642).
Research harnesses and raw results are retained separately; other snapshots need
their own certificates.
