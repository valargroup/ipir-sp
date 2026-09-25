# Native snapshot correctness certificate

This implementation-specific argument covers the public statistics exported by
`native_noise`, using exact-rational arithmetic in `certify_native.py`. It is
conditional on the implementation, supplied snapshot, exported sampler
distribution, and independent fresh sampler draws. ChaCha20 is treated as a
cryptographic generator of independent uniform draws. This is not an independent
review, computational-security estimate, or approval of native KDM-RLWE.

The supported profile is Gaussian, d=2048, q=2^54, p=2^16, two base-2^19 limbs
with 16 dropped bits, 49-bit query bodies and 22-bit response bodies. Keys are
fresh per request. The passive-server threat model in `SECURITY.md` applies.
The probability covers a complete response for the recorded database/setup,
over fresh request randomness, for any selected row. It does not bound
accumulated failures over multiple requests.

## Original sample weights

In the separate two-mask mode, the final K_h switch is absent. The public
weight exporter stops after the two K_g collapse chains, so each output error
is `H[row] · e_g + S_pre[row] · s + database_column · e_query`, where
`S_pre` combines only the collapse residues. There is no final key error,
final residue, or K_h transport budget. The same D.1, query rounding, response
rounding, finite-sampler calculation, and full-response union bound apply.
The checker requires the distinct `native-noise-two-mask-v1` report format and
does not accept one-mask statistics as a two-mask certificate.

Write `delta = reconstructed_mask - input_mask (mod q)`. A switch contributes
the digit product with the key error plus `delta * source_secret`. For a
collapse step with key automorphism e, the source secret is `tau_(5e)(s)`.
The final source secret is `tau_-1(s)`.

The compiled matrix H combines all automorphic copies of each original K_g
error coefficient. A second matrix S combines *all* decomposition residues and
their source-secret automorphisms, including the final residue. Thus each
output's random error, apart from deterministically budgeted terms, is

    E = H[row] · e_g + Neg(final_digits)[row] · e_h
        + S[row] · s + database_column · e_query.

All weights are public and independent of request randomness. Centering matrix
entries modulo q changes the integer representative but not the decrypted
phase; bounding that representative inside the decoding interval suffices.
L1, squared L2 and maximum weight are computed after combining repeated uses
of the same variable. The exporter takes a componentwise upper envelope over
each block and concatenates the independent query-error family. Automorphic
copies are never counted as fresh error samples.

The independent Python oracle constructs the matrices by schoolbook products
on individual basis vectors. Tests compare all statistics, one-limb
counterfactuals and ciphertext outputs. Another check reconstructs original key
errors from the encryption equations and compares the predicted phase against
actual packing, leaving only the bounded D.1 residual.

## Deterministic budget

Reserve, for every output in a block,

    D = B_s*d² + 16*max_column_L1 + 2^31 + R_h*sum_j ||final_digits_j||_1.

The terms cover D.1 division, query-body transport, response-body transport and
final-key transport. B_s is the actual sampler support bound (65).
`R_h=0` at full precision, or `2^(53-t)` for t-bit K_h transmission.
Database entries are canonical nonnegative u16 values. Both query and key
rounding may depend on secrets/errors: these deterministic bounds assume no
independence. Key rounding is not modeled as fresh uniform error.

The phase must have absolute value strictly below `T=q/(2p)=2^37`. D.1 shares
secret variables with S, but reserving its absolute bound requires no
independence. The same reasoning covers correlations with query rounding.

## Finite-sampler tail calculation

The sampler is not replaced by an ideal Gaussian. Native secret and error
sampling use the frozen integer CDF in `src/native_gaussian_cdf.txt`, through the
pinned backend's fixed scan. No floating-point calculation determines its CDF.
The exporter computes exact integer multiplicities over all 2^64 draws.
Inclusive comparisons give the first bucket `cdf[0]+1` draws. Repeated
thresholds have zero subsequent mass. Draws above the last threshold return
zero and are included in the zero bucket.

The checker requires the exact frozen multiplicities, rejecting even a one-draw
redistribution, and includes `sampler_sha256` in its output. The digest covers
consecutive little-endian u64 CDF thresholds. New exports include that digest;
legacy local reports may omit it only because their full counts are still
checked against the frozen table. The table matches every saved benchmark
report exactly, so freezing it preserves those conditional bounds and setup IDs.
Any future distribution change requires a new native profile identity and fresh
certification. Older binaries that generated a different CDF are not compatible
with this claim and must be upgraded and reanalyzed.

For an actual sample X, let mu=E[X]. For positive a define

    C(a) = 2 E[exp(a*|X|) - 1 - a*|X|] / a².

For |u|<=a, expand the exponential and bound terms of degree >=2 by their
absolute moments. Since |u|^(k-2)<=a^(k-2),

    E[exp(uX)] <= 1 + u*mu + C(a)*u²/2
               <= exp(u*mu + C(a)*u²/2).

For weight norms L1, L2² and M, reserve `|mu|*L1` for sampler bias. Set
`B=T-D-|mu|*L1`. If B<=0, the checker does not certify the profile. Otherwise,
for positive lambda with `lambda*M<=a`, independence of *original* samples gives

    Pr[|E| >= T-D] <= 2 exp(-lambda*B + C(a)*lambda²*L2²/2).

For each a in a fixed grid, use `lambda=min(B/(C(a)*L2²), a/M)` and select
the strongest bound. This deterministic public choice needs no extra union
bound. Union over all output coefficients requires no independence between
coefficients or packing blocks. The reported integer k gives a conditional
full-response bound <=2^-k.

The checker uses exact integers/Fractions. Exponentials use a Taylor sum with
upward-rounded 192-bit fixed-point arithmetic and an upper bound on the entire
remaining tail. Conversion to failure bits divides by a rational upper bound
on ln(2) and rounds down. No floating-point tails or measured errors enter it.

## Binding and reproduction

The CLI now defaults to `--require-bits 128`. A lower historical research target
must be requested explicitly; ordinary invocation rejects the saved 28-bit
rounded-mask report. This command is still not a runtime snapshot admission gate.


The report contains setup ID, SHA-256 of the actual column-major u16 database,
dimensions, exact sampler counts and statistics for every block. These are local
evidence, not authenticated server claims. The checker trusts the exporter; it
cannot verify the database hash or matrices from norms alone. Never accept an
untrusted JSON report as proof of honest server work.

Changing K_h wire precision changes the setup ID and public mask expansion.
A precision sweep on one report is a counterfactual screen. Rerun the exporter
at the selected precision and use `actual_profile` for acceptance. One-limb
entries screen hypothetical final gadgets on the pre-final mask; they do not
enable those gadgets or certify their privacy/security composition.

From the workspace root:

```sh
RAYON_NUM_THREADS=8 cargo run --release -p ipir-sp \
  --features native-reinspiring --example native_noise -- 28672 32768 47 > noise.json
python3 reinspiring/tools/security/certify_native.py noise.json
python3 -m unittest discover -s reinspiring/tools/security
```

This generates a deterministic full-range-u16 benchmark database, not an
application snapshot. For a real snapshot, call `NativeServer::build_analyzed`
with its actual database/setup, export the same complete metadata/statistics
and rerun the checker. Independent review remains required before production.

## Rounded public masks without additional download

`native-noise-two-mask-rounded-v1` reports a profile-bound precision in 27..=32
bits for each published mask. Each mask is reconstructed by the client as
`2^(54-t) * round(a / 2^(54-t)) mod q`, with ties upward. The setup hash includes
the precision; use the actual regenerated report for acceptance, not a precision
screen on a different setup.

Let epsilon_0 and epsilon_1 be reconstructed minus original mask coefficients.
They are public and independent of fresh request randomness. Replace the original
collapse-secret matrix S by

    S_rounded = S + Neg(epsilon_0) + Neg(epsilon_1) P_(tau_-1)  (mod q).

The exporter adds these matrices exactly modulo q and centers the resulting
entries before computing norms. Thus the random error is

    H[row] dot e_g + S_rounded[row] dot s + database_column dot e_query.

The same secret coefficients occur in collapse residues and both rounding terms;
they are never treated as independent samples. D.1, query transport, response
transport, sampler-bias handling, finite-distribution Chernoff bounds and the
full-response union factor are unchanged. There is no additional deterministic
mask-rounding budget: its complete contribution is already in S_rounded.
The independent schoolbook oracle checks all rounded norms and the exact phase
change from replacing both masks.

The rounded certificate checker verifies precision, full block coverage,
published-byte count and agreement between the actual weights and the selected
precision's exported weights. As before, reports are trusted local exports, not
proofs supplied by an untrusted server. The reference no-extra-download budget
is the existing one-mask u64 wire encoding: 36 + 8*cols bytes. RNP3 uses
36 + ceil(2*cols*t/8) bytes. It is not compared against a separately optimized
54-bit lossless single-mask encoding.
