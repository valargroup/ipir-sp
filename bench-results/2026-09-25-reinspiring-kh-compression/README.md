# Final-key bandwidth reduction at p=2^16

Implemented opt-in reduced-precision transmission of the two K_h bodies,
retaining the existing two base-2^19 limbs and full-precision K_g. The request
uses RNQ2 and binds its precision to the setup. RNQ1 and the default profile
remain unchanged. Independent gadgets are investigated by the offline analysis;
one-limb gadgets are not enabled in the runtime.

For this recorded benchmark snapshot, **46 bits is the smallest screened
precision meeting the hard 2^-78 full-response correctness target**. Its
own regenerated setup gives a conditional bound of 2^-112. **47 bits** is the
smallest screened precision meeting the preferred 2^-128 target, with a bound
of 2^-260 on its regenerated setup. These are conservative upper bounds, not
measured failure rates. A new application snapshot needs its own certificate.
The native profile still requires independent cryptographic review before
production activation.

## Recorded results

d=2048, q=2^54, p=2^16, Gaussian sampler nominal sigma=6.4, 28,672 rows,
32,768 columns (16 packing blocks), full-range u16 benchmark database.

| K_h bits | Key bytes | Complete request bytes | Key saving | Full-request saving | Conditional full-response failure bound |
|---|---:|---:|---:|---:|---:|
| 54 (baseline) | 55,296 | 230,948 | — | — | <=2^-405 |
| 48 | 52,224 | 227,876 | 5.56% | 1.33% | <=2^-345 |
| 47 | 51,712 | 227,364 | 6.48% | 1.55% | <=2^-260 |
| 46 | 51,200 | 226,852 | 7.41% | 1.77% | <=2^-112 |

Each row uses its own setup and certificate, not the counterfactual precision
sweep on another setup. The deterministic budget exhausts the decoding radius
at 45 bits and below in the recorded sweeps, so this method does not certify
those precisions. That is not a proof that every tighter analysis must fail.

All four profiles decoded correctly for three warmups and 30 measured queries
each, cycling first, middle and last rows. The maximum measured phase errors
were 15,957,899,846 (54 bits), 15,025,229,622 (48), 14,016,809,915 (47) and
15,903,743,898 (46), compared with radius 137,438,953,472. These measurements
validate implementation behavior; they do not establish the tail bounds.
Response size remained 90,180 bytes.

`e2e-*.jsonl` retain timings; `summary.json` contains medians and other metrics.
The runs overlapped local builds/tests and are **not controlled performance
comparisons**. No runtime improvement is claimed from these measurements.

## Why the one-limb proposal is not selected

The analysis evaluates retained widths 25–29 with discarded widths 29–25 on
the actual pre-final mask. It combines the candidate residue with the existing
collapse residues on the same secret coefficients. None meets 2^-78. The best
recorded candidate (27/27) only obtains a conservative full-response bound of
2^-18 from this checker. Failure to certify is not an estimate of the actual
failure rate, nor a proof of impossibility for all alternative gadgets.

Changing gadget widths without removing limbs does not save full-precision key
bytes. The implemented reduction instead rounds the uploaded K_h ciphertexts.
Their added error is bounded deterministically using actual final-digit L1
norms; no independent rounding-noise assumption is made.

## Certificate and security scope

See [the full argument](../../reinspiring/tools/security/NATIVE_CERTIFICATE.md).
The exporter combines weights on original K_g errors and secret coefficients;
the checker uses the actual finite CDF distribution, exact rational arithmetic,
upward exponential bounds and a union bound across all 32,768 coefficients.
It also reserves deterministic budgets for D.1, query rounding, response
rounding and K_h transport. The original-error independence assumption is the
usual idealization of fresh cryptographic PRNG draws.

The JSON reports contain the actual database digest, setup ID and sampler
counts. They are local evidence, not authenticated proofs. Verify the sampler
counts on the target build/platform, and do not transfer these certificates
to a different database, seed, shape, sampler or profile.

The change sends a deterministic function of the original key ciphertexts.
Any distinguisher of this compressed upload could be applied to the original
upload followed by that same rounding. Therefore this transport change does
not itself introduce an additional disclosure beyond the underlying profile;
it does not establish that profile's unresolved KDM-RLWE security assumptions.
No cryptographic production activation or default change was performed.

## Reproduction and usage

Host: Apple M4 Max, Mac16,6, 128 GiB RAM, Darwin arm64. Rust 1.89.0;
eight Rayon workers. Database seed 0x2417, query-test seed 0x2418, setup seed
`[7;32]`, benchmark snapshot identifier `[19;32]`. These are public test seeds.

```rust
let profile = NativeProfile::new(pack, rows, cols)?.with_kh_bits(46)?;
```

The option is experimental and does not enforce a certificate automatically.
Choose 47 for the preferred target on this benchmark snapshot. For application
use, run `NativeServer::build_analyzed` on the actual snapshot first.

```sh
for bits in 54 48 47 46; do
  RAYON_NUM_THREADS=8 cargo run --release -p ipir-sp \
    --features native-reinspiring --example native_noise -- 28672 32768 "$bits" > "noise-$bits.json"
  python3 reinspiring/tools/security/certify_native.py "noise-$bits.json" > "certificate-$bits.json"
  RAYON_NUM_THREADS=8 BENCH_THREADS=8 cargo run --release -p ipir-sp \
    --features native-reinspiring --example native_e2e -- 28672 32768 16 2 30 1 "$bits" > "e2e-$bits.jsonl"
done
```

The checker exits unsuccessfully when the *actual* profile misses
`--require-bits` (default 78). For example, `noise-46.json --require-bits 128`
is rejected. The precision sweep alone must not be used as the acceptance
result for a newly derived setup.

## Validation

- Reinspiring and IPIR-SP release test suites pass; the existing ignored
  degree-2048 research test is complemented by the full-size end-to-end runs.
- Independent Python oracle checks compiled original-noise weights, residue
  signs, one-limb counterfactuals and rounded-key ciphertexts.
- Tests cover modular rounding ties and boundaries, legacy encoding, malformed
  RNQ2 padding/length/version, setup/precision mismatches, and mapped/owned and
  prepared/unprepared packing with rounded keys.
- Rational-checker tests cover upward rounding, biased finite distributions,
  full-response union factors, recorded certificate values and negative gates.
- Native wire fuzzing exercised both RNQ1 and RNQ2: 20,889 inputs in 31 seconds,
  no crash. Scalar/SIMD differential tests pass on available dispatch paths;
  this arm64 host does not execute x86 AVX paths.
- Clippy with warnings denied and formatting checks pass. The fuzz lockfile
  was refreshed to the workspace's existing package versions/dependencies.
