# Upload reduction with no additional download

The native two-mask profile can halve packing-key upload while keeping snapshot
download at or below the current single-mask download. Public masks use a new
rounded, bit-packed RNP3 encoding. This is opt-in experimental native cryptography;
it does not approve the underlying native profile for production.

## Validated bandwidth and correctness

Full-size fixture: d=2048, q=2^54, p=2^16, two base-2^19 K_g limbs, Gaussian
sampler nominal sigma 6.4, 28,672 rows, 32,768 columns, 16 output blocks.
Each actual profile below was regenerated with its own precision-bound setup.

| Route | Key upload | Complete request | Published snapshot | Response | Conditional full-response failure bound |
| --- | ---: | ---: | ---: | ---: | ---: |
| Current one mask, full keys | 55,296 B | 230,948 B | 262,180 B | 90,180 B | <=2^-405 |
| One mask, 47-bit K_h | 51,712 B | 227,364 B | 262,180 B | 90,180 B | <=2^-260 |
| Two masks, 32 bits each | 27,648 B | 203,300 B | 262,180 B | 90,180 B | <=2^-375 |
| Two masks, 29 bits each | 27,648 B | 203,300 B | 237,604 B | 90,180 B | <=2^-228 |
| Two masks, 28 bits each | 27,648 B | 203,300 B | 229,412 B | 90,180 B | <=2^-82: rejected |

Both accepted two-mask routes save **50% of key upload** and **11.97% of complete
request upload**. The 29-bit route additionally reduces snapshot download by
24,576 bytes (9.37% including the header). No extra-query download or cold-start
snapshot download is needed. The 47-bit K_h route remains a validated smaller
change, but saves only 6.48% of key upload and misses the 20% objective.

The reference snapshot format is the current one-mask **64-bit coefficient
encoding**. A hypothetical exact 54-bit single-mask encoding would take 221,220
bytes; the accepted two-mask routes are not smaller than that separately
optimized baseline. The 27-bit/two-mask counterfactual matches 221,220 bytes but
only certifies 2^-12 on the 32-bit setup and is not selected.

29 bits is the smallest screened precision passing the 2^-128 target and was
confirmed on its own regenerated setup. 32 bits offers a larger correctness
margin at exactly the existing snapshot download size. A new application snapshot
needs its own analysis; these are conditional upper bounds, not measured failure
rates or certificates for arbitrary data.

## Why the noise accounting is valid

For published masks a_0, a_1 and their rounded reconstructions, the extra error is

    (rounded(a_0)-a_0)*s + (rounded(a_1)-a_1)*tau_-1(s).

Both residual polynomials are public. The exporter adds their negacyclic matrices
and secret automorphism to the existing matrix on the original secret variables,
then centers the combined matrix modulo q before computing norms. It never
assumes independent secret coefficients for repeated occurrences of the same
variable, nor independent random rounding errors. The original finite-sampler
Chernoff calculation and full-response union bound then apply unchanged.
See [the argument](../../reinspiring/tools/security/NATIVE_CERTIFICATE.md).

`noise-*.json` contains all 16 blocks, the database digest, setup ID, sampler
counts, actual selected weights and precision screens. `certificate-*.json`
contains actual-profile results. `precision-screen.json` is a counterfactual
screen on the 32-bit setup; its other rows are not acceptance certificates.
The 28-bit checker invocation deliberately exits with failure at --require-bits
128. These files are trusted local evidence, not authenticated server proofs.

## API and wire behavior

```rust
let profile = NativeProfile::new(pack, rows, cols)?
    .with_two_mask_output()?
    .with_published_mask_bits(29)?; // use 32 for the larger recorded margin
```

The public-mask precision is included in setup derivation. RNP3 retains the
36-byte header and packs first-mask then second-mask coefficients, rounding to
nearest with ties upward modulo q. The client reconstructs multiples of
2^(54-bits). Mode, precision, setup, length and unused-padding-bit mismatches are
rejected. Server in-memory publication and parsed publication agree exactly.
Prepared decoding binds the actual mask bytes and works for both precisions.

The extra in-memory public transforms still exist: 1,048,576 coefficient bytes
versus 524,288 for prepared one-mask decoding. Request-local secret mask products
are 262,144 bytes for either mode and are erased on drop. Context/allocator
storage is additional. All per-request preparation is charged to client generation.

## Reproduction

Public fixture seeds: database 0x2417; setup [7;32]; snapshot [19;32].

```sh
cargo build --release -p ipir-sp --features native-reinspiring --examples
RAYON_NUM_THREADS=8 target/release/examples/native_noise 28672 32768 54 32 --two-mask > noise-32.json
RAYON_NUM_THREADS=8 target/release/examples/native_noise 28672 32768 54 29 --two-mask > noise-29.json
RAYON_NUM_THREADS=8 target/release/examples/native_noise 28672 32768 54 28 --two-mask > noise-28.json
python3 reinspiring/tools/security/certify_native.py noise-32.json --require-bits 128
python3 reinspiring/tools/security/certify_native.py noise-29.json --require-bits 128
# Deliberately rejected:
python3 reinspiring/tools/security/certify_native.py noise-28.json --require-bits 128
RAYON_NUM_THREADS=8 target/release/examples/native_compare 30 29
RAYON_NUM_THREADS=8 target/release/examples/native_compare 30 32
python3 -m unittest discover -s reinspiring/tools/security
```

`native_compare` alternates mode order per query, uses three warmups and 30 measured
queries per mode, includes request preparation in generation for both modes,
parses the actual published wire data, and verifies both prepared and original
decoding against the database. The baseline is the equally optimized full-key
single-mask mode. `native_e2e` also accepts public-mask bits as its eighth argument
and measures cold preparation/decoding.

## Validation

- Both crates' release test suites pass; existing production profiles retain
  their wire formats and behavior.
- The independent Python schoolbook oracle agrees with all six rounded-mask
  weight matrices' norm envelopes and the exact change to the decrypted phase.
- Tests cover rounding ties and modular endpoints, all 27..32-bit publications,
  exact byte counts, wire roundtrips, wrong setup/mode, truncated/extended input,
  noncanonical padding, prepared and original decoding, and actual analysis
  selecting the matching rounded-mask weights.
- The certificate tests freeze both accepted bounds, reject 28 bits at the
  selected target, and reject format/precision/size/weight mismatches.
- Extended wire fuzzing includes 29- and 32-bit modes and mutations of valid
  public-mask payloads: 7,812 executions in 31 seconds, no crash.
- Clippy with warnings denied and formatting checks pass. Native KDM review and
  a certificate for each served snapshot remain prerequisites for production.

## Performance evidence and remaining gate

Host: Apple M4 Max, 128 GiB RAM, Darwin arm64, Rust 1.89.0, eight Rayon workers.
Each precision had an initial comparison and three retries monitored specifically
during the online phase. All attempts are retained and included in `aggregate.json`:
120 measured requests per mode per precision, with repeated deterministic fixture
seeds. No attempts were selected by their timing outcome. Every response decoded
correctly, including the independent original decoder on parsed RNP3 masks.

| Median online metric | One mask in 29-bit comparison | 29-bit two masks | One mask in 32-bit comparison | 32-bit two masks |
| --- | ---: | ---: | ---: | ---: |
| Client generation, including request preparation | 24.130 ms | 22.523 ms | 26.167 ms | 24.273 ms |
| Client decode | 0.23246 ms | 0.23233 ms | 0.24819 ms | 0.24796 ms |
| Server response | 32.729 ms | 32.206 ms | 34.476 ms | 34.001 ms |

Aggregate mean server times are 65.463/61.582 ms for baseline/29-bit and
35.977/34.210 ms for baseline/32-bit. Large background-load outliers affect the
first pair especially; retain these values rather than discarding slow samples.
Observed serial throughput ratios are 1.063 and 1.052, respectively. Both routes
meet the 5% limits in these observed aggregate metrics.

**The strict performance gate is still unverified.** Online monitoring detected
unrelated compiler activity or another process exceeding one CPU core during each
retry. `run_quiet_comparison.py` caps retries at three and selects only by the
observed environment, never by favorable timings. Its attempt files and monitoring
metadata document the limitation. An idle-host repeat is needed before claiming
controlled throughput non-regression. No native production activation occurred.

Maximum measured phase errors were 23,957,864,448 for 29-bit masks and
15,665,725,440 for 32-bit masks, versus a decoding radius of 137,438,953,472.
These measurements validate behavior; the negligible-failure claims come from
the separate conditional certificate, not from the number of successful trials.

The 29-bit route is the smallest tested precision meeting the correctness target
and reduces both upload and snapshot download. The 32-bit route is the more
conservative precision choice when matching the current download size suffices.
Both are ready for independent review and an isolated performance acceptance run.


## Follow-up on review findings

The three selected findings (prepared decoder scratch erasure, certificate CLI
threshold, and exact sampler distribution) have been addressed. See the
[fixes, migration notes, tests and follow-up reviews](review-fixes/README.md).
The original review files are retained as historical findings.
