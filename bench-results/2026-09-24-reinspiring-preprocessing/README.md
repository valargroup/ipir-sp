# Native preprocessing optimization

Target: reduce complete native IPIR-SP preprocessing by at least 3× relative
to PR #17 at `689bceb`, without changing its cryptographic parameters, database
shape, wire formats, output coefficients, or retained packing material.

The workload is 28,672 × 32,768 u16 elements (1.75 GiB), p14, degree 2,048,
q=2^54, two gadget limbs, eight preprocessing workers. Setup includes all
sixteen packing blocks. Final measurements and validation are recorded below.

## Matched Intel results

Dedicated DigitalOcean `g-8vcpu-32gb-intel`, Ubuntu 24.04, ams3, Xeon Gold
6548N, eight vCPUs and 32 GiB RAM. Rust 1.89.0, release builds with
`RUSTFLAGS='-C target-cpu=native'`; separate checkout-local target directories.
Three serial baseline/optimized pairs, with no overlapping build or benchmark
processes. Each run builds a fresh complete snapshot and verifies six full-wire
queries (three warmups plus three recorded samples, selecting first/middle/last
rows). Database generation is outside the setup timer in both versions.

| Complete preprocessing | Before (`689bceb`) | After (`59a09f2`) |
|---|---:|---:|
| Run 1 | 117.724 s | 36.862 s |
| Run 2 | 118.097 s | 36.690 s |
| Run 3 | 117.271 s | 36.655 s |
| **Median** | **117.724 s** | **36.690 s** |
| Retained packing coefficients | 513.25 MiB | 513.25 MiB |
| Median peak process RSS | 2.527 GiB | 2.720 GiB |

**3.209× faster; 68.83% less preprocessing time.** All three matched pairs
exceed 3×. The original 118.343-second result is reproduced by the fresh baseline
to within 1%; the optimized median is below its 39.448-second /3 target.

Peak process memory increases by about 198 MiB because independent trace halves
and gadget-limb compilation now overlap. Output blocks remain sequential, and
no new transforms survive setup: retained database and packing storage are
unchanged. Timings include validation, hint construction, mask aggregation,
packing compilation, and the existing database-layout conversion.

Every recorded row decoded correctly. All nine recorded phase-error values,
upload sizes and download sizes match the baseline exactly. The arithmetic
changes preserve the complete packing computation; the independent Python
integer oracle also compares both ciphertext rows coefficient-for-coefficient.
This is not a new cryptographic parameter choice or a noise/precision tradeoff.

Main's previously measured InspiRING setup was 9.523 seconds. Native setup is
therefore still approximately 3.85× slower than that historical main result,
down from approximately 12.4×. This change meets the requested 3× improvement
target; it does not claim preprocessing parity with InspiRING.

## Additional Apple validation

On an Apple M4 Max with eight Rayon workers, three clean before/after repeats
had medians of 70.909 and 19.854 seconds (**3.57×**). The initial exploratory
baseline overlapped build/profiling activity and is excluded from these results.
The Mac has more timing variation, so the dedicated Intel result is primary.
Full-size p16 runs with two and three limbs also decoded correctly; their
recorded phase errors match the prior retained p16 measurements exactly.

## Changes

1. Cache auxiliary NTT transforms of the public query masks once per database
   setup. Previously, each of 32,768 columns transformed the same fourteen masks
   again and reconstructed each product separately.
2. Accumulate the fourteen products in the auxiliary NTT rings, then apply one
   inverse transform and signed CRT reconstruction per prime and column. Select
   two or three primes from a checked bound for the **entire sum**. At this
   workload, hint construction drops from 126 transforms per column
   (14 products × 3 primes × 3 transforms) to 30 (2 primes × 15 transforms),
   plus only one CRT reconstruction per column instead of fourteen.
3. Reuse the public packing-mask transforms along each key-switching trace.
   The identity `ds * tau(w) = tau(tau^-1(ds) * w)` moves the varying automorphism
   onto the small public digits. The gadget decomposition itself is unchanged.
4. Execute the two independent trace halves concurrently, preserving left/right
   digit order; compile independent gadget-limb matrices concurrently. Database
   output blocks remain sequential to bound scratch storage.

## Exactness and security scope

For public left polynomials with centered coefficient maxima A_i and a checked
right coefficient bound B, each integer coefficient of the dot product has
absolute value at most `d * B * sum(A_i)`. The chosen auxiliary-prime product
must be strictly greater than twice that quantity. Every right operand is
validated against B. Checked arithmetic rejects overflow or insufficient CRT
capacity. Signed reconstruction occurs before reduction modulo q.

This bound is deliberately different from the existing per-product bound:
reusing a single-product capacity check for an accumulated sum is unsound.
Tests include a dense sum that actually crosses the two-prime signed range,
forcing three-prime reconstruction, as well as negative endpoints, malformed
operands, mismatched contexts and insufficient total capacity.

All transformed and inspected values in the new API are public preprocessing
material. The online secret/key-generation paths are unchanged. The native
profile remains experimental; this optimization does not change its security
claims or close the independent-review gates in `reinspiring/SECURITY.md`.

## Reproduction

`run.sh BASELINE_CHECKOUT OPTIMIZED_CHECKOUT OUTPUT_DIRECTORY` builds each
checkout in a separate target directory, then runs three serial before/after
pairs with correctness checks. It records toolchains, source revisions, build
flags, wall times and peak process memory. Avoid simultaneous builds or other
benchmarks while measuring.

## Validation and provenance

- Algorithm commit: `59a09f20ed153b6e16ff40953bbc1e6b188a0a07`; baseline:
  `689bcebd5335eeb14b89032c20e60c379f244d40`. The remote source patch was
  byte-identical to the committed diff (SHA-256 recorded in `metadata.json`).
- Linux: 203 release tests and 203 debug tests passed, with two default ignores;
  the native degree-2048 test was run explicitly and passed for both samplers
  and both limb counts. Clippy, rustdoc, formatting, all-target checking and
  both workflow benchmark builds passed.
- Mac: 103 tests passed for the changed crates, plus the strengthened capacity
  test and explicit degree-2048 test; Clippy, rustdoc and formatting passed.
- New boundary tests cover a sum that crosses the two-prime signed range,
  negative reconstruction, odd and power-of-two q, incorrect bounds, malformed
  shapes, noncanonical operands, mismatched contexts and insufficient capacity.
- All 27 remote result/log files were downloaded and SHA-256 verified.
- GitHub's self-hosted Rust jobs remain queued, including jobs from earlier
  commits. The checks above were executed directly on the dedicated host;
  they are not presented as green GitHub check results.

`linux-summary.json` and `mac-summary.json` contain exact timings and memory
measurements. `raw/` retains samples, process-memory reports, source/toolchain
metadata and validation logs. The temporary host was deleted after collection;
its identity and cleanup verification are recorded in `metadata.json`.
