# ReinspiRING refresh and benchmark — 2026-09-24

**Historical initial run.** See the [performance follow-up](../2026-09-24-reinspiring-perf/REPORT.md)
for the subsequently optimized implementation and controlled CPU-targeted comparisons.

The native power-of-two implementation is complete as an **experimental** packing
and IPIR-SP backend. On the benchmark host, its two-limb configuration reduced
the 14-bit IPIR-SP server median from 80.461 ms to 71.162 ms (11.6%) at eight
workers. It did not improve the complete local client/server/decode path:
111.912 ms became 120.643 ms. Offline setup increased from 10.495 s to 125.759 s.
Do not activate this profile in production until the cryptographic review and
correctness-certificate gates below are met.

## Scope and provenance

- Refreshed PR #17, originally `8f6b6c2907dc43268c8fd17dc1d29f4ed59b4a6a`,
  by merging main `611a29284264d844bf4dba00de2874c5b762f8c2`.
- Implementation: `8719787`; final arithmetic/lifecycle revision:
  `085d7184238f0beb45e012ff24c59f9c3d17be61`.
- Main benchmark uses a separate checkout of the pinned main commit with only
  the self-contained `inspiring_e2e.rs` measurement harness copied into it.
  Its library implementation is unchanged. No upstream InspiRING codebase was
  separately benchmarked.
- Final standalone packing measurements and `native-p14-final-t8.jsonl` use
  `085d718`. Native scaling and 16-bit measurements use `8719787`; the subsequent
  revision compacts the odd-modulus adapter, adds secret zeroization, and hardens
  boundary handling. It does not change the native power-of-two arithmetic
  schedule. Both revisions' 14-bit results are retained, not silently pooled.
- This is packing plus IPIR-SP, not an implementation or benchmark of the whole
  ReinsPIRe protocol. Gaussian is the integrated profile. Ternary is research-only.

## Implementation gaps closed

The old cubic compiler is replaced by an O(d² log d) ring FFT, including arbitrary
valid odd exponents. Native preprocessing performs Appendix D.2 aggregation in
wide integer arithmetic before Appendix D.1 division. Approximate signed gadget
decomposition, key generation, leftover encryption, and decoding now run as one
complete protocol. Exact three-prime NTT/CRT replaces the infeasible single-prime
lift and quadratic fallback. Signed compact matrices and runtime AVX2 kernels
have scalar differential coverage. The odd-q adapter still produces exact
current-InspiRING outputs, with its own measured performance below.

The integrated backend has private validated parameter/state types, fresh
OS-seeded requests by default, fixed-length versioned transport, canonical
padding checks, setup/profile/snapshot/request binding, and concurrent immutable
server use. Public hashes check consistency, not authentication. Production
profile APIs/defaults remain unchanged; opt-in requires `native-reinspiring`.
See [SPEC](../../reinspiring/SPEC.md) and
[SECURITY](../../reinspiring/SECURITY.md) for contracts and limitations.

## Method

Dedicated temporary DigitalOcean general-purpose Intel droplet, eight vCPUs,
32 GiB RAM, Ubuntu 24.04, ams3. Guest CPU: Intel Xeon Gold 6548N, one hardware
thread per exposed core, AVX2 and AVX-512 available. These kernels dispatch AVX2;
they do not implement the paper's AVX-512 Highway kernels. Rust 1.89.0 release
builds. Full CPU/toolchain/binary identifiers are in
[raw/host-and-binaries.txt](raw/host-and-binaries.txt).

IPIR-SP database: 28,672 rows × 32,768 columns, u16 storage (1.75 GiB), fixed
ChaCha20 data seed `0x2417`, uniform values in the selected plaintext domain.
Each query retrieves and verifies a complete row, cycling first/middle/last.
Requests use fresh keys: native harness uses a reproducible RNG stream, main
uses OS-seeded keys. Benchmarks never log private keys. This is a synthetic
snapshot, not a certificate for a production snapshot.

Each configuration has three warmups and 30 measured end-to-end requests;
standalone packing has five warmups and 30 measurements. Correctness checks and
known-message noise measurements are outside timed decoding. Setup uses eight
workers for all IPIR-SP runs; online scaling uses the stated pool size. No
network transfer/RTT is measured. Wire sizes are actual serialized bytes.
Standalone full-pack and component timings are separate loops, so their medians
need not add. Bootstrap intervals describe within-run sample variation only,
not cross-host reproducibility or guaranteed latency. Raw samples, time/RSS
records, intermediate optimization runs, and [summary.json](summary.json) are
retained. Run [run.sh](run.sh), then [summarize.py](summarize.py), to reproduce.

## IPIR-SP results

Eight workers; medians in milliseconds. Local path is the median of each sample's
client generation + server + decode time, with no network latency.

| Profile | Server | Client generation | Decode | Local path | Upload B | Download B | Offline s |
|---|---:|---:|---:|---:|---:|---:|---:|
| Main p14 | 80.461 | 27.749 | 3.699 | 111.912 | 236,544 | 81,920 | 10.495 |
| Native p14, two limbs, final source | 71.162 | 35.503 | 14.021 | 120.643 | 230,948 | 81,988 | 125.759 |
| Main p16 query-q46 | 81.141 | 27.807 | 3.702 | 112.641 | 250,880 | 81,920 | 10.197 |
| Main p16 query-q48 | 81.352 | 27.780 | 3.700 | 112.879 | 258,048 | 81,920 | 10.284 |
| Main p16 query-q49 | 81.694 | 27.848 | 3.703 | 113.242 | 261,632 | 81,920 | 10.314 |
| Native p16, two limbs | 71.978 | 35.287 | 14.093 | 121.396 | 230,948 | 90,180 | 125.339 |
| Native p16, three limbs | 79.941 | 38.690 | 14.056 | 132.793 | 258,596 | 90,180 | 154.017 |

The q46/q48/q49 labels identify main's **query transport precision**, not its
packing modulus. Native uses q=2^54, query precision 49, response precision
pbits+6. Main's packing q is approximately 2^56. These are different cryptographic
profiles; speed alone does not establish equivalent security/correctness.

For p14, final server median bootstrap 95% intervals are main [80.347,80.631] ms
and native [70.687,71.411] ms. Server stages explain the result: packing falls
from 36.477 to 17.018 ms, while database multiplication rises from 41.448 to
51.995 ms. Total wire bytes fall 1.74%, from 318,464 to 312,936. Published setup
grows from 229,376 to 262,180 bytes. Peak process RSS is about 5.76 GiB for main
and 2.53 GiB for native two limbs; this is process peak including construction,
not a measurement of steady-state serving memory. Native retains 537,657,344
coefficient bytes with two limbs and 806,354,944 with three limbs.

Online scaling, measured in one run per backend:

| Workers | Main p14 server ms | Native p14 two-limb server ms |
|---:|---:|---:|
| 1 | 392.394 | 368.901 |
| 2 | 199.798 | 191.344 |
| 4 | 102.196 | 97.820 |
| 8 | 80.461 | 70.471 |

The separate final-source eight-worker native repeat was 71.162 ms; an earlier
repeat was 72.517 ms. Do not interpret narrow within-run intervals as eliminating
that variation. Offline native hint construction remains an optimization
opportunity: it does not cache all transformed public operands and deliberately
builds blocks sequentially to bound peak memory.

## Standalone packing and paper comparison

d=2048, base 2^19. Main/odd adapter use the current main odd modulus and three
limbs. Native uses q=2^54 and Gaussian sigma 6.4. Timings in milliseconds:

| Operation | 1 worker | 8 workers |
|---|---:|---:|
| Current main InspiRING, full pack | 10.148 | 2.495 |
| Exact odd-q ReinspiRING adapter, full pack | 19.385 | 5.960 |
| Native two limbs, H′y | 3.409 | 0.646 |
| Native two limbs, leftover | 1.214 | 1.214 |
| Native two limbs, full pack | 5.329 | 1.910 |
| Native three limbs, H′y | 5.642 | 0.980 |
| Native three limbs, leftover | 1.804 | 1.809 |
| Native three limbs, full pack | 7.619 | 2.922 |

The exact odd-q adapter is slower than current main and is not a performance
replacement. Its final compact implementation improves on earlier retained runs
(26.078/15.383 ms at one/eight workers). Final native standalone preprocessing
at one worker is 4.163 s (two limbs) and 6.055 s (three). Retained coefficients
including the leftover c1 are 33,603,584 and 50,397,184 bytes respectively. The
odd compiled matrix alone is 50,331,648 bytes; its 1.900 s compilation follows
1.210 s of InspiRING preprocessing.

[ReinsPIRe, ePrint 2026/1934](https://eprint.iacr.org/2026/1934), Table 5,
reports the following single-thread packing components at d=2048, q=2^54,
base 2^19. The original PR confused the H′y and leftover columns; 1.2 ms is
the **leftover**, not matrix multiplication.

| Limbs | Paper preprocessing s | Here, 1 worker s | Paper H′y ms | Here ms | Paper leftover ms | Here ms |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 3.9 | 4.163 | 13.6 | 3.409 | 1.2 | 1.214 |
| 3 | 6.0 | 6.055 | 20.6 | 5.642 | 1.8 | 1.804 |

These are descriptive comparisons, not controlled speedup claims: paper CPU is
an Intel Xeon at 2.6 GHz, implementation is C++/Highway/AVX-512, and this is a
different CPU/compiler/layout. The implementation now matches the intended
O(ell*d²*log d) preprocessing and ell*d² + O(ell*d*log d) packing structure.
The paper's coefficient storage bound is ell*d²*(log2(d*z)+1) bits; signed i32
storage at these parameters realizes 32 MiB for two limbs and 48 MiB for three,
before small auxiliary data. Wider coefficients use an exact i64 fallback.

[InsPIRe, ePrint 2025/1352](https://eprint.iacr.org/2025/1352), Table 5,
reports 36 s offline and 40 ms online for **4096 LWEs**, with d=2048, q≈2^56,
p=2^15, three limbs, base 2^19, 84 KB keys and 33.4-bit noise. That benchmark
produces two degree-2048 outputs. Dividing by two gives 18 s/20 ms per output
only as a normalization, not a rerun. Our current-main one-output measurement
is 1.210 s/10.148 ms on this host. Different code, parameters and hardware
prevent attributing the difference to one algorithm. Whole-protocol paper PIR
throughput is not comparable to this IPIR-SP workload.

## Correctness, security and readiness

All timed end-to-end requests recovered their expected rows. Largest measured
p14 centered errors were 60,904,727,770 (main) and 20,058,078,578 (final native).
Native p16 maxima were 15,957,899,846 (two limbs) and 15,581,724,467 (three).
These are sample maxima, not probabilistic failure bounds.

Validation includes 199 passing debug all-feature tests and 196 passing Linux
release tests (two intentionally ignored defaults in each), explicit
degree-2048 tests for both samplers and limb choices, an independent Python
integer/schoolbook oracle, FFT-versus-naive tests, CRT-versus-schoolbook tests,
odd-q exact equivalence, scalar/SIMD differentials, malformed and cross-request
transport tests, and concurrent query tests. Formatting, warnings-as-errors
Clippy and rustdoc pass. The final native wire fuzz smoke run completed 67,977
executions in 61 seconds without a crash (in addition to an earlier 66,040-run
smoke test). This is bounded fuzz coverage, not a completed audit. Evidence is
under `raw/`.

Pinned lattice-estimator `53da5982597709ba0fdf94ea37a84d822310fd84`, Sage 10.9:

| Profile | Minimum MATZOV log2 work | Minimum ADPS16 core-SVP log2 work |
|---|---:|---:|
| Main Gaussian q≈2^56 | 131.219 | 103.368 |
| Native Gaussian q=2^54, two limbs | 136.829 | 109.500 |
| Native ternary q=2^54, two limbs | 128.789 | 100.355 |

These are generic scalar-LWE diagnostics across primal uSVP/BDD and dual/hybrid,
granting unrounded query bodies. They are not proofs for structured KDM-RLWE,
exhaustive attack searches, or interchangeable cost models. The ternary profile
has little MATZOV margin. See raw estimates and SECURITY.md for assumptions.

Remaining production release gates:

1. Independent cryptographic review of native power-of-two/KDM composition,
   sampling and approximate decomposition. The runbook requires a second
   reviewer for key-material changes; self-testing cannot discharge that gate.
2. Reviewed general failure bound or conservative per-snapshot certificate.
   The two-limb deterministic decomposition bound exceeds the decoding interval.
   Original key errors are reused under automorphisms; an independence heuristic
   is not a certificate. Three limbs remove truncation error, but not every other
   error source. Existing main snapshot certificates cannot be reused.
3. Client CRT/conversion constant-time audit if local timing/cache attackers are
   in scope. Transport is not malicious-server authentication or verifiable PIR.

Thus the code is ready for independent review and further experiments, not a
production-default switch. No production service or snapshot was modified.

## Artifact integrity and host cleanup

All 47 remote result files were copied and verified byte-for-byte against remote
SHA-256 hashes before deleting temporary droplet 603281659. Its absence was
verified in DigitalOcean. `REMOTE-SHA256SUMS` preserves original remote filenames;
`.log` files are stored locally as `.txt`. `SHA256SUMS` covers all local raw
artifacts. Metadata records source revisions, validation and cleanup.
