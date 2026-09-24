# ReinspiRING performance follow-up — 2026-09-24

**Preprocessing update:** The [subsequent preprocessing report](../2026-09-24-reinspiring-preprocessing/README.md)
measures a 3.21× reduction, from 117.72 to 36.69 seconds, on the same hardware
profile and workload. It supersedes this report's native offline setup times;
the online measurements below remain historical results for the stated commits.

The earlier native backend already used the paper's hardware-friendly **q=2^54**.
The gap was in the implementation: AVX2-only matrix kernels, repeated general
three-prime leftover products, and a database scan that did not exploit byte dot
products. These are now fixed without changing the cryptographic parameters or
query precision.

With identical CPU-targeted builds, native two-limb standalone packing is more
than **2× faster than current main**. The complete eight-worker IPIR-SP server
response improves from **82.259 ms to 48.379 ms (1.70×)** in the retained-source repeat.
The database scan and packing stages both improve. This does not establish a
2× total IPIR-SP speedup; the paper's headline compares the complete ReinsPIRe
protocol against its InsPIRe baseline, not this different composition.

## Changes and root causes

1. **Use the available SIMD width.** Native signed matrices now dispatch to an
   AVX-512 kernel with four accumulators, while keeping AVX2/scalar fallbacks.
   Products wrap modulo 2^64, then mask to q=2^54; because q divides 2^64 this is
   exact. No prime reduction occurs inside the matrix dot-product loop.
2. **Move public leftover work offline.** Cache left-hand NTT transforms. Use
   two auxiliary primes only if their product exceeds
   `2*d*max_abs(public_operand)*floor(q/2)`. Otherwise retain three. Reconstruct
   each limb separately before reducing and summing. This is an exact capacity
   check based on public data, not an approximation or secret-dependent choice.
3. **Exploit native arithmetic in the database scan.** Decompose the uploaded
   query into signed radix-256 digits. Store the u16 database in 16-column tiles
   with separate low/high byte planes, then use AVX-512 VNNI byte dot products.
   A window contains at most 65,536 products of magnitude 255*128 per lane, below
   2^31. Recombination is exact modulo q. Database storage remains two bytes per
   element, and the layout conversion is offline. Unsupported CPUs and shapes
   use exact fallback kernels.
4. **Check build fairness.** Spiral's NTT SIMD selection is compile-time. Both
   primary comparison builds use `RUSTFLAGS='-C target-cpu=native'`. Main's p14
   server median was 85.753 ms in its ordinary release build and 82.259 ms in its
   CPU-targeted build; the reported gain uses the stronger baseline.

A small row-tile scan was slower and was removed. Splitting the native matrix
multiply into signed 32-bit products also failed to improve timings and was
removed. Their raw exploratory measurements are preserved. An early attempted
shared Cargo target directory reused an old example binary; those mislabeled
"after" measurements are explicitly discarded, not counted as improvements.
Final builds use separate checkout-local target directories and recorded hashes.

## Controlled workload and provenance

- Current main: `611a29284264d844bf4dba00de2874c5b762f8c2`, verified still current.
- Optimized algorithm: `c13b051`. Retained source: `2e19774`; subsequent changes
  are documentation, stronger boundary vectors and a scalar-loop lint fix.
  The hot SIMD and packing algorithms are the same. `retained-*` files repeat
  the p14 and standalone measurements from the retained source.
- Dedicated DigitalOcean `g-8vcpu-32gb-intel`, Ubuntu 24.04, ams3; Xeon Gold
  6548N guest CPU with AVX-512/VNNI. Rust 1.89.0, release mode. No simultaneous
  benchmark or build processes during timed runs.
- 28,672 × 32,768 u16 database: 1.75 GiB resident storage; p14 logical data is
  1.53125 GiB. Fixed synthetic data seed, fresh per-request keys, first/middle/last
  rows verified through complete serialization and decoding. Same dimensions,
  plaintext domain and output for each matched pair.
- Three warmups and 30 samples per IPIR-SP configuration; five warmups and 30
  samples for standalone packing. Reported times are medians, with complete
  distributions in `summary.json`. Network transfer is excluded. Setup always
  uses eight workers; online pools use the stated worker count.

## Complete IPIR-SP results

Eight workers, CPU-targeted builds; milliseconds except offline setup.
The local path is the median of client generation + server + decoding per sample.

| Profile | DB scan | Packing | Server | Local path | Offline s |
|---|---:|---:|---:|---:|---:|
| Main p14 | 45.909 | 33.894 | 82.259 | 113.334 | 9.523 |
| Native p14, two limbs, repeat | 34.303 | 12.253 | 48.379 | 96.125 | 118.343 |
| Main p16 query-q46 | 46.149 | 34.148 | 82.738 | 113.843 | 9.552 |
| Main p16 query-q48 | 46.061 | 34.120 | 82.611 | 113.614 | 9.508 |
| Main p16 query-q49 | 45.847 | 33.878 | 82.097 | 113.047 | 9.525 |
| Native p16, two limbs | 33.907 | 12.167 | 47.988 | 95.715 | 118.299 |
| Native p16, three limbs | 34.317 | 17.783 | 54.117 | 105.630 | 145.709 |

The native p14 packing stage is **2.77× faster** and its database scan is **1.34×
faster** than main. Together they give a 41.2% server-time reduction. The complete
local client/server/decode path improves 15.2%; client arithmetic remains more
expensive than main. Offline setup remains substantially slower. Native wire
sizes and security profiles are unchanged by these optimizations.

| Workers | Main p14 server ms | Native p14 server ms |
|---:|---:|---:|
| 1 | 414.400 | 260.184 |
| 2 | — | 136.447 |
| 4 | — | 78.997 |
| 8 | 82.259 | 48.096 |

An isolated, full-range u16 scan on the retained byte-plane algorithm measured
255.844 → 192.122 ms on one worker and 43.266 → 33.869 ms on eight workers,
compared with the AVX-512 word kernel. The intermediate non-interleaved byte
kernel measured 237.923/39.226 ms. Every output was compared exactly.

A diagnostic that only reads/XORs the same resident bytes took 99.802 ms on one
worker and 24.778 ms on eight. This is an optimistic lower bound for the scan,
not a claim that the native implementation saturates memory bandwidth. The full
response must also read 538,181,632 retained coefficient bytes for two limbs
(807,141,376 for three), perform arithmetic, and serialize. Amdahl's law prevents
translating a 2.8× packing gain directly into a 2.8× complete-response gain.

## Standalone packing and the papers

The retained-source repeat at `2e19774` measured:

| Operation | 1 worker ms | 8 workers ms |
|---|---:|---:|
| Main InspiRING pack | 9.773 | 2.333 |
| Native two-limb H′y | 1.557 | 0.411 |
| Native two-limb leftover | 0.461 | 0.467 |
| Native two-limb full pack | 2.162 | 0.954 |
| Native three-limb full pack | 4.781 | 1.483 |

Thus native two-limb packing is **4.52× faster on one worker** and **2.44× faster
on eight**, compared with actual main on the same host/build settings. Standalone
matrices can stay in cache; the integrated stage traverses sixteen distinct
matrices, so multiplying a hot single-pack time by sixteen is not a latency model.
The earlier full-matrix run measured 2.129/0.873 ms for native two-limb packing;
the repeat is somewhat slower at eight workers, but both exceed 2× versus their
matched main measurements. One-worker native packing preprocessing was 3.895 s
for two limbs and 5.626 s for three in the repeat.

[ReinsPIRe, ePrint 2026/1934](https://eprint.iacr.org/2026/1934), Table 5,
reports single-thread H′y/leftover times of 13.6/1.2 ms for two limbs and 20.6/1.8 ms
for three. Its 1.2 ms number is not H′y. Its headline 2× result concerns the whole
ReinsPIRe protocol; Table 7's identical-parameter comparison is 304 ms versus
164 ms (1.85×). These are measurements, not a theorem fixing every implementation's
speedup. Its C++/Highway implementation, CPU, caching and complete protocol differ.
Our implementation follows the native-modulus cost structure but this work does
not implement the rest of ReinsPIRe.

[InsPIRe, ePrint 2025/1352](https://eprint.iacr.org/2025/1352), Table 5,
reports 40 ms packing for 4096 LWEs, producing two degree-2048 outputs; halving
that yields a 20 ms per-output normalization. It is not our current-main baseline.
The comparison above uses the actual pinned main implementation rather than
substituting paper numbers for measured baseline performance.

## Validation and limits

All sampled complete queries recovered the expected row. Final validation passed
202 local debug tests and 199 Linux release tests, with two default ignores;
native degree-2048 coverage was run explicitly and passed. Clippy passed on both
architectures with warnings denied, as did rustdoc and formatting. Arithmetic regression
coverage includes independent schoolbook/integer oracles, both sides of the
prepared-CRT capacity boundary, signed multiplication/carry boundaries, vector
and accumulator-window tails, full-range u16 entries, and 16-column layout
conversion. Both Gaussian and ternary packing, two/three limbs, degree 2048,
transport errors and concurrent requests remain covered. Final validation counts
and exact evidence files are recorded in `metadata.json`.

Cryptographic parameters, transport precision and security claims did not change.
This does **not** close the independent-review and correctness-certificate gates
in [SECURITY.md](../../reinspiring/SECURITY.md). In particular, measured successful
queries cannot establish a negligible failure probability for approximate
key switching. The new native backend remains opt-in and experimental.

[run.sh](run.sh) reproduces the controlled comparisons; [summarize.py](summarize.py)
checks complete 30-sample groups and produces distributions with within-run
bootstrap intervals. `SHA256SUMS` covers the retained artifacts. These intervals
are not cross-host guarantees, and the synthetic data is not a production
snapshot certificate.

## Cleanup and integrity

All 81 retained remote result files were checked against remote SHA-256 hashes
before deleting temporary droplet 603294590; its absence was verified. The one
excluded remote file is an exploratory disassembly, reproducible from source.
`REMOTE-SHA256SUMS` uses original remote paths; exploratory and discarded files
were subsequently moved into explicitly labeled local directories.
