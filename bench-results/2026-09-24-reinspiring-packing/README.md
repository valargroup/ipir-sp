# Native packing optimization results

Final implementation: `6c1aabca59ca096a716db2015a78f51ca3efdaac`, based on main `1d8aea3`.
The complete four-row reference measurements below remain available so that
results from different cohorts are not silently pooled. This final supplement
selects eight-row tiles and supersedes their online timings on AVX-512/VBMI.
The preprocessing arithmetic, coefficient format, parameters and wire format
are unchanged by the final tiling refinement.

## Final eight-row refinement

Three paired trials per layout, thirty fresh-key queries per trial, sixteen
blocks, degree 2048, two limbs, eight workers; reversed layout order in the
second repetition. Every fixture and ciphertext digest matches across layouts,
and also matches the four-row reference cohort.

| Run | Four rows | Eight rows | Sixteen rows |
|---|---:|---:|---:|
| 1 | 8.640 ms | 8.057 ms | 8.067 ms |
| 2 | 8.405 ms | 8.074 ms | 8.256 ms |
| 3 | 8.679 ms | 8.388 ms | 8.585 ms |

The median improves **8.640 → 8.074 ms (6.5% lower)**.
Eight rows improved every paired trial; sixteen rows was less consistent.
Single exploratory checks also improved the three-limb fixture
(13.373 → 12.971 ms) and one-block two-limb fixture (0.925 → 0.901 ms).
These secondary checks have one repetition and are not precision estimates.

Final expanded Intel SIMD tests, Clippy, integrated native flow and three
full-wire benchmark runs pass. The full-database shape remains **28,672 × 32,768
u16 elements, 1.75 GiB**. Final medians:

| Measurement | Final eight-row implementation |
|---|---:|
| Complete preprocessing, eight blocks in flight | 18.101 s |
| Packing stage | 7.933 ms |
| Database scan | 34.767 ms |
| Complete server response, sequential stages | 44.773 ms |
| Retained native two-limb coefficients, sixteen blocks | 433.25 MiB |

These are a final validation cohort, not freshly interleaved baseline pairs;
see the four-row section for directly paired preprocessing evidence. First,
middle and last rows recover exactly, with matching baseline phase errors and
wire sizes. Faster final scan timings are run variation, not a scan code change.

The final same-host, single-block hot-path comparison (three runs, thirty
samples each, eight workers) measures actual InspiRING at **2.369 ms**,
native two-limb ReinspiRING at **0.923 ms**
(**2.57× faster**) and native three-limb at
**1.349 ms**. The identical-parameter odd-q ReinspiRING adapter
remains slower at **4.390 ms**. Native uses a different modulus
and decomposition; these are implementation measurements, not a security-equivalence
claim or a reproduction of the complete ReinsPIRe protocol's headline gain.

## Packing material, measured directly

| Coefficient payload | Per degree-2048 output | Sixteen outputs |
|---|---:|---:|
| Actual InspiRING preprocessed output | 95.96875 MiB | 1535.5 MiB |
| Native ReinspiRING, two limbs | 27.07813 MiB | 433.25 MiB |
| Native ReinspiRING, three limbs | 42.10938 MiB | 673.75 MiB |

InspiRING also has **95.953125 MiB of shared top-key image coefficients**, counted
once rather than per output. Counts come from allocated coefficient vector lengths
in `packing_compare`, not peak RSS. The sixteen-output InspiRING figure is the
linear sum of sixteen per-output buffers, not a new full-server allocation sample.
Context tables, object headers, allocator overhead, temporary scratch, database and
other server state are excluded. Native compression uses exact actual coefficient
bounds, not lossy truncation. Parallel setup can raise peak process memory even
while retained material falls.

## Remaining optimization opportunities

The tested low-level candidates are exhausted for this pass, not proven globally
optimal. On the four-row source, matrix work took 7.069 ms versus 6.238 ms for a
read/XOR sweep of its compressed payload. This is an optimistic traffic reference,
not a strict bandwidth lower bound or a prediction for another machine.

Further experiments have different tradeoffs: batching multiple queries could
reuse matrix reads and raise throughput but may add queueing latency; deployment
hardware, thread affinity and NUMA placement need measurements on that hardware;
persisting compiled material could avoid rebuilding unchanged snapshots but needs
versioning and snapshot binding. These are unimplemented candidates, not claimed
wins. The split API already permits packing contributions to overlap the scan,
but transport, authentication, request/block binding and two-machine timings remain
integration work. Do not add scan and packing times when estimating an ideal
parallel critical path; do include final addition and network overhead.

## Final evidence

`summary-final8.json`, `analyze-tiles.py`, `tiles-experiment.sh` and
`run-tiles-final.sh` record the refinement. `harness/tiles-final.patch` is the
kernel/test diff from `abb6a96`; the separate material-count patch affects only
reported buffer counts. All 451 remote source files match commit `6c1aabc`.
`REMOTE-SHA256SUMS` covers 403 collected host artifacts; names under `final/`,
`final27/` and `final8/` map to `raw-final/`, `raw-final27/` and `raw-final8/`.
All other names map to `raw-experiments/`. Frozen binaries were also downloaded
and verified locally; their hashes are archived, not their large executable files.
`completion.json` records source CI links and verified temporary-host cleanup.
Independent review approved the final implementation; the native cryptographic
profile remains experimental with the production gates in SECURITY.md.

---

# Four-row reference measurements

Published implementation: `abb6a96804dbef6f5b14cb4e23f97e6645df5938`, including
main `1d8aea3`. Baseline: `cf6a83c`, with diagnostic-only commit `b308543` and
the archived benchmark harness. Scope is ReinspiRING packing plus its IPIR-SP
integration. This does not implement the complete ReinsPIRe protocol.

## Primary packing result

Sixteen degree-2048 blocks (32,768 output coefficients), q=2^54, p=2^14,
base=2^19, two limbs, Gaussian profile; eight Rayon workers. Packing-only setup
starts from sixteen distinct random public mask matrices. It excludes database
hint construction and is not a benchmark of a database of a specified row count.
Each online sample has freshly generated uploaded keys. Medians below are
medians of three run medians, each with five warmups and thirty measured queries.

| Measurement | Before | Final | Improvement |
|---|---:|---:|---:|
| Packing setup, one block in flight | 21.532 s | 10.160 s | 2.12× |
| Packing setup, eight blocks in flight | 8.340 s | 4.658 s | 1.79× |
| Online packing, eight-block setup fixture | 12.163 ms | 8.418 ms | 1.44× |
| Retained packing coefficients | 513.25 MiB | 433.25 MiB | 15.59% smaller |
| Peak packing-only process RSS, eight blocks in flight | 2.898 GiB | 2.416 GiB | Includes fixtures and scratch |

Moving from the previous serial-block configuration to the explicit eight-block
configuration gives 4.62× lower packing setup time. The same-concurrency
row separates arithmetic improvements from scheduling. The default server
constructor still processes blocks sequentially; concurrent setup is opt-in.
The harness holds all input masks through setup, so process RSS includes that
caller-owned storage. Retained coefficient counts exclude NTT context tables,
allocator overhead, object headers, and the database.

The primary eight-block comparison is three directly interleaved baseline/final
pairs. Serial-block baseline values come from the preceding matched-fixture run
on the same dedicated host; they are not a second set of immediate final pairs.
Raw per-run values and variation are in `summary-final27.json` and `summary.json`.

## Complete database check

The original workload is **28,672 rows × 32,768 columns of u16**, exactly
1,879,048,192 bytes (**1.75 GiB**), with sixteen output packing blocks. Complete
setup includes hint construction, packing compilation, and database layout.
Three new baseline/final pairs each verify first, middle, and last rows through
the complete wire format (three warmups plus three measured queries).

| Complete IPIR-SP measurement | Before | Final |
|---|---:|---:|
| Preprocessing, previous serial / explicit eight-block final | 37.303 s | 18.514 s |
| Packing stage | 12.187 ms | 8.328 ms |
| Database scan | 35.263 ms | 35.489 ms |
| Complete server response | 49.382 ms | 45.824 ms |
| Peak process RSS | 2.720 GiB | 3.284 GiB |

Complete preprocessing improves 2.01× relative to the
previous optimized revision. Against the older 117.724-second preprocessing
measurement in the [preceding report](../2026-09-24-reinspiring-preprocessing/README.md),
the final value is approximately 6.36× faster; that older result
was collected on a different instance of the same hardware class, not in these
fresh pairs. The historically measured main InspiRING full setup was 9.523 s;
that full-database baseline has not been rerun in this packing-focused pass.

A separate check of the final **default serial constructor** took
22.606 s with 2.571 GiB peak RSS
(one run). Concurrent preprocessing therefore remains an explicit throughput /
peak-memory tradeoff, even though retained packing material is smaller.
All matched full-wire phase errors and upload/download sizes are unchanged.

## Separate packing and scan machines

`prepare_keys` prepares uploaded ciphertext bodies once per request;
`prepare_pack` computes H'y and the leftover without a scan result; consuming
`PendingNativePack::finish` adds the matching scan body. For the primary fixture:

| Packing component | Median time |
|---|---:|
| Request key preparation | 0.221 ms |
| Independent packing contribution | 8.093 ms |
| Final addition of scan bodies | 0.103 ms |

Component medians need not add exactly to the total median. With independent
machines, the computational critical path can approach
`max(scan, key preparation + packing contribution) + final addition`, rather
than the sum of scan and packing. This is an architectural implication, **not a
measured two-host latency**. Network, serialization, queueing, and authenticated
request/block dispatch are not implemented or measured by this split API.
The raw scan output for this shape is 256 KiB. A faster scan backend could make
packing the critical stage instead; no GPU/packing-machine comparison is claimed.

## Actual InspiRING and the papers

The same-host `packing_compare` benchmark uses one degree-2048 output, five
warmups and thirty samples per run, repeated three times. It repeats fixed keys
and inputs for hot-path attribution; it is separate from the fresh-key,
many-block benchmark above. Native entries here use the standalone `pack` API.

| Actual implementation | One worker | Eight workers |
|---|---:|---:|
| InspiRING, odd q≈2^56, three limbs | 10.196 ms | 2.345 ms |
| Odd-q ReinspiRING adapter, identical ciphertext parameters | 14.330 ms | 4.418 ms |
| Native ReinspiRING, q=2^54, two limbs | 1.991 ms | 0.942 ms |
| Native ReinspiRING, q=2^54, three limbs | 3.284 ms | 1.379 ms |

Native two-limb packing is 5.12× faster
with one worker and 2.49× faster with eight
than the actual InspiRING implementation in this hot-path benchmark. The odd-q
adapter remains slower. The native comparison changes modulus and decomposition
profile, so it is not an identical-security-parameter speedup claim.

[ReinsPIRe Table 5](https://eprint.iacr.org/2026/1934) reports single-threaded
packing setup / matrix / leftover times of 3.9 s / 13.6 ms / 1.2 ms for two limbs
and 6.0 s / 20.6 ms / 1.8 ms for three. Our final one-worker setup measurements
from the matching attribution harness are
1.389 s and 2.332 s;
matrix times are 1.520 / 2.514 ms,
and standalone leftover times 0.469 / 0.711 ms.
These use a newer Xeon, Rust/Spiral, different caching, and different implementation
choices. Paper numbers are measurements, not a theoretical universal speedup.

[InsPIRe Table 5](https://eprint.iacr.org/2025/1352) reports 40 ms online and 36 s
offline for 4,096 LWEs producing two degree-2,048 outputs in its q≈2^56, p=2^15 profile (our actual-implementation fixture uses p=2^14).
A per-output normalization is 20 ms online / 18 s offline, not a fresh measured
baseline. Both papers report single-threaded Xeon results. The full ReinsPIRe
headline throughput gain concerns its complete protocol, not this IPIR-SP
composition.

The algorithmic cost remains O(ell*d² log d) compilation and O(ell*d²) online
matrix work, plus lifted polynomial products. Optimizations reduce constants,
allocations, transforms, and coefficient traffic. For two limbs, the dense
matrix payload is `2*d*d*27/8 = 27 MiB` per block on this host; the remaining
packing coefficient bytes are the final mask, cached leftover transforms, and
eight padding bytes. Three-limb matrices in the measured fixtures require 28 bits.

## Retained and rejected work

Retained: owned power-of-two FFT compilation, tiled transpose and direct compact
block concatenation; bounded block scheduling; safe i64-to-i128 aggregation;
public trace residue/CRT simplification; request-wide transforms and bounded
full-sum leftover reconstruction; four-row SIMD; exact adaptive 27/28-bit storage;
and the scan-independent packing API. All wider-range and unsupported-CPU
fallbacks remain exact.

The final 27-bit refinement was a separately reviewed three-pair experiment:
two-limb online medians were 8.736 ms with 28 bits and 8.478 ms with adaptive
storage, at about 2% more packing setup time. It saves a further 16 MiB over
sixteen blocks. Its three-limb fixtures retain 28-bit storage.

Rejected: reusable trace scratch changed setup only about 0.2%; 24/26-bit storage
could not represent the observed coefficients; the previously tested split-word
multiply did not beat the native SIMD kernel. Shared uploaded transforms alone
were modest until combined with the full-sum leftover path and matrix kernel.
A read/XOR diagnostic of the original 32-bit payload took about 7.35 ms versus
7.95 ms for the four-row matrix multiplication; this motivated compression.
It is an optimistic traffic reference, not a strict hardware lower bound.

At this four-row checkpoint, no further demonstrated CPU-packing win remained
from the candidates tested so far; the final eight-row supplement records the
subsequent successful refinement. This is not a proof of optimality: different hardware,
request batching, or protocol changes are separate experiments. Reusing the few
setup-mask transforms across blocks cannot remove the thousands of sequential
trace products per block; this pass retains the simpler per-block contexts.

## Validation and reproduction

Final code passed Intel formatting, docs, Clippy, all-feature tests, explicit
release degree-2048 checks, release SIMD tests, and integrated full-wire checks.
The initial implementation also passed bench compilation and independent Python
integer-oracle tests. Mac checks cover portable fallbacks. CUDA hardware tests
inherited from main are explicitly ignored on this CPU host.

`analyze.py` and `analyze-final27.py` reject missing groups, incomplete runs,
failed process statuses, input-hash mismatches, ciphertext-hash mismatches, or
changed matched full-wire phase errors. All four fixture shapes and all thirty
per-shape ciphertext sample hashes match across versions and schedules.
`REVIEW.md` records the required second implementation review and the FFT helper
regression it found and closed. This does not approve the experimental native
cryptographic profile; the existing production activation gates in
[SECURITY.md](../../reinspiring/SECURITY.md) remain unchanged.

Hardware: DigitalOcean dedicated Intel eight vCPU / 32 GiB, ams3, Xeon Gold
6548N, Rust1.89, release `RUSTFLAGS='-C target-cpu=native'`. Build/test processes
and timed workloads ran serially. `metadata.json`, frozen binary hashes,
source verification, raw logs, and the three run scripts establish provenance.
The final host tree was checked against all 451 files in source commit `abb6a96`.

Recreate baseline `b308543` and optimized `8866066`, copy the archived baseline
harness into its example path, and run the commands in `run-final.sh` using
separate target directories. Apply `harness/packed27-candidate.patch` (the retained
`abb6a96` code diff), then run `run-packed27.sh` and `run-final27.sh`. Host paths
and the prerequisite-wait PID in those scripts describe the recorded session;
adapt them for a new host. Run both analysis scripts after collecting all data.
Cleanup and SHA-256 verification are recorded alongside the report.
