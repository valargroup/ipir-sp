# Upload optimization investigation

Status: experimental; native cryptographic production review is still required.
Target: at least 20% packing-key reduction with no more than 5% regression in
client generation/decode or server throughput, at d=2048, q=2^54, p=2^16.

## Arithmetic and API

Prepared public decoding caches auxiliary transforms. Each fresh request
transforms its secret once, derives the conjugate by a verified reversal, and
combines mask products before inverse NTT/CRT. The full integer sum is bounded
using the public sampler support before selecting two primes. Request preparation
is included in client generation for both the one-mask and two-mask comparator.
The response decoding path is identical after preparation. Legacy decoding is
retained for differential verification.

```rust
let published = server.published();
let prepared = published.prepare(server.setup())?; // once per snapshot
let mut request = NativeRequest::generate(server.setup(), target)?;
request.prepare_decode(&prepared)?; // per-request online client work
let (response, _) = server.respond(request.bytes())?;
let row = request.decode_prepared(&prepared, &response)?;
```

Select two-mask output with `NativeProfile::with_two_mask_output()`. No default
profile changed. Every served snapshot still needs its own correctness
certificate. The existing two-mask fixture certificate remains <=2^-436 because
the decoding optimization preserves the exact phase.

## Gadget and quantization results

The search recompiles the actual first output block for 49 ordered K_g width
pairs (16 through 22 bits per limb), then screens 261 final gadgets per pair:
one limb of 25 through 29 bits, or two limbs of 12 through 27 bits each.
All 12,789 combinations fail the conservative 2^-128 gate at the bandwidth
target. The strongest screened bound is 2^-18. This is a failure to certify,
not an impossibility proof or a measured failure rate.

Integer dynamic programming minimizes the deterministic compression bound over
all per-limb wire precisions 1 through 54 with at most 172 transmitted bits per
ring coefficient. That corresponds to 44,032 key bytes, a 20.37% saving. For the
original [19,19]/[19,19] gadgets, the optimal target allocation is
[46,46,40,40] and its compression bound is 7,460,617,575,552, versus a decoding
radius of 137,438,953,472, before reserving other errors. Wider search is not
certified by treating key-rounding errors as independent random variables.

The screen combines weights on reused secret variables conservatively via
triangle inequalities; the original exact one-limb checker remains available.
Because every candidate fails already on block 0, other blocks cannot turn this
particular full-response certificate into an acceptance. No mixed-radix runtime
format was introduced. `gadgets-block0.jsonl` retains public masks, norms,
sampler counts, database digest and setup identity; `screen-block0.jsonl` holds
screen results. Public seeds are the existing fixture seeds.

## Exact bandwidth and storage

| Metric | One mask | Two masks |
| --- | ---: | ---: |
| Key upload | 55,296 B | 27,648 B |
| Complete request | 230,948 B | 203,300 B |
| Response | 90,180 B | 90,180 B |
| Published masks | 262,180 B | 524,324 B |
| Cached public transform coefficients | 524,288 B | 1,048,576 B |
| Request-local secret mask products | 262,144 B | 262,144 B |

Savings are 50% of packing keys and 11.97% of the complete request. Extra public
mask transfer breaks even on the tenth query per cached snapshot. Transform
storage excludes allocator/context overhead. Request-local products are erased
on drop and cannot be reused across requests.

## Reproduction

```sh
cargo build --release -p ipir-sp --features native-reinspiring --examples
RAYON_NUM_THREADS=8 target/release/examples/native_gadget_search 28672 32768 0 > gadgets.jsonl
python3 reinspiring/tools/security/search_upload.py gadgets.jsonl > screen.jsonl
RAYON_NUM_THREADS=8 target/release/examples/native_compare 30 > paired.jsonl
python3 reinspiring/tools/security/certify_native.py bench-results/2026-09-25-two-mask/noise.json --require-bits 128
python3 -m unittest discover -s reinspiring/tools/security
```

`native_compare` alternates order between modes for each query, with three
warmups and 30 measured queries per mode. It builds both snapshots before timing
online work, verifies every row against the expected database, and independently
checks legacy decoding and phase error. `native_e2e` also measures cold decoding
including public-transform preparation. First exploratory files `one-1.jsonl`
and `two-1.jsonl` overlap unrelated Rust builds and predate request preparation;
they must not be used as the final performance comparison.

## Validation

Release tests for reinspiring and ipir-sp pass, including existing production
flow and adapter equivalence tests. New tests cover prepared/legacy agreement,
conjugation at degree 2048, sampler support boundaries, request/setup binding,
exact per-limb compression residuals, equal-gadget screen equivalence, mixed-radix
reconstruction, correlated bounds and DP agreement with exhaustive enumeration.
The Python certificate/search suite has eight passing tests. Clippy with warnings
denied and formatting checks pass. Sage is unavailable on this host; no new
lattice-estimator numbers are claimed. The original full-key diagnostics remain
conservative for the subset of key material sent in two-mask mode.

## Performance result and recommendation

Two alternating runs produced 60 measured requests per mode, plus warmups.
Host: Apple M4 Max, 128 GiB RAM, Darwin arm64, Rust/Cargo 1.89.0, eight Rayon
workers. `host.json` records the environment and fixture dimensions.

| Observed metric | Prepared one mask | Prepared two masks | Change |
| --- | ---: | ---: | ---: |
| Median client generation including request preparation | 33.697 ms | 28.145 ms | -16.48% |
| Median client response decoding | 0.26733 ms | 0.26769 ms | +0.13% |
| Median server response | 77.654 ms | 68.159 ms | -12.23% |
| Mean server response | 80.825 ms | 73.899 ms | +9.37% inferred serial throughput |
| Maximum observed phase error | 14,354,664,781 | 14,673,893,560 | Both below 2^37 |

All measured responses decoded correctly. `summary.json` also records p95,
individual observations remain in `paired-*.jsonl`, and the environment files
record compiler overlap. The host ran unrelated project builds and tests during
both experiments (compiler overlap in 55/77 and 13/56 one-second samples).
**These are exploratory timings: the strict 5% performance gate is unverified.**
Alternating order reduces drift but does not establish isolation or eliminate
contention. An idle-host repeat is required before claiming that gate is met.

The result supports retaining the prepared two-mask path as the candidate: exact
50% key-upload reduction, unchanged response size, exact arithmetic, a preserved
snapshot correctness certificate, and promising observed performance. It does
not justify enabling the native profile for production. No screened quantized or
asymmetric one-mask profile meets the selected correctness target at 20% savings.
Cold public-state acquisition/preparation costs are separate and increase for
two masks; the recommendation assumes public state is cached per snapshot.
