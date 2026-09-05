# Packing: the batching gate, and a 1.47x collapse-loop win

Date: 2026-09-05

The plan gated the "coalesce concurrent queries" item on one measurement: does
packing `k` unrelated queries in a single pass over `digits_ntt` cost
meaningfully less than `k` separate passes?

**On the deployed host: no. 1.06× at best, which does not justify the change.**
The hypothesis behind Track A.3 was wrong, and so was the plan's premise that
both halves of the online path are memory-bound — the packing half is not. The
useful result is what the measurement turned up instead: packing runs at 0.134
multiply-accumulates per core-cycle while leaving 58% of the host's memory
bandwidth unused, next to a first-dimension kernel doing 0.91 MAC/cycle with a
technique already written in this workspace.

## Headline

Two results, one negative and one positive, from the same investigation on
`roman-ipir-bench-8vcpu`:

| | before | after | |
|---|---:|---:|---|
| packing, 16 blocks | 68.4 ms | **46.6 ms** | **1.47x** |
| total online server time | 126.8 ms | **103.3 ms** | **1.23x** |
| packing share of online time | 54% | 45% | |
| **live server QPS, real snapshot** | **8.17** | **9.94** | **1.22x** |
| live mean latency | 122.5 ms | 100.6 ms | |

Validated on the deployed path: byte-identical responses to the previous build
across six rows of the production snapshot, correct end-to-end decode of present
and absent nullifiers, and unchanged noise (`||e||_inf = 2^36` against
`delta/2 = 2^41`).

- **Batching packing across queries: 1.06x. Not worth doing.** That was the
  gate for Track A.3 and it fails.
- **Reordering the collapse loop: 1.47x on packing.** Found by profiling *why*
  batching failed. No parameter change, no protocol change, bit-exact output.

The second result exists because the first one failed in an informative way.

## The hypothesis, and why it was plausible

`QueryPackPreprocessed::digits_ntt` is 100.6 MB per CRS block at
`d = 2048, ell = 3` and is derived from the CRS alone, so it is byte-identical
for every client. The inner loop in `accumulate_collapse_term`
(`inspiring/src/preprocess.rs`) multiplies each 8-byte digit — read exactly once
— by a key body that is only 48 KB and fully cache-resident. That reads as one
multiply-accumulate per 8 bytes streamed, i.e. memory-bound, and suggested `k`
queries could share the stream while multiplying only the arithmetic.

Against that, YPIR §4.3 measured cross-client batching at only 1.3× (k=4) and
attributed the ceiling to packing: "the fixed cost of the LWE-to-RLWE packing
does not benefit from cross-client batching." That is CDKS, where the online work
genuinely is per-client key-switching, so it was not decisive for InspiRING —
hence this measurement. In the event, YPIR's number was closer to the truth than
the hypothesis, and the underlying reason is different from theirs.

## Result — Xeon 8358, the deployed host

`roman-ipir-bench-8vcpu`, DigitalOcean `g-8vcpu-32gb-intel` in `ams3`: Intel Xeon
Platinum 8358 @ 2.60 GHz, 8 cores, AVX-512F/BW/CD/DQ/VL/VBMI (**no
`avx512ifma`**), 31 GiB, Rust 1.89.0, `RUSTFLAGS=-C target-cpu=native`. Idle
(load 0.00). Same slug and region as `vote-nullifier-pir-primary-prod`.

| `k` | sequential ms/query | batched ms/query | speedup | digit stream GB/s | MAC/cycle |
|---:|---:|---:|---:|---:|---:|
| 1 | 4.60 | 4.57 | 1.01× | 22.0 | 0.132 |
| 2 | 4.59 | 4.44 | 1.03× | 11.3 | 0.136 |
| 4 | 4.56 | 4.31 | **1.06×** | 5.8 | 0.140 |
| 8 | 4.59 | 4.33 | 1.06× | 2.9 | 0.140 |
| 16 | 4.59 | 4.43 | 1.04× | 1.4 | 0.137 |

**Batching packing is worth 6% — nothing.** Three consecutive runs agree
(`raw/xeon-d2048.txt`); MAC/cycle is pinned between 0.132 and 0.140 across a 16×
change in work per pass. The sequential 4.6 ms/block also independently
reproduces the 4.18 ms/block from the second optimization pass.

The hypothesis is refuted on the host that matters, and by a wide margin.

## Why: packing is not memory-bound

The plan asserted that both halves of the 122 ms are DRAM-bandwidth-bound. With
a STREAM anchor that turns out to be half right, and the half that is wrong is
exactly the half this experiment targeted.

STREAM Triad on this host (`raw/xeon-stream.txt`, OpenMP, 960 MB working set):
**57.9–58.7 GB/s on 8 threads, 14.3–14.4 GB/s single-threaded.** Copy is
50.2–51.8 / 12.3.

| stage | achieved | % of STREAM Triad | MAC/cycle | verdict |
|---|---:|---:|---:|---|
| first-dimension matvec | 37.9 GB/s | **65%** | 0.91 | genuinely near the memory roof |
| InspiRING packing | 24.1 GB/s | **42%** | **0.134** | arithmetic-bound, 2.4× memory headroom unused |

65% for the matvec sits inside the published band for this family (SandwichPIR
measures SimplePIR at 63% of STREAM; YPIR reports 83%), so the first dimension is
in good shape and there is at most ~1.5× in it.

Packing is the opposite. It leaves well over half the memory bandwidth unused and
runs at **0.134 MAC/cycle — 7.5 cycles per multiply-accumulate**. Sharing the
digit stream cannot help something that is not waiting on the digit stream, which
is precisely what the flat MAC/cycle column shows.

## The finding that matters, and the fix

Profiling the failed batch explained it. `perf stat` over the benchmark, against
5.46e9 multiply-accumulates:

| | baseline | after | ideal |
|---|---:|---:|---:|
| instructions / MAC | 16.8 | **11.8** | ~6 |
| L1-dcache loads / MAC | 7.9 | **4.5** | ~3 |
| IPC | 1.71 | 1.59 | |

**16.8 instructions per multiply-accumulate at IPC 1.71 is not a memory
problem** — the loop was issuing far too many instructions, and no amount of
sharing the digit stream fixes that. Two causes, both structural:

**1. Digit-outer iteration order.** All `ell` digits of a term accumulate into
the *same* slot, but the loop ran digits on the outside, so each 32 KiB
accumulator took `ell = 3` separate read-modify-write passes instead of one.
Worth 1.05x on its own — small, because it was not the dominant cost.

**2. Operand slices behind an array index.** Holding the `ell` body and digit
slices in an array and writing `bodies[digit_idx][src]` reloads a
(pointer, length) pair and bounds-checks it *per element*. Naming the six slices
directly for the production `ell = 3` — and masking the permutation index with
`d - 1`, which is the identity given that the table is a bijection on `0..d` and
`d` is a power of two, but lets the bound be proven without a branch — removed
30% of instructions and 43% of L1 loads. This is where the 1.47x is.

The residual is still ~2x off the ~6 instructions/MAC floor (one `mulx`, an
add/adc pair, two operand loads, amortized index and accumulator traffic).
Closing that would need the `u128` accumulation itself restructured — the
split-limb approach the first-dimension kernel uses — which is a larger change
with a real carry-handling problem, and is not attempted here.

Achieved digit-stream rate rose from 23.1 to 31.5 GB/s, i.e. 40% to **54% of
STREAM Triad**. Packing is now much closer to the memory roof, which also means
the remaining headroom is smaller than it was.

## Live validation on the real snapshot

Everything above is a benchmark. This section is the deployed path: the actual
`nullifier-pir` HTTP server, on the production snapshot
(`/root/vs-ypir/data/nullifiers.bin`, 1,597,627,296 B, 49,925,853 records,
28,672 x 32,768), both builds side by side at `setup_seed=7`.

### Byte-exact response diff

A response is a deterministic function of `(snapshot, setup_seed, query bytes)`,
so a bit-exact change must return byte-identical responses for a fixed query
blob. `nullifier-pir/examples/replay_query` emits one blob; the same bytes were
POSTed to both servers.

| target | result |
|---|---|
| `GET /public-params` (229,376 B) | **identical** |
| row 0 | **identical** |
| row 1 | **identical** |
| row 12,345 | **identical** |
| row 20,000 | **identical** |
| row 27,860 (last real row) | **identical** |
| row 28,671 (padded row) | **identical** |

This is the strongest available correctness argument for this change: same bytes
out, on production data, through the real server — not "tests pass".

### End-to-end decode

Via the CLI against the new server, verifying the decrypted row actually
contains the target:

- record 1,638,400 → row 914, offset 512 — found and verified (matches
  `NULLIFIER_FIXTURE.md`)
- record 49,925,852 → row 27,860, offset 732 — found and verified (last record)
- all-zero nullifier, probe row 914 — correctly reported absent

Wire is exactly as documented: upload 236,544 B (86,016 keys + 150,528 query),
download 81,920 B, total 318,464 B.

### Sustained throughput

`nullifier-pir/examples/loadtest`, 24 requests, real snapshot, one server at a
time:

| concurrency | baseline QPS | new QPS | baseline mean | new mean |
|---:|---:|---:|---:|---:|
| 1 | 8.17 | **9.94** | 122.5 ms | **100.6 ms** |
| 2 | 8.17 | 9.83 | 239.8 ms | 199.3 ms |
| 4 | 8.15 | 9.81 | 460.2 ms | 382.1 ms |

**QPS 8.17 → 9.94, a 1.22x throughput gain on the live server**, matching the
1.23x measured in the benchmark. p99 improves from 125.1 ms to 102.5 ms at
concurrency 1.

**QPS is flat across concurrency on both builds.** The server pins
`.workers(1)` (`nullifier-pir/src/http.rs`) and each query saturates the box
with rayon, so concurrent arrivals serialize and only inflate latency — 122 ms
to 460 ms at c=4 on baseline. That is the expected behaviour, now measured
rather than assumed, and it is why the A.3 coalescing idea targeted this layer
in the first place.

## A note on the matvec number

The A/B table shows matvec at 55.4 ms (baseline) and 53.7 ms (new), against 49.6 ms
in the 2026-09-02 comparison report. That is not a regression, and the difference
is not noise. Measured directly with `cargo bench -p simplepir-kernel --bench
first_dim` at the deployed `28,672 x 32,768` shape on this host:

| kernel | time |
|---|---:|
| `avx512_u16` | **50.13 ms** |
| `chunked_split` (portable) | **55.01 ms** |

**The end-to-end benchmark hardcodes `ChunkedSplitKernel`**
(`ipir-sp/benches/end_to_end.rs:474`), while the server selects at runtime via
`new_auto_kernel` (`nullifier-pir/src/backend.rs:108`) and therefore uses AVX-512
on this host. So the e2e figures come from the portable kernel and the published
49.6 ms from the vectorized one — two different kernels, ~10% apart.

Three consequences worth stating:

- **The A/B is unaffected.** Both sides used the same portable kernel, and the
  matvec moved 55.36 -> 53.66 ms, i.e. slightly *down*, as expected for a change
  that touches only `accumulate_collapse_term`.
- **The e2e bench's total server time is ~5 ms pessimistic** relative to
  production. The live HTTP mean of 100.6 ms, not the bench's 103.3 ms, is the
  production-representative number. The ratio is essentially unchanged either way
  (121.9 -> 98.4 ms, 1.24x, if both sides are adjusted to the AVX-512 kernel).
- **The e2e bench does not exercise the kernel the server runs.** That is a real
  coverage gap, separate from this change, and worth closing so benchmark and
  production agree by construction rather than by accounting.

## Cross-check: Apple M4 Max

Run first, and useful only as contrast (`raw/m4max-d2048.txt`; 12P+4E cores,
128 GiB unified memory, 16 workers):

| `k` | sequential ms/query | batched ms/query | speedup |
|---:|---:|---:|---:|
| 1 | 1.30 | 1.31 | 0.99× |
| 4 | 1.43 | 1.13 | 1.27× |
| 8 | 1.39 | 0.93 | **1.50×** |
| 16 | 1.34 | 0.93 | 1.44× |

The M4 Max shows 1.5×, the Xeon 1.06×. The difference is that the M4 Max sustains
77 GB/s on the digit stream against the Xeon's 22 GB/s, so on that machine the
stream is a larger share of the cost and sharing it pays a little. On the
deployed host it does not. **The laptop result was optimistic by 1.4×, and had it
been taken as the answer it would have justified building the wrong thing.**

A `d = 512` control (`raw/m4max-d512.txt`, 6.3 MB block, entirely cache-resident)
reaches a similar MAC/cycle to the 100.6 MB block — the same conclusion from the
other direction: block size is not what sets the rate.

## What this means for the plan

- **Track A.3, packing: dead.** 1.06x does not justify the API change, the
  coalescing queue, or the latency cost. The batched API is kept because it is
  tested, costs nothing unused, and is the vehicle for re-testing if the loop
  balance changes.
- **Track A.3, matvec: still open.** The matvec is at 65% of STREAM with 0.91
  MAC/cycle against a much higher AVX-512 ceiling, so it remains the stage where
  amortizing the stream should convert into throughput. Untested.
- **A.1: partly done.** STREAM measured; the concurrent-load harness is not.
- **New:** the plan's premise that both halves of the online path are
  DRAM-bandwidth-bound was wrong for packing, and correcting it produced a 1.23x
  end-to-end server win that was not in the plan at all.

## Correctness

The collapse reordering is **bit-exact, not approximate**. The accumulation is
`u128` integer addition with no modular reduction between terms and a proven
no-overflow bound (`fused_accumulator_fits`), so the sum is associative and
reordering cannot change the result.

Pinned by:

- `accumulate_collapse_term_orderings_agree` — slot-outer against the retained
  digit-outer reference, both permuted (`K_g`) and contiguous (`K_h`) branches,
  operands near `q`, accumulated twice so a term is exercised on a non-zero
  accumulator.
- `accumulate_collapse_term_ell3_specialization_matches_generic` — the `ell = 3`
  fast path against the generic path. The default test parameters use `ell = 5`
  and would have exercised only the generic path, so this uses a dedicated
  `ell = 3` fixture.
- `cached_automorphism_tables_are_permutations` — every cached table is a
  bijection on `0..d`, which is the invariant the index masking relies on.

### The masking invariant is enforced in release builds

A first cut of this change validated the permutation only in tests, with a
`debug_assert!` in the hot loop — i.e. the safety argument rested on a check that
never runs in production. Every `NttAutomorphTable` is now built through
`new_checked`, which **panics** (not `debug_assert`s) if the table is not a
bijection on `0..d`. Tables are constructed once per parameter set and cached, so
the `O(d)` check is free: offline build stays at 1.11 s/block and packing at
3.13–3.19 ms, unchanged.

This matters because the failure mode is silent. Masking with `d - 1` cannot
panic, so an out-of-range entry would read the wrong slot and return a **wrong
plaintext to the client** rather than an error.
- `fused_collapse_matches_stepwise_cascade` (pre-existing) — the fused collapse
  against the stepwise cascade, unchanged and still passing.

The end-to-end run reports `||e_pack||_inf_bits=34`, unchanged from baseline, as
it must be for a bit-exact change.


`batched_pack_matches_sequential` asserts the batched output is bit-identical to
the sequential output for every query at `k ∈ {1, 2, 3, 5}`, with distinct key
bodies and distinct `b` blocks so a bug crossing accumulator slots between
queries cannot pass by symmetry. `batched_pack_rejects_mismatched_lengths` covers
the shape errors. Both pass on the Xeon under `--release -C target-cpu=native`
and on the M4 Max.

`batched_pack_matches_sequential` asserts the batched output is bit-identical to
the sequential output for every query at `k` in {1, 2, 3, 5}, with distinct key
bodies and distinct `b` blocks so a bug crossing accumulator slots between
queries cannot pass by symmetry. Batching shares no secret state and changes no
ciphertext — it is server-side request coalescing over public preprocessing, not
batch PIR, and carries no cryptographic assumption.

**142 tests pass on both hosts** (`inspiring` + `ipir-sp`, `--all-features
--release`, and on the Xeon under `-C target-cpu=native`), `cargo clippy
--all-targets --all-features -D warnings` clean, `cargo fmt --check` clean.

## Method

`inspiring/examples/batched_pack_bench.rs`, one CRS block at the production
packing parameters (`d = 2048`, `q = 72,057,594,037,641,217 ≈ 2^56`, `p = 2^14`,
`ell = 3`, `z = 2^19`). Each configuration runs the sequential path
(`pack_b_prevalidated`, once per query) and the batched path
(`pack_b_batched_prevalidated`) over the same inputs, 7 repetitions, best time
taken. One untimed warm-up pack precedes the measurements so first-touch page
faults on the freshly built digit cache are not charged to `k = 1`. Queries use
distinct key bodies and distinct `b` blocks — they are independent queries, not
copies.

`MAC/cycle` is normalized at 2.6 GHz per worker, exact for the Xeon and
indicative for the M4 Max. `stream GB/s` assumes one pass over `digits_ntt` per
batch, so it falls as `1/k` by construction; it is reported to show what the
batch *would* have saved if the stream were the constraint.

Limitations: CRS contents are pseudorandom, which cannot affect timing since
every path touches every coefficient. One CRS block is measured, not all sixteen;
the deployed server packs sixteen under `par_iter`, so wall-clock there also
reflects block-level parallelism this benchmark does not model. Best-of-7 is
reported rather than a distribution.

## Reproducing

```bash
# batching gate + collapse-loop throughput, one block
cargo run --release -p inspiring --example batched_pack_bench
INSPIRING_BENCH_SMALL=1 cargo run --release -p inspiring --example batched_pack_bench

# end-to-end at the deployed 16-block shape
IPIR_SP_BENCH_NULLIFIER=1 cargo bench -p ipir-sp --bench end_to_end -- \
  online_pack_only --sample-size 10 --measurement-time 20
```

The A/B baseline is `git show main:inspiring/src/preprocess.rs` dropped into the
tree; the end-to-end bench does not use the batched API, so `main`'s file builds
against the rest of the branch unchanged.

- [Xeon 8358, live HTTP on the real snapshot](raw/xeon-live-http.txt) — byte diff, decode, throughput
- [Xeon 8358, end-to-end A/B at the 16-block server shape](raw/xeon-e2e-ab.txt) — the headline numbers
- [Xeon 8358, after the loop fix](raw/xeon-fast.txt) and [its `perf stat`](raw/xeon-perf-fast.txt)
- [Xeon 8358, before the loop fix](raw/xeon-d2048.txt)
- [Xeon 8358, STREAM](raw/xeon-stream.txt) and [host](raw/xeon-host.txt)
- [M4 Max, d = 2048](raw/m4max-d2048.txt), [d = 512 control](raw/m4max-d512.txt), [host](raw/host.txt)
