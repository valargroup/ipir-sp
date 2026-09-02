# IPIR+SP Optimization Pass

Date: 2026-09-02

Three changes across bandwidth, server time, and preprocessing, plus one
security fix that had to land first.

## Environment

- Host: Apple Silicon laptop, 16 cores, 137 GB RAM, `arm64`
- Rust: `rustc 1.89.0 (29483883e 2025-08-04)`
- Base commit: `aff18bd`

**This is not the benchmark host used by
[`../2026-05-10-ipir-ypir/REPORT.md`](../2026-05-10-ipir-ypir/REPORT.md)** (Xeon
Platinum 8358, 8 vCPUs, AVX-512, 31 GiB). Numbers here are not directly
comparable to that report, and in particular:

- The AVX-512 kernel (`U16Avx512Kernel`) does **not** run on this host; every
  first-dimension measurement below is the portable `ChunkedSplitKernel`.
- Apple Silicon has considerably more memory bandwidth per core than an 8-vCPU
  Xeon slice, so the parallel first-dimension speedup here is an optimistic
  bound for production.
- ARM has much cheaper integer division than x86, where a 128-bit modulo is a
  `__umodti3` libcall. The preprocessing win below should therefore be **larger**
  on the production host, not smaller.

All numbers must be reconfirmed on the Xeon host before the README's headline
table is updated.

Raw logs are in `raw/`.

## Security fix: the first-dimension query had no error term

`encrypted_selection_query` (`ipir-sp/src/client.rs`) computed

```text
query[row] = delta * [row == target_row] - <a * X^j, s>
```

with no error term; `sigma_chi` was never referenced anywhere in `ipir-sp/src/`.
Because `a` is public — both peers derive it from the shared setup seed — the
server could take any of the 255 query blocks not containing the target, solve
`d` exact linear equations for `s`, and then read `target_row` directly off the
remaining block. Query privacy was fully broken.

Fixed by sampling `e <- DG(sigma_chi)` per coefficient, using the same
`DiscreteGaussian::init(sigma_chi * sqrt(TAU))` idiom already used in
`inspiring/src/preprocess.rs`.

Noise cost is nil: measured `||e_pack||_inf_bits` is **34**, unchanged, against
`delta/2 = 2^41`.

Regression coverage: `encrypted_selection_query_is_randomized` asserts the query
is not a deterministic function of `(setup_seed, target_row, s)`, and
`encrypted_selection_query_matches_scalar_reference` now checks that the NTT
path reproduces the scalar mask arithmetic up to a bounded error rather than
exactly.

## 1. Database aspect ratio: 4.04x less total wire traffic

Upload scales with the row count and download with the column count, while
their product is fixed by the dataset. At one instance per row the production
database was `524,288 x 2,048` — a 256:1 skew putting 3.5 MB of first-dimension
query against a 12 KB response.

`SIMPLEPIR_COEFFS_PER_ITEM` moved from 2,048 to 8,192 (four instances, 448
nullifiers per row), and `params_for_simplepir` now pads `db_rows` up to a
multiple of `poly_len` instead of to a power of two — the old padding wasted 15%
of both the database and the upload.

Measured with `IPIR_SP_BENCH_NULLIFIER=1` (`raw/ipir-sp-nullifier-shape.log`):

```text
profile=ipir_sp_nullifier_111442_114688 rows=112640 d=2048 outputs=4 db_cols=8192
measured_upload_bytes: packing_keys=98304 online_query_packed=788480
response=48 KiB   ||e_pack||_inf_bits=34
```

| | before | after |
|---|---:|---:|
| rows x cols | 524,288 x 2,048 | 112,640 x 8,192 |
| nullifiers per row | 112 | 448 |
| packing keys | 98,304 B | 98,304 B |
| first-dimension query | 3,670,016 B | 788,480 B |
| **upload** | **3,768,320 B** | **886,784 B** (4.25x) |
| download | 12,288 B | 49,152 B |
| **total wire** | **3,780,608 B** | **935,936 B** (**4.04x**) |
| database resident | 2.147 GB | 1.845 GB |
| output blocks | 1 | 4 |

Two second-order effects, both confirmed:

- **Packing wall time is flat at 4x the work.** `pack_intermediate_blocks`
  already parallelized over blocks, but with one block rayon had nothing to do.
  Measured packing is **41.2 ms** for four blocks here, against 42 ms for one
  block on the Xeon.
- **Query deserialization stopped mattering.** It was 13.4 ms for the 3.5 MB
  query; at 770 KB it is **524 us**. The byte-aligned fast path that was planned
  for it is no longer worth writing.

## 2. First-dimension matvec: 3.6x on 8 threads

`simplepir-kernel` had no rayon and no threads — one core streamed the whole
database per query. Both kernels now evaluate column bands in parallel. The
database is column-major, so a band is a contiguous, disjoint slice writing a
disjoint output slice: no reduction, no synchronization. Row chunks stay the
sequential outer loop so the query window stays resident.

New benchmark `simplepir-kernel/benches/first_dim.rs` measures the kernel alone
at the production shape (112,640 x 8,192, 1.85 GB), without paying for the PIR
fixture (`raw/first-dim-kernel.log`):

| threads | time | speedup | effective bandwidth |
|---:|---:|---:|---:|
| 1 | 175.90 ms | 1.00x | 10.5 GB/s |
| 2 | 87.15 ms | 2.02x | 21.2 GB/s |
| 4 | 63.98 ms | 2.75x | 28.9 GB/s |
| 8 | **48.90 ms** | **3.60x** | 37.8 GB/s |
| 16 | 39.49 ms | 4.45x | 46.8 GB/s |

Scaling is clearly bandwidth-bound, not compute-bound: it is near-linear to 2
threads and flattens after 8. On the 8-vCPU Xeon, which has less bandwidth per
core than this host, expect a smaller factor — but it is currently 1.00x there,
so the direction is not in doubt.

`ToU64` gained `Send + Sync` supertraits, which is what a database element type
shared across reader threads has to be.

## 3. Preprocessing: 1.89x

`add_shifted_tau` (`inspiring/src/preprocess.rs`) is the innermost loop of
`build_a_agg` and runs `d^3 = 8.6e9` times per CRS block at `d = 2048`. Each
iteration executed three hardware divisions, all removable without touching the
algebra:

1. `*coeff % q` — redundant, `a_tilde_coeffs` already reduces every coefficient.
2. `% two_d` where `two_d = 2d = 4096` — a mask on a power of two, but the
   compiler cannot prove `d` is one through the slice length.
3. `(u128(out) + u128(term)) % u128(q)` — a conditional subtract in disguise;
   both addends are already below `q`.

`cargo bench -p inspiring --bench pack -- offline`, `d = 2048` param set
(`raw/inspiring-offline-{baseline,optimized}.log`):

| | median |
|---|---:|
| baseline | 12.114 s |
| optimized | 6.410 s |
| | **1.89x** |

This is the smallest of the three wins and well below the 5-10x that removing
three divisions from a `d^3` loop suggested. ARM's integer division is cheap;
on x86 the `u128` modulo is a `__umodti3` libcall, so the production host should
do better. That needs measuring on the Xeon before any claim is made.

Byte-for-byte equivalence is guarded by
`inspiring/tests/python_oracle_match.rs`, which passes unchanged.

The remaining `Theta(d^3)` structure of `aggregate_slot` is untouched.
Reorganizing it into an NTT-domain formulation is the real fix and is still
open.

## Combined effect

| Metric | before | after | note |
|---|---:|---:|---|
| Upload | 3,768,320 B | 886,784 B | measured |
| Download | 12,288 B | 49,152 B | measured |
| Total wire | 3,780,608 B | 935,936 B | **4.04x**, measured |
| First-dimension matvec | 1.00x | 3.60x | 8 threads, this host |
| Packing | 1 block | 4 blocks, flat wall time | 41.2 ms measured |
| Query deserialize | 13.4 ms (Xeon) | 0.52 ms | measured |
| Offline per block | 12.11 s | 6.41 s | this host |
| Database resident | 2.147 GB | 1.845 GB | |
| `||e_pack||_inf_bits` | 34 | 34 | unchanged |
| Query privacy | broken | fixed | |

## Not done

- **No end-to-end HTTP run.** `data/nullifiers.bin` is not present on this host,
  so the three `NULLIFIER_FIXTURE.md` queries were not exercised against a live
  server. `NULLIFIER_FIXTURE.md` has been updated for the new packing (record
  1,638,400 is now row 3,657, offset 64) but that mapping is arithmetic, not
  measured.
- **No AVX-512 verification.** The parallelized `U16Avx512Kernel` compiles but
  cannot execute on this host; `avx512_u16_matches_chunked_when_supported` is a
  no-op here. It must be run on the Xeon before deployment.
- **No YPIR+SP re-baseline.** The comparison table in the root `README.md` is
  still the 2026-05-10 Xeon numbers.

## Reproducing

```bash
cargo test --workspace

# preprocessing
cargo bench -p inspiring --bench pack -- offline

# first-dimension kernel, production shape
for t in 1 2 4 8 16; do
  RAYON_NUM_THREADS=$t cargo bench -p simplepir-kernel --bench first_dim
done

# end-to-end shape, upload accounting and server breakdown
IPIR_SP_BENCH_NULLIFIER=1 cargo bench -p ipir-sp --bench end_to_end
```
