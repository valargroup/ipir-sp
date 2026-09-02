# Xeon AVX-512 Confirmation Run

Date: 2026-09-02

Reconfirms `REPORT.md` on production-class hardware. **This host is the same
model as the original 2026-05-10 benchmark host**, so these numbers are directly
comparable to that report.

## Environment

- Droplet: `roman-ipir-bench-8vcpu`, DO `g-8vcpu-32gb-intel`, ams3
  (same size slug and region as `vote-nullifier-pir-primary-prod`)
- CPU: **Intel Xeon Platinum 8358 @ 2.60GHz, 8 cores, no hyperthreading**
- AVX-512: `avx512f avx512bw avx512cd avx512dq avx512vl avx512_vnni ...`
- RAM: 31 GiB. Ubuntu 24.04. `rustc 1.89.0`

## AVX-512 correctness

`avx512_u16_matches_chunked_when_supported` **passes on real AVX-512 hardware**:
the parallelized `U16Avx512Kernel` is bit-identical to the portable kernel.
Full workspace suite green (23 test binaries).

## 1. First-dimension matvec (production shape, 112,640 x 8,192, 1.85 GB)

| threads | AVX-512 | portable |
|---:|---:|---:|
| 1 | 249.47 ms | 395.73 ms |
| 2 | 112.35 ms | 221.94 ms |
| 4 | 59.11 ms | **106.94 ms** |
| 8 | **50.27 ms** | 118.24 ms |

- AVX-512, 1 -> 8 threads: **4.96x**.
- Against the 2026-05-10 production number (308 ms, old shape, AVX-512,
  single-threaded): **6.1x**.
- The portable fallback peaks at 4 threads and degrades ~11% by 8. Reproducible
  and monotonic (4/6/8 threads: 106.9 / 113.0 / 118.2 ms). Not hyperthreading
  (1 thread per core) and not band granularity — sweeping `MIN_BAND_BYTES` over
  2/8/32/128 MB moved it only 116-131 ms. Unexplained; it is the fallback path,
  production selects AVX-512 via `new_auto_kernel`, and it is still 3.3x faster
  than serial.

## 2. Packing — block parallelism confirmed, with a thread-count cliff

`online_pack_only`, 4 output blocks:

| threads | time |
|---:|---:|
| 1 | 165.03 ms |
| 2 | 83.33 ms |
| 4 | **41.70 ms** |
| 8 | 86.67 ms |

Linear to 4 threads — exactly the block count — then a 2x regression at 8.

**The "flat wall time at 4x the work" claim holds, but only at 4 threads:**
41.70 ms for four blocks against the 2026-05-10 figure of 42 ms for one block.

## 3. Preprocessing

`cargo bench -p inspiring --bench pack -- offline`, `d = 2048`:

| | median |
|---|---:|
| baseline (`aff18bd`) | 40.370 s |
| optimized | 17.757 s |
| | **2.27x** |

Better than the 1.89x measured on arm64, as predicted — x86 pays a `__umodti3`
libcall for the 128-bit modulo. Still far short of the 5-10x that removing three
divisions from a `d^3` loop suggested; the `Theta(d^3)` structure of
`aggregate_slot` remains the real fix.

Note this host is much slower than the arm64 laptop at this workload
(40.4 s vs 12.1 s baseline).

## 4. Wire format and noise, unchanged from `REPORT.md`

```text
rows=112640 d=2048 outputs=4 db_cols=8192
packing_keys=98304  online_query_packed=788480  response=49152
||e_pack||_inf_bits=34
```

Upload 3,768,320 -> 886,784 B (**4.25x**), total wire 3,780,608 -> 935,936 B
(**4.04x**). The added query error term costs nothing: `||e_pack||` is still 34
bits against `delta/2 = 2^41`.

## Server-time projection

One-shot breakdown at 8 threads (portable kernel):
`deserialize=1.73 ms matrix_vector=119.58 ms packing=41.93 ms serialization=1.07 ms`

Composing the best measured numbers, AVX-512 kernel:

| rayon threads | matvec | packing | + deser/ser | total |
|---:|---:|---:|---:|---:|
| 8 | 50.27 ms | 86.67 ms | 2.8 ms | ~140 ms |
| **4** | **59.11 ms** | **41.70 ms** | **2.8 ms** | **~104 ms** |

Against the 2026-05-10 baseline of **364 ms**, four threads gives **~3.5x**.

**The matvec wants 8 threads and packing wants 4, and they share one global
rayon pool.** Four is the better single setting today.

## Open items

- The 8-thread regression in both packing and the portable matvec is
  unexplained. Both peak at exactly 4 threads on an 8-core box.
- `ipir-sp/benches/end_to_end.rs` still measures `ChunkedSplitKernel`, not the
  AVX-512 kernel production selects — its `matrix_vector` number
  (119.58 ms) is the portable path. `simplepir-kernel/benches/first_dim.rs`
  covers AVX-512.
- Still no live HTTP run against `data/nullifiers.bin`.
- Root `README.md` still carries the 2026-05-10 YPIR+SP comparison.
