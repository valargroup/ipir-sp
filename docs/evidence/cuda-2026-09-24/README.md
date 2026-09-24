# CUDA matrix-vector validation — 2026-09-24

Implementation: `e674645e1b49ece6e106b0fb7984011834c4ca0c` on
`feat/cuda-matvec`, based on `611a29284264d844bf4dba00de2874c5b762f8c2`.

## Hardware and method

- Runpod NVIDIA RTX 2000 Ada Generation, 16,380 MiB VRAM, driver 570.172.08,
  CUDA 12.8 / NVRTC.
- Host CPU: AMD EPYC 7352, 24 cores / 48 logical CPUs. The container has a
  **5.1 CPU quota** (`cpu.cfs_quota_us=510000`, period 100000). These results are
  a comparison on this quota-limited host, not a general GPU-versus-AVX-512 claim.
- CPU backend: portable `ChunkedSplitKernel` (this CPU lacks AVX-512).
  Eight Rayon threads outperform the separately measured 24-thread setting.
- Rust 1.89.0, repository release profile; binaries compiled on an x86_64 Linux
  AVX-512 host without `target-cpu=native`, then transferred to Runpod because
  the pod could not download Rust's toolchain. Runtime CPU detection selects
  the appropriate backend on the execution host.
- Seeded database and 100 arbitrary full-width u64 queries, ten warmup queries,
  three repetitions for each one/four-caller case. Every response is compared
  exactly with the CPU result. Four callers share one serialized GPU instance.
- CUDA event timing measures both kernels and excludes transfers. Wall timing
  includes query/result transfers, synchronization, event instrumentation and
  output comparison. Request latency includes mutex waiting.

## Results

Medians of three repetitions, milliseconds per query:

| Shape / callers | CPU wall, 8 threads | GPU wall | GPU kernels | GPU request latency |
|---|---:|---:|---:|---:|
| 32768 × 12288 / 1 | 36.539 | 4.471 | 4.379 | 4.457 |
| 32768 × 12288 / 4 | 36.539 | 4.555 | 4.450 | 11.920 |
| 4097 × 257 / 1 | 0.163 | 0.041 | 0.017 | 0.039 |
| 4097 × 257 / 4 | 0.163 | 0.050 | 0.019 | 0.111 |

The full database is 805,306,368 bytes (768 MiB). In the uncontended recorded
run, CUDA initialization/compilation took 595.459 ms and database preparation/
upload took 73.728 ms. These one-time costs are excluded from query timing.
Observed total device memory peaked at **894 MiB**, including CUDA overhead;
this is sampled device usage, not retained host RSS. The server additionally
retains its host database for offline preprocessing.

The full-shape single-caller result is about **8.2× faster** than the measured
8-thread CPU baseline. At 24 CPU threads the CPU median was 58.064 ms, while
GPU median wall time remained around 4.5 ms. Increasing callers does not increase
GPU parallelism in this implementation; it increases queueing latency.

Raw results: [full shape](full-8-threads.log), [small/non-aligned shape](small-8-threads.log),
[24-thread comparison](full-24-threads.log), [sampled device memory](gpu-memory.csv).
Do not extrapolate these results to other GPUs, unrestricted CPU hosts, packing
performance, or whole-request PIR throughput.

## Correctness

[Kernel tests](kernel-tests.log) pass on the GPU, covering empty/nonaligned shapes,
4096-row boundaries, arbitrary and maximum coefficients, u16 maxima, moduli 1/2/
production/u64::MAX, repeated calls, same-shape replacement, independent instances,
concurrent callers, timed evaluation, invalid inputs and unavailable device ordinals.
Explicit invocation without CUDA libraries fails with a clear error.

[All four production profiles](pir-profiles.log) pass end-to-end GPU multiplication,
unchanged CPU packing, and client decode with the existing decryption-margin check:
P14, P16Q46, P16Q48, P16Q49. Ordinary CI keeps GPU tests ignored; these logs are the
explicit hardware invocation, not skipped tests.

Reproduce using the commands in [the backend guide](../../cuda-matvec.md).
Full/small/24-thread benchmark logs contain 1,800 checked GPU evaluations total,
in addition to warmup and hardware tests.

Binary SHA-256:

```text
f6665536e87dd7e53a2a17f60b3f4f661e565ece12b368aec81c8306e4af95c2  cuda_bench
c3875ae2192858173d7c6c19d8d8e954da1d22afac95809311a6b3faf93e6fc4  cuda hardware tests
a9478886008984ff4d21c15de307176deeef1b6a6c1cb9f0cd0b4642c39e43d8  production profile tests
```
