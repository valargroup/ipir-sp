# CUDA matrix-vector backend

The optional CUDA backend evaluates only the first-dimension `u16` matrix-vector
product. Packing, offline preprocessing, serialization, and client decoding use
the existing CPU code. CPU selection remains the default. This change does not
introduce a network boundary or move packing to another service.

```sh
cargo run --release -p ipir-sp --bin server --features http_server,cuda -- \
  32768 172032 --matvec-backend cuda --cuda-device 0
```

The runtime parameter is `--matvec-backend cpu|cuda`; `--cuda-device` is optional
and defaults to zero with CUDA. Supplying it with CPU is an error. CUDA selection
requires the `cuda` feature, an NVIDIA device, the CUDA driver shared library,
and NVRTC (CUDA 12). Shared libraries are loaded at runtime, so CPU builds and
all-feature compile checks do not require a CUDA toolkit. Explicit CUDA selection
fails on missing libraries/devices; it does not silently fall back to CPU.

Library callers use
`YServer::<u16>::try_from_profile_with_backend(..., MatvecBackend::Cuda { device: 0 })`
and `try_multiply_query`. Existing constructors and infallible evaluation methods
remain compatible. Online PIR methods return `InspiringError::Internal` for device
failures, and the demo HTTP server returns HTTP 500. Backend details are logged
without query contents. Callers using infallible methods still receive a panic
on backend failure.

## Arithmetic and ownership

Each CUDA instance uploads its own immutable column-major database. Every
preparation replaces that upload, even for identical dimensions. Direct kernel
callers must reprepare when database contents change. Preparation failure
invalidates the previous upload. There is no global or dimension-keyed cache.
The server retains the host database for CPU offline preprocessing, so GPU
selection adds a device copy; it does not eliminate host database memory.

Each block handles one column and at most 4096 rows with 256 threads. A query
coefficient is split into two 32-bit limbs. Each limb sum is bounded by
`4096 * (2^32 - 1) * (2^16 - 1) < 2^64`, including the block reduction. The high
limb is shifted modulo the modulus with 32 overflow-safe doublings. A second
kernel adds tile residues with overflow-safe modular addition. This is exact
integer arithmetic for arbitrary `u64` coefficients and nonzero `u64` moduli;
no floating point or Tensor Core arithmetic is involved.

Query, tile, and result device buffers are reused. A mutex serializes requests to
one instance, and results are synchronized before return. Multiple callers queue;
they do not create concurrent scratch allocations. At 32768 by 12288 the device
payload is 768 MiB database + 256 KiB query + 768 KiB tile sums + 96 KiB output,
plus CUDA context/module/allocator overhead. Preparation releases old device
buffers before allocating replacements. No batching or multiple-device scheduling
is provided.

## Validation and benchmarking

Ordinary tests never need a GPU. Explicit hardware tests are ignored by default
and fail when invoked without working GPU access:

```sh
cargo test --release -p simplepir-kernel --features cuda --test cuda -- --ignored
cargo test --release -p ipir-sp --features cuda --test production_params_flow \
  cuda_profiles_round_trip_with_cpu_packing -- --ignored
cargo run --release -p simplepir-kernel --features cuda --example cuda_bench -- \
  32768 12288 100
```

The benchmark uses three repetitions after warmup, one and four callers, and
checks every GPU output against the fastest available CPU backend. It reports
initialization, upload, synchronized device kernel time, total wall time per
completed query, and average request latency including lock wait. Device timing
uses CUDA events and excludes host transfers. Wall timing includes transfers,
event overhead, and result verification. Four callers share one device instance.
Results depend on GPU bandwidth, CPU memory bandwidth, and thread count; selecting
CUDA does not imply a speedup on every host or shape.

The [RTX 2000 Ada validation report](evidence/cuda-2026-09-24/README.md) records
hardware correctness results, memory usage, raw timings, and CPU quota caveats.
