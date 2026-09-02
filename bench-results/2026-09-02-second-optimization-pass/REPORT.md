# IPIR+SP Second Optimization Pass

Date: 2026-09-02

Three changes, one per dimension, plus the correctness work each one forced.
Baseline is `0e16fc1`, the tree the
[2026-09-02 optimization pass](../2026-09-02-optimization-pass/REPORT.md) left
behind.

## Environment

- Host: `roman-ipir-bench-8vcpu`, DigitalOcean `g-8vcpu-32gb-intel` in `ams3` —
  the same slug and region as `vote-nullifier-pir-primary-prod`.
- CPU: Intel Xeon Platinum 8358 @ 2.60 GHz, 8 cores, no hyperthreading,
  AVX-512F. Same CPU model as the 2026-05-10 report's host, so those numbers
  are comparable again.
- 31 GiB RAM, `rustc 1.89.0`, `RUSTFLAGS=-C target-cpu=native`.
- Baseline tree `~/ipir-sp-base` at `0e16fc1`; new tree `~/ipir-sp-new`.

Raw logs in `raw/`.

> **On commit `ac0929b`.** That commit ("Add Xeon AVX-512 confirmation run")
> contains 455 added lines of `inspiring/src/preprocess.rs` that are this pass's
> fused collapse and NTT-domain aggregate: a second agent committed a working
> tree that was being edited concurrently. Its timings cannot be attributed to
> the code its message describes, so nothing in this report is taken from it.
> Every number below was measured here against `0e16fc1` directly.

## The coupling that shapes the pass

Total wire is minimized by making the database wider and shorter, but both
online packing and offline preprocessing cost a fixed amount per output block,
and widening adds blocks. The previous pass stopped at four instances for
exactly that reason. So the packing and preprocessing work came first, and the
bandwidth win is what they unlock.

## 1. Packing: one Barrett reduction per block instead of one per (step, slot)

`multiply_permuted_body_by_digits` ran `d - 1 = 2047` times per output block,
and each call did `d = 2048` `u128 % u64` divisions plus a 16 KiB allocation.
Across four blocks that is **16.8 M divisions and 33 MB of allocation churn per
query**, and on x86 each division is a `__umodti3` libcall. `inspiring/` used
`barrett_reduction_u128` nowhere, while `simplepir-kernel` already used it.

Two structural facts made this more than a Barrett swap:

- **The collapse is a sum, not a chain.** In `collapse_uploaded_body_half` the
  running `c2` enters only through `add_into` — never permuted, never
  multiplied. So

  ```text
  b_final = NTT(b̃) + Σ_i τ_i(kg_body) · digits_i + kh_body · digits_last
  ```

  is a reduction over `d - 1` independent terms. It had been running as a serial
  loop parallel only across four blocks, so at most four of eight cores worked.

- **A whole block fits one accumulator.** Every product is under `(q-1)²` and
  there are `(d-1) · ell = 6141` of them, bounded by `2^124.6 < 2^128`. One
  `u128` per NTT slot absorbs the entire block and is reduced exactly once:
  2,048 reductions per block instead of 4.19 M.

The rewrite fuses all of it into one pass with a preallocated accumulator,
parallel over steps with per-thread partials. `fused_accumulator_fits` gates the
bound and falls back to the original per-step cascade for any future parameter
set that would violate it; `fused_collapse_matches_stepwise_cascade` pins the two
against each other at a 56-bit modulus.

## 2. Preprocessing: `Θ(d³)` → `Θ(d² log d)`

`build_a_agg` computed, for each of `d` output slots,
`out_e = Σ_j X^j · τ_e(ã_j)` by scatter-adding coefficients: `d³ = 8.59e9` inner
iterations per CRS block, and essentially all of the offline cost. The previous
report named the NTT-domain reformulation as "the real fix and still open".

It follows from two identities the codebase already relies on elsewhere — an
automorphism is an NTT slot permutation, and multiplying by `X^j` is pointwise
multiplication by `ω_s^j`:

```text
out_e[s] = Σ_j ω_s^j · Â_j[π_e(s)] = Q_{π_e(s)}(ω_s),   Q_v(Y) = Σ_j Â_j[v]·Y^j
```

With `s` fixed, `π_e(s)` runs over every slot as `e` varies, so the whole family
needs one table `E[v][s] = Q_v(ω_s)` — and evaluating `Q_v` at every `ω_s` *is* a
forward NTT. Total: `2d` length-`d` NTTs plus `O(d²)` data movement, against
`d³`.

The result is exact, not approximate: the NTT is a ring isomorphism, so it
agrees with the direct computation coefficient for coefficient.
`build_a_agg_matches_direct_transform` checks that against the retained `Θ(d³)`
implementation, and `python_oracle_match` passes unchanged.

That exposed the serial cascade underneath, which had three redundancies:

- 2,046 `automorphic_image` calls per block went through `tau_ntt`, documented
  in `automorph.rs` as the slow oracle hot paths must not use — 12 NTTs each,
  ~24,552 per block. They are slot permutations of one matrix, so they now come
  from composed tables.
- `collect_half_digits` computed the gadget digits, then called `collapse_one`,
  which recomputed them from the same `c1`. `collapse_one_with_digits` already
  existed, private and unused.
- `signed_gadget_invert_alloc` ran three hardware divisions and an `i128`
  `rem_euclid` per (coefficient, digit) — 12.6 M iterations per block — for a
  base `z` that is a power of two by construction.
- `build_pack_preprocessed_blocks` built independent blocks with `.iter()` while
  the function directly below it used `par_iter`.

## 3. Bandwidth: 935,939 → 318,464 bytes per query (2.94×)

Three changes; the third is only affordable because of §1 and §2.

**(a) The response's `c1` row is a snapshot constant.** It is
`QueryPackPreprocessed::collapse_a_final_ntt`, built from the CRS and two fixed
reference seeds — it does not depend on the query, the client secret, or the
uploaded packing keys, so it is byte-identical for every client and every query
against a snapshot. It was 28,672 of every 49,152 response bytes. It is now
served once from `GET /public-params`, at full `q` precision rather than
switched to 28 bits, which also removes the rounding term it used to contribute
to the client's decryption noise.

**(b) The query was transmitted at the full 56-bit modulus.** 788,480 of
886,784 upload bytes were first-dimension coefficients at full ciphertext
precision. Rounding to `k` bits injects at most `q / 2^(k+1)` per row, which the
matrix-vector product amplifies to roughly `(q/2^k) · p · √db_rows` at `6σ`;
`query_modulus_bits` picks the smallest `k` holding that at or below `Δ/64`, six
bits under the `Δ/2` decryption threshold. The target is a power of two so the
server's lift back to `q` is a shift, not a division.

Query privacy is unaffected — the rounding uses no secret, so it is
post-processing of an already-secure LWE sample, and any distinguisher against
the rounded query gives one against the unrounded query by applying the same
rounding. What it spends is decryption headroom, not hardness.

**(c) The aspect ratio moves again.** Upload scales with rows, download with
columns, their product fixed by the dataset. With the per-byte costs from (a)
and (b), total wire is minimized near 21 instances, but the curve is flat from
16 to 28 while packing work, offline work, and the resident `digits_ntt` cache
all grow linearly in the block count. Sixteen sits at the near-flat end — 2%
more wire than the optimum for 24% less packing work and 24% less memory:

| | before | after |
|---|---:|---:|
| `SIMPLEPIR_INSTANCES_PER_ITEM` | 4 | 16 |
| rows × cols | 112,640 × 8,192 | 28,672 × 32,768 |
| nullifiers per row | 448 | 1,792 |
| packing keys | 98,304 B | 86,016 B |
| first-dimension query | 788,480 B | 150,528 B |
| response | 49,155 B | 81,920 B |
| **total wire** | **935,939 B** | **318,464 B** (**2.94×**) |

Two side effects worth naming. The key bodies are now bit-packed at 56 bits
instead of raw `u64`, which the original plan had targeted and never delivered.
And at 28,672 rows the first-dimension delayed-reduction window covers a whole
column, so the kernel sweeps the database in one pass instead of two — the
window fix the plan called for, obtained from the shape rather than from tuning
`DEFAULT_CHUNK_ROWS`.

## Correctness work this forced

**A latent AVX-512 overflow.** `U16Avx512Kernel` never clamped its
delayed-reduction window at all; it was correct only because production
plaintexts happen to be 14-bit. The window bound is now derived from an
`element_max` measured over the database at load and threaded through
`FirstDimKernel::multiply_query`, so both kernels size it from the real bound
rather than from `u16::MAX` (too loose to be safe) or the plaintext modulus (a
contract nothing enforced).

**`/public-params` served an empty body.** `Backend::public_params` was not
forwarded through the enum wrapper, so the default trait implementation returned
`Vec::new()` and the client failed on a length assertion. Only the live HTTP run
caught this — no unit test exercises the enum wrapper's forwarding.

**Packing key bodies were never range-checked.** Pre-existing, but the fused
collapse's accumulator bound is stated in terms of `q`, and bit-packing at
`ceil(log2 q)` still admits values in `[q, 2^56)`. `validate_packing_key_body`
now rejects unreduced coefficients.

## End-to-end HTTP, finally

The previous pass could not run one — `data/nullifiers.bin` was absent on its
host — so the fixture remap it published was arithmetic, not measured. This pass
ran the live flow against a 4,000,000-record synthetic snapshot (2,233 PIR rows
at 1,792 nullifiers per row), exercising `/meta`, `/public-params`, the switched
query and the sixteen-block packing:

| case | result |
|---|---|
| record 2,000,000 (mid-snapshot) | found at row 1,116, offset 128, verified |
| record 3,999,999 (last record) | found at row 2,232, offset 255, verified |
| all-zero nullifier | correctly reported absent |

`NULLIFIER_FIXTURE.md` is updated for 1,792 nullifiers per row: record
1,638,400 is now row 914, offset 512. That mapping is still arithmetic — it is
stated as `record / nullifiers_per_row` so it is obvious it moves with the
packing constant — but the arithmetic itself is now exercised by the runs above.

## Corrections to the plan's estimates

- **Snapshot encoding: predicted 50–100×, measured 1.9×.** `read_bits_le` did
  loop one bit at a time over billions of iterations, but the compiler unrolls
  that loop far better than the estimate assumed. Word-at-a-time extraction
  takes the full-database encode from ~3.3 s to ~1.7 s — worth having, not the
  order of magnitude claimed.
- **AVX-512 IFMA is not available.** The plan proposed replacing the split-limb
  `mul_epu32` scheme with `madd52`. The Xeon 8358 reports `avx512f/bw/cd/dq/vl`
  plus `vbmi/vnni/bitalg/vpopcntdq` — but not `avx512ifma`. Dropped.
- **Packing did not reach ~5 ms.** The fused pass still streams the digit blocks
  and permutation tables, roughly 117 MB per block per query, so it is
  memory-bound well above the arithmetic floor.

## Not done

- `TopKeyImages::validate` still walks 2,046 cached images per query. Left
  alone: it is shape checks on a structure fixed at construction, and against a
  packing stage in the tens of milliseconds it does not register.
- The column-major materialization in `YServer::with_kernel` is still a
  scatter — one write per element, each to a different cache line. Blocked
  transposition is the fix; not attempted here.
- `generate_hint_from_query_polys` (450k length-2048 NTTs per snapshot) is still
  untimed by any benchmark. It is now plausibly the largest remaining offline
  term and should get a timer before anything else offline is optimized.
- `simplepir-kernel/benches/first_dim.rs` still hardcodes `112,640 × 8,192`, so
  it no longer measures the deployed shape. Kept as-is here precisely so the
  baseline and new trees are compared on identical input.

## Results

All measured on the Xeon host described above, `0e16fc1` against this tree.

### Offline preprocessing — `cargo bench -p inspiring --bench pack -- offline`

| parameter set | baseline | this pass | |
|---|---:|---:|---:|
| `d = 1024`, `q` 28-bit (4 chunks) | 9.075 s | 2.171 s | **4.18×** |
| `d = 2048`, `q` 56-bit (2 chunks) | 17.592 s | 2.345 s | **7.50×** |

Per CRS block at `d = 2048`: **8.80 s → 1.17 s**. The arm64 development host saw
4.6× on the same change; x86 gains more, exactly as the previous report
predicted for the division removals it could not measure.

### First-dimension kernel — `cargo bench -p simplepir-kernel --bench first_dim`

The benchmark hardcodes `112,640 × 8,192`, so both trees run identical input.
That is deliberate — and it means this table measures only the `element_max`
change, which at that shape leaves the reduction window exactly where it was:

| threads | kernel | baseline | this pass |
|---:|---|---:|---:|
| 1 | portable | 236.81 ms | 235.92 ms |
| 1 | AVX-512 | 224.95 ms | 220.40 ms |
| 4 | portable | 82.07 ms | 72.78 ms |
| 4 | AVX-512 | 59.73 ms | 60.18 ms |
| 8 | portable | 55.09 ms | 55.35 ms |
| 8 | AVX-512 | **51.36 ms** | **50.69 ms** |

Read this as "no change", which is the honest result: the differences are within
run-to-run spread. The kernel benefit of this pass comes from the shape — at
28,672 rows a column fits one reduction window, so the sweep is single-pass —
and this benchmark cannot see that because it pins the old dimensions.

`avx512_u16_matches_chunked_when_supported` **executed for the first time** on
this host: the parallelized AVX-512 kernel is bit-identical to the portable one.
It had never run anywhere, on any host, before this.

### Online server path — `IPIR_SP_BENCH_NULLIFIER=1 cargo bench -p ipir-sp --bench end_to_end`

Each tree runs at its own deployed shape, which is the comparison that matters:
baseline at `112,640 × 8,192` with four output blocks, this pass at
`28,672 × 32,768` with sixteen. From `one_shot_server_breakdown_us`:

| stage | baseline (4 blocks) | this pass (16 blocks) | |
|---|---:|---:|---:|
| deserialize query | 1.61 ms | 0.36 ms | 4.45× |
| matrix-vector | 54.05 ms | 52.01 ms | 1.04× |
| packing | 82.22 ms | 66.80 ms | 1.23× |
| serialize response | 1.05 ms | 3.21 ms | 0.33× |
| **total** | **138.93 ms** | **122.39 ms** | **1.14×** |

The headline 1.23× on packing understates the change, because the new shape
packs four times as many blocks. **Per block it is 20.55 ms → 4.18 ms, 4.92×**,
and that is what paid for the bandwidth reduction. Serialization is the one
stage that is worse in absolute terms — four times the blocks against 1.31×
better per block.

The matrix-vector time barely moves: the product of the dimensions is fixed, so
the same 1.85–1.88 GB is streamed either way. The single-pass sweep the new row
count enables offsets the slightly larger padded database.

### Wire

Measured, from `measured_upload_bytes` and the reported response size:

| | baseline | this pass | |
|---|---:|---:|---:|
| packing keys | 98,304 B | 86,016 B | 1.14× |
| first-dimension query | 788,480 B | 150,528 B | 5.24× |
| response | 49,152 B | 81,920 B | 0.60× |
| **total per query** | **935,936 B** | **318,464 B** | **2.94×** |

`||e_pack||_inf_bits` is **34 in both trees** — the fused collapse is exact, so
packing noise is unchanged.

The synthetic bench fixture measures packing noise only, so it cannot see the
query switch. `production_params_flow` measures the real pipeline end to end at
`d = 2048`, `q ≈ 2^56`, `p = 2^14` and the deployed 28,672 rows:

```text
production flow: ||e||_inf = 2^36 against delta/2 = 2^41 (query at 42 bits)
```

Five bits of headroom, with the switch contributing about two bits over the
2^34 packing floor — which is what the `Δ/64` target in `query_modulus_bits`
was chosen to buy.

## Reproducing

Baseline is `0e16fc1`; note that `ac0929b` on the same branch already contains
this pass's `preprocess.rs` work, so it is not a usable baseline.

```bash
# offline preprocessing, both parameter sets
cargo bench -p inspiring --bench pack -- offline

# first-dimension kernel; pins 112,640 x 8,192 for comparability
for t in 1 4 8; do
  RAYON_NUM_THREADS=$t cargo bench -p simplepir-kernel --bench first_dim
done

# deployed shape: server breakdown, wire accounting, packing noise
IPIR_SP_BENCH_NULLIFIER=1 cargo bench -p ipir-sp --bench end_to_end

# real-pipeline noise margin at production RLWE parameters
cargo test -p ipir-sp --release --test production_params_flow -- --nocapture
```

Live HTTP, which needs a snapshot rather than a fixture:

```bash
cargo run --release -p nullifier-pir -- serve \
  --snapshot-path data/nullifiers.bin --backend local-ipir --port 8080
cargo run --release -p nullifier-pir -- query \
  --server-url http://127.0.0.1:8080 --snapshot-path data/nullifiers.bin \
  --nullifier-hex <64 hex chars>
```

The client fetches `GET /public-params` once before its first query; a server
that does not serve it will fail the client's `published c1 length` assertion.
### Production offline path — `offline_crs_extract_and_preprocess`

This is the one that gates snapshot rebuilds: `build_pack_preprocessed_blocks`
over every CRS block of the deployed shape.

| | baseline (4 blocks) | this pass (16 blocks) | |
|---|---:|---:|---:|
| wall time | 37.574 s | **6.649 s** | **5.65×** |
| per CRS block | 9.394 s | 0.416 s | **22.6×** |

Four times the blocks in a fifth of the time. The per-block figure is better
than the 7.50× the `inspiring` microbenchmark shows because that one measures a
single block serially, while this also picks up the `par_iter` across
independent blocks.

### Criterion groups, side by side

Baseline at four blocks, this pass at sixteen:

| group | baseline | this pass |
|---|---:|---:|
| `online_deserialize_query_only` | 1.515 ms | 364.4 µs |
| `multiply_query_only_scalar` | 5.768 s | 5.784 s |
| `multiply_query_only_chunked_split` | 53.94 ms | 53.14 ms |
| `offline_crs_extract_and_preprocess` | 37.574 s | 6.649 s |
| `online_pack_only` | 83.65 ms | 73.19 ms |
| `online_serialize_only` | 937.5 µs | 2.597 ms |
| `online_pack_and_serialize` | 75.77 ms | 76.33 ms |
| `client_decode_only` | 1.073 ms | 3.241 ms |

## Combined effect

| metric | baseline | this pass | |
|---|---:|---:|---:|
| total wire per query | 935,936 B | 318,464 B | **2.94×** |
| offline preprocessing (deployed shape) | 37.574 s | 6.649 s | **5.65×** |
| offline per CRS block | 9.394 s | 0.416 s | **22.6×** |
| `inspiring` offline, `d = 2048` | 17.592 s | 2.345 s | **7.50×** |
| online server total | 138.93 ms | 122.39 ms | **1.14×** |
| packing per output block | 20.55 ms | 4.18 ms | **4.92×** |
| `‖e_pack‖∞` (packing only) | 2^34 | 2^34 | unchanged |
| real-pipeline `‖e‖∞` vs `Δ/2 = 2^41` | — | 2^36 | 5 bits spare |

The honest summary: the preprocessing and bandwidth wins are large, and online
server time is only slightly better because most of the packing win was spent
on the four-fold increase in output blocks that bought the bandwidth. If the
shape were held at four blocks, packing alone would be roughly 4.9× faster; that
option remains open if latency ever matters more than wire.

Client decode moves the same way — 1.07 ms to 3.24 ms absolute, but 268 µs to
203 µs per block. Every per-block figure improved; the absolute online figures
carry four times the blocks.
