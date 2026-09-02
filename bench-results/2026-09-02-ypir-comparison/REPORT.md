# IPIR+SP vs YPIR+SP — re-baseline

Date: 2026-09-02

The 2026-05-10 report compared the initial IPIR+SP port against upstream
YPIR+SP. Three optimization passes later that comparison was stale, and the
README carried a "not yet re-baselined" caveat. This is the re-baseline.

## Environment

- Host: `roman-ipir-bench-8vcpu`, DigitalOcean `g-8vcpu-32gb-intel` in `ams3` —
  the same slug and region as `vote-nullifier-pir-primary-prod`.
- CPU: Intel Xeon Platinum 8358 @ 2.60 GHz, 8 cores, no hyperthreading,
  AVX-512F (no `avx512ifma`). 31 GiB RAM, `rustc 1.89.0`.
- IPIR+SP: `main` at `2bc1075`. YPIR+SP: upstream pinned at `4f7ef3d`, the same
  revision the 2026-05-10 report used, via `--features ypir-artifact`.
- Snapshot: 49,925,853 records × 32 bytes = 1,597,627,296 bytes — the exact
  production dimensions. Contents are synthetic (the host has no egress to the
  snapshot CDN); contents affect neither timing nor wire size.

Both systems run through the same `nullifier-pir` HTTP harness, over the same
snapshot file, with the same record-to-row encoding, and both were queried for
the same record (global index 25,000,000). The backend actually under test is
read back from `GET /meta` before any query is issued — an earlier run of this
comparison silently measured IPIR+SP twice because a stale server held the port,
and the guard exists because of it.

Raw logs in `raw/`. Medians of 3–5 trials; spread was under 3% throughout.

## Results

`inst` is `SIMPLEPIR_INSTANCES_PER_ITEM`, the number of RLWE output blocks per
row. It is the shape knob both systems share.

| system | inst | rows × cols | matvec | packing | total server | upload | download | **total wire** |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| **IPIR+SP** | 16 | 28,672 × 32,768 | 49.6 ms | 66.9 ms | **120.0 ms** | 236,544 B | 81,920 B | **318,464 B** |
| YPIR+SP | 16 | 32,768 × 32,768 | 460.0 ms | 743.0 ms | 1208.4 ms | 802,816 B | 196,608 B | 999,424 B |
| **IPIR+SP** | 4 | 112,640 × 8,192 | 52.1 ms | 17.3 ms | **72.7 ms** | 691,456 B | 20,480 B | **711,936 B** |
| YPIR+SP | 4 | 131,072 × 8,192 | 461.0 ms | 193.0 ms | 656.2 ms | 1,589,248 B | 49,152 B | 1,638,400 B |

At matched shape:

| | 4 instances | 16 instances |
|---|---:|---:|
| server time | **9.0×** | **10.1×** |
| total wire | **2.30×** | **3.14×** |
| packing per output block | 11.1× | 11.1× |
| first-dimension matvec | 8.9× | 9.3× |

Sixteen instances is IPIR+SP's tuned shape and four was the previous one, so
both are reported rather than only the flattering one. YPIR+SP's own best
configurations are four instances for latency (656 ms, 1.64 MB) and sixteen for
wire (999 KB, 1208 ms) — it faces a real trade-off between them, because CDKS
packing cost scales with the block count while its fixed 540,672-byte public
parameters push the optimum wide. IPIR+SP at sixteen instances beats **both** on
**both** axes simultaneously: 5.1× less wire and 5.5× less server time than
YPIR+SP's latency-optimal configuration, 3.1× and 10.1× against its
wire-optimal one.

## Which differences are the scheme, and which are the implementation

This matters, and the aggregate numbers hide it.

**Packing is the scheme.** InsPIRing's linear cascade against CDKS's recursive
one, and it is **11.1× per output block at both shapes** — 4.18 ms vs 46.44 ms
at sixteen instances, 4.33 ms vs 48.25 ms at four. That the ratio is identical
across a 4× change in block count is what you would expect from a per-block
constant-factor difference, and it is the cleanest signal in this report.

**The first-dimension matvec is not the scheme.** Both systems compute the same
SimplePIR product over the same database. The ~9× gap is our kernel against
upstream's: `simplepir-kernel` is rayon-parallel AVX-512 across 8 cores, and
upstream YPIR's first pass is effectively serial. Per database element the gap
is 52.8 ps vs 428.4 ps at sixteen instances, and essentially the same at four —
it tracks the core count, not the shape. Give upstream YPIR an equivalent
kernel and its server time would fall by roughly 410 ms at either shape: ~247 ms
at four instances against our 72.7 ms, still **3.4×**. The scheme advantage is
real but it is roughly a third of the headline number, not all of it.

A second, smaller implementation difference: YPIR pads its row count to a power
of two (32,768 rows for 27,861 items) where IPIR+SP pads only to a multiple of
`poly_len`. That is 14–16% more database streamed per query, and it is included
in the matvec figures above.

**Upload splits into both.** YPIR's CDKS public parameters are a fixed
540,672 B against IPIR+SP's 86,016 B of `(K_g, K_h)` bodies — **6.3×**, and this
is the scheme difference InsPIRe exists for. The first-dimension query is
implementation and tuning: 8 bytes per row for YPIR against IPIR+SP's 42-bit
modulus-switched coefficients, over fewer rows.

**Download is this workspace's own change.** 20,480 B against 49,152 B at four
instances, because IPIR+SP no longer repeats the snapshot-constant `c1` row in
every response.

## Offline preprocessing — the expected result has inverted

| | 4 instances | 16 instances |
|---|---:|---:|
| IPIR+SP cold start | **40 s** | **175 s** |
| YPIR+SP cold start | 109 s | 291 s |

Full-snapshot cold start: read and encode 1.6 GB, build the column-major
database, generate the hint, and run all packing preprocessing.

This is the finding worth flagging. InsPIRing buys its small upload by moving
work offline, and the paper's own accounting has that costing about 3×
(`SPEC.md`: 11 s → 36 s, "+225%, the price for the CRS-model speed-up").
`roman_notes.md` records the same expectation: *"InsPIRing is strictly worse
than CDKS in terms of pre-processing … roughly 3x overhead compared to YPIR."*
The 2026-05-10 report measured ~10× worse.

After the `Θ(d³) → Θ(d² log d)` reformulation of the CRS aggregate, IPIR+SP is
**2.7× faster** than YPIR+SP's offline phase at four instances and 1.7× at
sixteen. The trade InsPIRe explicitly opts into is no longer being paid here.

Resident memory also favours IPIR+SP: 3.16 vs 3.59 GiB at four instances,
5.76 vs 7.91 GiB at sixteen.

## Against the 2026-05-10 baseline

That report, same CPU model, initial port at `524,288 × 2,048`:

| | 2026-05-10 | now |
|---|---|---|
| Server time vs YPIR+SP | 31% **worse** | **9–10× better** |
| Offline vs YPIR+SP | ~10× **worse** | **1.7–2.7× better** |
| Packing public params | 5.5× better | 6.3× better |
| Total wire | 3,780,608 B | 318,464 B |

## Caveats

- Synthetic snapshot contents. Dimensions, encoding and record mapping are
  production's; contents cannot affect timing or byte counts.
- The matvec gap is implementation, not scheme — see above. A YPIR+SP with an
  equivalent kernel would land near 247 ms at four instances.
- Upstream YPIR is pinned at `4f7ef3d` and has not been re-tuned or updated;
  this is the same revision the original comparison used, chosen for continuity.
- Only two shapes were measured per system. Neither system's optimum was found
  by a full sweep, though the analytic wire model and the flat 11.1× packing
  ratio both suggest sixteen is close for IPIR+SP.

## Reproducing

`--features ypir-artifact` is required and is not covered by CI; it did not
compile at `2bc1075` (`BackendMetadata::published_c1_len` was missing from the
YPIR arm) and is fixed alongside this report.

```bash
head -c 1597627296 /dev/urandom > data/nullifiers.bin   # or the real snapshot
cargo build --release -p nullifier-pir --features ypir-artifact

# per backend: serve, confirm GET /meta reports the backend you asked for, query
cargo run --release -p nullifier-pir --features ypir-artifact -- serve \
  --snapshot-path data/nullifiers.bin --backend ypir-artifact --port 8102
cargo run --release -p nullifier-pir --features ypir-artifact -- query \
  --server-url http://127.0.0.1:8102 --snapshot-path data/nullifiers.bin \
  --nullifier-hex <64 hex chars>
```

Vary `SIMPLEPIR_INSTANCES_PER_ITEM` in `nullifier-pir/src/encoding.rs` to change
the shape; it drives both backends, so a rebuild moves them together.
