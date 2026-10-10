# 8-bit entries with one-key packing on the native path

Experimental, opt-in (`native-reinspiring`). This is a prototype and measurement,
not a production profile change. Follows the upload survey in valargroup/ipir-sp#28.

All configurations use the one-key two-mask mode: the client uploads K_g only.
Each 8-bit configuration is measured twice, with the shipped two-digit K_g
(base 2^19) and with a one-digit K_g (base 2^27).

## Result

On the production CPU (Xeon Platinum 8358, 8 workers):

| | Deployed wallet profile (p = 2^16, 49-bit query) | p = 2^8, two-digit K_g | p = 2^8, one-digit K_g |
|---|---:|---:|---:|
| Upload per query | 203,300 B | **128,036 B (−37%)** | **114,212 B (−44%)** |
| Download per query | 90,180 B | 81,988 B (−9%) | 81,988 B (−9%) |
| Published masks per snapshot | 237,604 B | 360,484 B (+52%) | 360,484 B (+52%) |
| Certified failure bound (target 2^-128) | ≤ 2^-228 | ≤ 2^-406 | ≤ 2^-209 |
| Server, 8 workers | 47.5 ms | 50.7 ms (+7%) | 56.1 ms (+18%) |
| Server, 1 worker | 202 ms | 208 ms (+3%) | 251 ms (+24%) |
| Offline setup (4 blocks in flight) | 39 s | 56 s | 55 s |
| Server RSS after build | 2.34 GB | 2.80 GB (+0.46 GB) | 2.97 GB (+0.63 GB) |
| Packing matrices | 454 MB (packed 27-bit) | 907 MB (packed 27-bit) | 1,075 MB (i64) |

Against production InspiRING (236,544 B upload), the two-digit profile is
**1.85×** smaller and the one-digit profile **2.07×**. Lattice security is
unchanged: same n = 2048, q = 2^54, σ = 6.4 instances. p and the gadget do not
enter the estimate, and the one-digit key sends half the key samples.

Three findings:

1. **8-bit storage is what keeps the server time flat.** Storing 8-bit entries
   one per byte, and skipping the all-zero low query digits, keeps the scan at
   35 ms against 38 ms today. Kept in u16, the same profile scans in 70.7 ms and
   needs 4.68 GB RSS.
2. **The one-digit key does not save server memory.** Its compiled packing
   matrices need 34–35-bit entries, so they are stored as i64 (1,075 MB). That
   is 18% more than the two-digit key's packed 27-bit matrices (907 MB), and
   packing is slower: 19.5 ms against 13.5 ms. It saves 13,824 B of upload per
   query.
3. **Packing memory doubles with the block count.** For wallet-pir that fits
   every host except the txid display host (projection below).

## What was built

- `NativeParams` admits digit widths and dropped bits up to 27. A one-digit
  base-2^27 K_g is valid at q = 2^54, and storage width and magnitude are reported.
- `NativeProfile`:
  - transport floors depend on the plaintext width: at p = 2^8, dithered queries
    ≥ 27 bits and two-mask masks ≥ 21 bits; p = 2^16 is unchanged;
  - `with_response_bits` (p+1..=p+6);
  - a size guard that counts storage bytes.
- `NativeServer::build_u8_*` stores one byte per entry and scans with a new
  AVX-512 VNNI byte-tile kernel (portable fallback). Responses are identical to
  u16 storage.
- The byte kernels skip all-zero low radix-256 query digits. A 28-bit query
  lifted to 2^54 needs 4 digit passes instead of 7.
- Two-mask analysis screens 16..=32-bit masks at p = 2^8.
- `certify_native.py`:
  - certifies p = 2^8 two-mask reports with any gadget and response width;
  - recorded certificates stay byte-identical;
  - `--screens` adds the width frontier and a data-independent query bound.
- Examples:
  - `native_e2e` gains gadget, response, storage and worker flags, memory
    checkpoints and an offline split;
  - `native_noise` and `native_dot` gain profile flags.

## Width selection and certificates

`screen.sh` exported one full-size report per gadget. Those reports used a
28-bit dithered query, lossless masks and 10-bit responses, at 28,672 × 65,536
(32 blocks) with uniform 8-bit entries. `certify_native.py --screens` then gave
the frontier:

| Gadget | Smallest certified points (query / response / masks) |
|---|---|
| Two-digit | 27 / 10 / 22 (2^-138); 28 / 9 / 22 (2^-187); 28 / 10 / 21 (2^-177) |
| One-digit | 28 / 10 / 22 (2^-209); 29 / 9 / 23 (2^-155) |

Both gadgets were measured at **28 / 10 / 22** so that the key is the only
difference. `certify.sh` regenerated each chosen width set with its own setup
ID (`raw-mac/certificate-*.json`):

| Profile | Request | Response | Published | Certified |
|---|---:|---:|---:|---:|
| two-digit 28/10/22 | 128,036 | 81,988 | 360,484 | ≤ 2^-406 |
| one-digit 28/10/22 | 114,212 | 81,988 | 360,484 | ≤ 2^-209 |
| two-digit 27/10/22 (smallest upload) | 124,452 | 81,988 | 360,484 | ≤ 2^-138 |
| two-digit 28/9/22 (smallest total) | 128,036 | 73,796 | 360,484 | ≤ 2^-187 |
| two-digit 28/10/22, 65,536 rows × 32,768 | 257,060 | 41,028 | 180,260 | ≤ 2^-236 |
| one-digit 28/10/22, 65,536 rows × 32,768 | 243,236 | 41,028 | 180,260 | ≤ 2^-150 |

Notes:

- **Large tables.** The 65,536-row checks show tables that large need no extra
  query bit at p = 2^8. At p = 2^16 they needed one.
- **Data-independent bound.** The two-digit screen certifies the query term even
  with every entry at 255: 2^-222, against 2^-147 for one digit.
- **p = 2^16 regression.** `raw-mac/noise-p16-regression-two-mask29-n49.json`
  equals the recorded 2026-10-09 report apart from three added keys
  (`ell`, `gadget_bits`, `dropped_bits`), and still certifies at 2^-228.

## Server time (Xeon Platinum 8358, `raw-xeon/`)

Medians of 20 samples after 3 warmups. Timings are by worker count.

| Config | Workers | Server ms | Scan ms | Packing ms |
|---|---:|---:|---:|---:|
| Deployed (p16, 49-bit query) | 1 / 2 / 4 / 8 | 202.1 / 111.1 / 63.5 / 47.5 | 172.0 / 94.2 / 53.1 / 38.1 | 27.7 / 14.5 / 8.0 / 6.9 |
| p16, 43-bit dithered query (#30) | 1 / 2 / 4 / 8 | 200.9 / 113.5 / 67.2 / 45.3 | 171.2 / 96.4 / 55.4 / 36.2 | 27.7 / 14.7 / 9.7 / 6.8 |
| p8, two-digit, u8 | 1 / 2 / 4 / 8 | 207.9 / 116.1 / 80.7 / 50.7 | 150.6 / 84.6 / 59.6 / 35.1 | 55.2 / 29.0 / 19.2 / 13.5 |
| p8, two-digit, u16 | 1 / 2 / 4 / 8 | 387.5 / 198.0 / 105.6 / 86.6 | 328.2 / 166.7 / 88.2 / 70.7 | 57.2 / 29.0 / 15.7 / 13.7 |
| p8, one-digit, u8 | 1 / 2 / 4 / 8 | 250.9 / 133.8 / 77.9 / 56.1 | 159.7 / 86.2 / 49.8 / 34.9 | 89.8 / 45.3 / 26.2 / 19.5 |

- **Repeat pass.** A second pass in reverse order (`*-c1`, 8 workers, sequential
  setup) agrees within 4%.
- **No regression versus main on unchanged u16 profiles.** Main's binary
  (`base-*`) measured 48.8 / 46.2 ms against 47.5 / 45.3 ms here.
- **Isolated scan** (`dot-*`, interleaved kernel). Each configuration scans
  1.88 GB of database bytes, except p8 in u16, which scans 3.76 GB.

  | Configuration | 1 worker | 8 workers |
  |---|---:|---:|
  | p16, 49-bit query | 177.6 ms | 37.3 ms |
  | p16, 43-bit query | 170.3 ms | 36.4 ms |
  | p8 u16, 28-bit query | 322.6 ms | 68.9 ms |
  | p8 u8, 49-bit query | 163.0 ms | 34.9 ms |
  | p8 u8, 28-bit query | 136.1 ms | 33.5 ms |

  At 8 workers the scan is memory-bound. On one worker the 8-bit tiles and digit
  skipping cut it by 23% against today's scan.
- **Apple M4 Max** (`raw-mac/mac-*`, portable scan, i32/i64 matrices):
  26.6 ms for the deployed profile, against 51.2 ms (p8 two-digit u8),
  56.7 ms (u16) and 53.5 ms (one-digit). Without byte kernels, the 8-bit scan
  costs twice as much on such hosts.

## Client

On the Xeon:

- **Request generation:** ~45 ms in every configuration.
- **Per-request decode preparation:** 3.7 ms (deployed profile) against 7.1 ms (p8).
- **Decode:** 0.6 ms against 1.2 ms.
- **Prepared decode cache:** 1 MiB against 2 MiB, as the block count doubles.

## Memory

| Xeon run | Database | Packing coefficients | RSS after build (trimmed) | Build peak, 4 blocks in flight / sequential | Request transient |
|---|---:|---:|---:|---:|---:|
| Deployed (p16) | 1.88 GB | 454 MB | 2.34 GB | 3.10 / 2.81 GB | ≤ 0.8 MB |
| p8 two-digit u8 | 1.88 GB | 907 MB | 2.80 GB | 3.91 / 3.36 GB | ≤ 1.8 MB |
| p8 two-digit u16 | 3.76 GB | 907 MB | 4.68 GB | 5.81 / 5.20 GB | ≤ 1.8 MB |
| p8 one-digit u8 | 1.88 GB | 1,075 MB | 2.97 GB | 3.66 / 3.21 GB | ≤ 1.7 MB |

- **Measurement.** RSS comes from `/proc/self/status`. The request transient is
  the peak increase across `respond`, measured after resetting VmHWM.
- **Storage width per block** (`matrix_storage`): two-digit blocks are packed
  27-bit on VBMI hosts (i32 on the Mac); one-digit blocks are i64 everywhere,
  with 34–35-bit magnitudes.
- **A follow-up worth having:** a packed 35-bit format for one-digit matrices
  would be about 17 MiB per block. Not built.

## wallet-pir memory projection (`wallet-projection.md`)

`project_wallet.py` applies the measured per-block packing bytes
(28.3 MB two-digit, 33.6 MB one-digit) and database bytes to the tables in
`wallet-inventory.json`. Inputs come from wallet-pir `a317455e`, with citations.
The projection is an estimate: context tables, allocator overhead and request
transients are not included, and it assumes VBMI-class hosts.

| Host | Today | p8 two-digit u8 | p8 one-digit u8 | p8 two-digit u16 | Budget |
|---|---:|---:|---:|---:|---|
| Transparent archive (82 shards × 2 tables) | 37.7 GB | 42.3 GB | 44.0 GB | 75.3 GB | 48 GiB cache |
| Transparent recent (9 shards × 2) | 0.96 GB | 1.47 GB | 1.66 GB | 1.93 GB | 5 GiB cache |
| Txid display (426 runtimes) | 15.7 GB | **27.7 GB** | 32.2 GB | 31.3 GB | **24 GiB cache** |
| Enhance router, per 32,768-row domain | 0.98 GB | 1.05 GB | 1.11 GB | 1.79 GB | 8 GiB host, memory gate failing |
| Status | 0.19 GB | 0.23 GB | 0.25 GB | 0.31 GB | P4000 host; masks refresh about every 20 s |

What the projection means per product:

- **Transparent archive and recent tiers:** fit, but only with u8 storage, which
  wallet-pir would have to port; its hint and runtime take `&[u16]` today.
- **Txid display:** does not fit its cache at p = 2^8.
- **Enhance:** grows little per domain, because 8-bit rows pad better (11 blocks
  against 6). Packing per domain goes from 170 MB to 312 MB.
- **Status:** gains nothing. Its masks change every generation, so each lookup
  downloads the larger published masks.
- **Host CPU class:** the per-block numbers assume AVX-512 VBMI. On hosts
  without it, two-digit blocks are i32, about 19% more.

## Limits

- **Fixture-only certificates.** Certificates cover these synthetic uniform
  fixtures only. Every served snapshot still needs its own report and
  certificate, and the floors are fixture minima.
- **Margins.** The p = 2^8 response uses 2^43 of the 2^45 decoding radius
  deterministically. The largest measured phase error was 1.25·10^13 (36% of the
  radius) with two digits.
- **Review.** One-digit residues are 2^11 larger and remain correlated with the
  secret; the certificate combines them exactly, but the profile is unreviewed.
  The native KDM review gate still applies to all of this.
- **Shared Mac.** The Mac runs share the machine with development work. The Xeon
  ran only these benchmarks, but load averages reflect the benchmark's own
  threads (`raw-xeon/log.txt`).
- **Floors changed after the Xeon run.** The Xeon binaries were built at
  `ff1bc0e`, before the floors were pinned (`9dc7594`). The pin changes only API
  validation; every measured width is at or above the pinned floors.

## Reproduction

```sh
# Release examples (Xeon: RUSTFLAGS='-C target-cpu=native', separate target dir)
cargo build --release -p ipir-sp --features native-reinspiring \
  --example native_e2e --example native_noise --example native_dot
bench-results/2026-10-09-p8-native/screen.sh  <examples> raw-mac   # frontier
bench-results/2026-10-09-p8-native/certify.sh <examples> raw-mac   # chosen widths
bench-results/2026-10-09-p8-native/bench.sh   <head-examples> <main-examples> raw-xeon
bench-results/2026-10-09-p8-native/bench-mac.sh <examples> raw-mac
python3 bench-results/2026-10-09-p8-native/summarize.py
python3 bench-results/2026-10-09-p8-native/project_wallet.py
```

**Hosts:**
- Temporary DigitalOcean `g-8vcpu-32gb-intel` droplet (ams3, destroyed after
  the run): Xeon Platinum 8358, AVX-512 VNNI and VBMI, 32 GB, Rust 1.89
  (`raw-xeon/host.json`, `raw-xeon/SHA256SUMS`).
- Apple M4 Max, 128 GB, Rust 1.89.

**Fixtures:** database seed 0x2417, setup `[7;32]`, snapshot `[19;32]`,
request RNG 0x2418.
