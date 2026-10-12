# 8-bit entries with one-key packing: measurements

Timing and memory for the experimental p = 2^8 native profile, against the
deployed p = 2^16 profile. All runs use one-key two-mask output (the client
uploads K_g only), 28,672 rows and 64 KiB per row, at the pinned 28-bit query,
10-bit response and 22-bit mask widths. Certificates are in
[`certificates/`](certificates/README.md).

## Result (Xeon Platinum 8358, 8 workers)

| | Deployed (p16, 49-bit query) | p8, two-digit K_g | p8, one-digit K_g |
|---|---:|---:|---:|
| Upload per query | 203,300 B | 128,036 B (−37%) | 114,212 B (−44%) |
| Download per query | 90,180 B | 81,988 B (−9%) | 81,988 B (−9%) |
| Published masks per snapshot | 237,604 B | 360,484 B (+52%) | 360,484 B (+52%) |
| Server, 8 / 1 workers | 47.5 / 202 ms | 50.7 / 208 ms | 56.1 / 251 ms |
| Offline setup | 39 s | 56 s | 55 s |
| RSS after build | 2.34 GB | 2.80 GB | 2.97 GB |
| Packing matrices | 454 MB (packed 27-bit) | 907 MB (packed 27-bit) | 1,075 MB (i64) |

Production InspiRING uploads 236,544 B, so the two-digit profile uploads
1.85× less and the one-digit profile 2.07× less.

- **Byte storage keeps the server flat.** With u8 storage and low-digit
  skipping the scan takes 35 ms against 38 ms today. The same profile in u16
  scans in 71 ms and needs 4.68 GB. The added server time is packing twice
  the blocks (13.5 against 6.9 ms).
- **One digit costs memory.** Its matrices need 34–35-bit entries, so they are
  stored as i64 and packing is slower (19.5 against 13.5 ms).
- **No regression on u16 profiles.** Main's binary measured 48.8 / 46.2 ms
  (49 / 43-bit query) against 47.5 / 45.3 ms here. A reverse-order repeat pass
  (`*-c1`) agrees within 4%.
- **Without VNNI** (Apple M4 Max, portable scan) the p8 profile answers in
  51 ms against 27 ms today.

Per-worker timings, the isolated scan (`dot-*`), client costs and memory
checkpoints are in the raw JSONL; `summarize.py` tabulates them.

## wallet-pir memory projection

`project_wallet.py` multiplies the measured per-block packing bytes and the
database bytes by the tables in `wallet-inventory.json` (wallet-pir
`a317455e`). It is an estimate: it leaves out context tables, allocator
overhead and request transients, and assumes AVX-512 VBMI hosts.

| Host | Today | p8 two-digit u8 | p8 one-digit u8 | Budget |
|---|---:|---:|---:|---|
| Transparent archive | 37.7 GB | 42.3 GB | 44.0 GB | 48 GiB cache |
| Transparent recent | 0.96 GB | 1.47 GB | 1.66 GB | 5 GiB cache |
| Txid display | 15.7 GB | **27.7 GB** | 32.2 GB | **24 GiB cache** |
| Enhance, per domain | 0.98 GB | 1.05 GB | 1.11 GB | 8 GiB host |

The Transparent tiers fit only if wallet-pir also stores entries as bytes.
Txid display does not fit.

## Limits

- Synthetic uniform fixtures, not a real snapshot.
- The Xeon binaries predate the floor pin (`ff1bc0e`); every measured width is
  at or above the pinned floors.
- The Mac shared the machine with other work; the Xeon ran only these runs.

## Reproduction

Build the `native_e2e` and `native_dot` examples in release with
`--features native-reinspiring` (on the Xeon with
`RUSTFLAGS='-C target-cpu=native'`), then run `bench.sh` (Xeon, against a
main build) or `bench-mac.sh`, then `summarize.py` and `project_wallet.py`.
Hosts: a temporary DigitalOcean `g-8vcpu-32gb-intel` droplet (`raw-xeon/host.json`)
and an Apple M4 Max; Rust 1.89. Database seed 0x2417, setup `[7;32]`,
snapshot `[19;32]`, request RNG 0x2418.
