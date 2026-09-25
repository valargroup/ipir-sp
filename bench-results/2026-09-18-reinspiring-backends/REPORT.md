# Dual-backend packing: InspiRING vs ReinspiRING

Date: 2026-09-18  
Host: Cursor cloud agent VM  
Profile: default SMALL (`d=64`, 64×128, one RLWE output)

## Commands

```bash
cargo bench -p ipir-sp --bench end_to_end -- --warm-up-time 1 --measurement-time 3
```

Raw log: [`raw/small-d64.log`](raw/small-d64.log)

## Correctness vectors

Committed under [`ipir-sp/fixtures/`](../../ipir-sp/fixtures/):

| Fixture | Shape | Check |
| --- | --- | --- |
| `tiny_d8_q12289_seed42.json` | `d=8`, `q=12289` | both backends == golden `c1`/`c2` |
| `prodlike_d16_q56bit_seed9.json` | `d=16`, 56-bit single-CRT `q` | both backends == golden `c1`/`c2` |

Regenerate: `IPIR_SP_WRITE_FIXTURES=1 cargo test -p ipir-sp --test pack_correctness_vectors write_fixtures_when_env_set`

Tests: `pack_correctness_vectors`, `pack_backend_dual` (tiny + prodlike non-zero CRS).

## One-shot stderr (SMALL)

```
H'_inf_bits≈6.8
packing_inspiring=41 µs
packing_reinspiring=92 µs
```

## Criterion medians (SMALL)

| Id | Median |
| --- | ---: |
| `online_pack_inspiring/1` | ~20.0 µs |
| `online_pack_reinspiring/1` | ~63.9 µs |
| `online_pack_and_serialize/1` (Inspiring) | ~23.8 µs |

At this tiny development shape ReinspiRING is slower: the coefficient `H'·y` path is not yet SIMD-tuned, and leftover `t''·y'` is schoolbook. The win from native moduli / smaller-norm material shows up at larger `d` and power-of-two `q` (paper eval), not on `d=64` with an NTT-friendly 14-bit prime.

## Paper degree pack-only (`d=2048`, odd production `q`)

**Wrong comparison for ReinspiRING’s claimed speedup.** Pack-only microbench on production odd single-CRT `q` (56-bit) with `ℓ=3`. Paper §5.1 uses hardware-native `q = 2^54`, `ℓ = 2` — see the next section.

```bash
cargo bench -p ipir-sp --bench pack_backends_d2048
```

Raw log: [`pack_backends_d2048.log`](pack_backends_d2048.log)

| Id | Median |
| --- | ---: |
| `online_pack_inspiring/2048` | ~1.86 ms |
| `online_pack_reinspiring/2048` | ~40.3 ms |

On NTT-friendly odd `q`, ReinspiRING pays Barrett-style reduction and cannot use free `q=2^k` masks — so it looks much slower here. That is expected and not the paper eval.

## Paper eval: ReinspiRING at `q = 2^54` (§5.1 / Table 5)

```bash
cargo bench -p reinspiring --bench paper_q254
```

Raw log: [`paper_q254.log`](paper_q254.log)

Params: `d=2048`, `q=2^54`, `ℓ=2`, `z=2^19` (approximate gadget; `z^ℓ ≪ q`).

| Step | This host | Paper Table 5 |
| --- | ---: | ---: |
| Compile preprocess | 81.2 s | 3.9 s |
| **`H'·y` matvec** | **~1.12 ms** | **~1.2 ms** |
| Leftover `t''·y'` (schoolbook) | ~21.1 ms | (lifted NTT; in Pack ≈ 13.6 ms total) |

`H'·y` matches the paper once the hardware-native modulus and bitmask reduction are used. Full Pack is still slower than Table 5 because leftover multiply is schoolbook (`Q > d q² = 2^119` needs a multi-word lift path). The paper’s end-to-end ~2× is ReinsPIRe vs InsPIRe under these native moduli, not an odd-`q` dual-backend race.

## MID

Not run in this report (setup cost). Use:

```bash
IPIR_SP_BENCH_MID=1 cargo bench -p ipir-sp --bench end_to_end
```
