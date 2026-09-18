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

## FULL / NULLIFIER note

`d=2048` profiles skip ReinspiRING preprocess in the Criterion fixture (`Compile` cost). Only `online_pack_inspiring` runs there until the O(d² log d) Compile path is production-ready.

## MID

Not run in this report (setup cost). Use:

```bash
IPIR_SP_BENCH_MID=1 cargo bench -p ipir-sp --bench end_to_end
```
