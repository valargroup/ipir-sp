# One-mask rounded and lossless public-mask publication

Follow-up to the two-mask upload reduction. The same RNP3 rounded encoding is
applied to the existing one-mask route, which halves the one-time snapshot
download without touching the per-query request or response. This is opt-in
experimental native cryptography; it does not approve the native profile for
production.

## Result

Full-size fixture: d=2048, q=2^54, p=2^16, two base-2^19 K_g limbs, Gaussian
sampler nominal sigma 6.4, 28,672 rows, 32,768 columns, 16 output blocks,
full-precision K_g and K_h. `screen.txt` is a counterfactual screen on the
lossless 54-bit setup; the 28- and 29-bit rows were regenerated with their own
precision-bound setup IDs (`noise-28.json`, `noise-29.json`).

| Published mask bits | Snapshot bytes | Conditional full-response failure bound |
| ---: | ---: | ---: |
| 64 (current RNP1) | 262,180 | <=2^-429 |
| 54 lossless | 221,220 | <=2^-429 |
| 32 | 131,108 | <=2^-427 (screen) |
| 29 (regenerated) | 118,820 | <=2^-333 |
| 28 (regenerated) | 114,724 | <=2^-161 |
| 27 | 110,628 | <=2^-42: rejected (screen) |

28 bits is the smallest precision meeting the 2^-128 target and reduces the
snapshot download by 56.2% against the current 64-bit encoding. Request upload
(230,948 B) and response (90,180 B) are unchanged. A full-size `native_e2e` run
at 28 bits decoded 10/10 responses with maximum phase error 3.06e10 against the
2^37 threshold.

## Relation to the two-mask route

The two-mask route's smallest certified precision is 29 bits (237,604 B) because
it carries two rounding terms. Against this one-mask baseline it costs about
123 KB more one-time download to save 27,648 B of upload per query, so it pays
back after roughly five queries per snapshot. Both routes remain opt-in.

## Noise accounting

The exporter adds the negacyclic matrix of `rounded(a) - a` under exponent 1 to
the existing collapse-secret matrix (which already includes the final K_h
residue) on the same original secret coefficients, then centers before taking
norms. No independence between rounding error and secret is assumed. The
deterministic budget, finite-sampler Chernoff calculation and union bound are
unchanged from [the argument](../../reinspiring/tools/security/NATIVE_CERTIFICATE.md).

The independent degree-8 schoolbook oracle checks every one-mask precision
screen from 24 through 32 bits, including the final K_h contribution. It also
checks the exact phase change against `(rounded(a) - a) * s` for the actual
packing mask and explicit rounding-tie and modular-wraparound coefficients.
Integration tests exercise one-mask 28..=32 and two-mask 27..=32 publication,
plus lossless 54-bit publication in both modes, through serialization and
ordinary/prepared decoding. Negative cases cover setup, mode and precision
mismatches, malformed lengths and versions, and noncanonical padding.

## Reproduction

```sh
RAYON_NUM_THREADS=8 cargo run --release -p ipir-sp --features native-reinspiring \
  --example native_noise -- 28672 32768 54 28 > noise-28.json
python3 reinspiring/tools/security/certify_native.py noise-28.json
python3 bench-results/2026-09-25-one-mask-rounded/screen.py noise-54.json
```

Each run took about 33 s on an Apple Silicon host with 8 Rayon threads.
