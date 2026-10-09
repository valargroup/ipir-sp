# Dithered native query transport

The client rounds each query coefficient up with probability equal to its
dropped fraction instead of rounding to nearest. The certificate then budgets
query rounding as a Hoeffding variance term instead of a worst-case sum, and
the query body can drop from 49 to 43 or 44 bits per row. This is opt-in
experimental native cryptography; it does not approve the native profile for
production.

## Result

Full-size fixture: d=2048, q=2^54, p=2^16, two base-2^19 K_g limbs, Gaussian
sampler nominal sigma 6.4, 28,672 rows, 32,768 columns, 16 output blocks.
Every row below was regenerated with its own precision-bound setup ID and
certified by `certify_native.py` (`certificate-*.json`).

| Profile | Query | Query bytes | Request bytes | Certified failure bound |
| --- | --- | ---: | ---: | ---: |
| One mask, full keys, RNP1 | 49 nearest (current) | 175,616 | 230,948 | <=2^-405 |
| | 44 dithered | 157,696 | 213,028 | <=2^-406 |
| | 43 dithered | 154,112 | 209,444 | <=2^-208 |
| Two masks, 29-bit RNP3 | 49 nearest (current) | 175,616 | 203,300 | <=2^-228 |
| | 44 dithered | 157,696 | 185,380 | <=2^-230 |
| | 43 dithered | 154,112 | 181,796 | <=2^-147 |

44 dithered bits certifies at least as strongly as today's 49 nearest bits and
saves 17,920 B per request (7.8% one-mask, 8.8% two-mask). 43 bits is the
smallest precision meeting the 2^-128 target in both modes and saves 21,504 B
(9.3% and 10.6%). The `query_screen` in each certificate shows 42 bits fails
(<=2^-54 one-mask, <=2^-48 two-mask on the 49-bit setups). Response
(90,180 B) and published snapshot bytes are unchanged.

Large tables gain the most. On a 65,536-row, 16,384-column two-mask 29-bit
report (`noise-two-mask29-65536-n49.json`), today's 49-bit nearest query
certifies <=2^-158. The counterfactual screen gives <=2^-295 for dithered
queries at the same 49 bits, and 44 bits is the smallest dithered precision
meeting 2^-128 (<=2^-186). Those dithered rows are a screen on the nearest
setup, not regenerated certificates.

## End-to-end runs

`native_e2e` at full size, 20 queries per configuration (3 rotating targets),
6 Rayon workers. All 80 responses decoded to the expected rows.

| Configuration | Upload | Max phase error (threshold 2^37 = 1.37e11) |
| --- | ---: | ---: |
| One mask, 49 nearest | 230,948 B | 1.58e10 |
| One mask, 43 dithered | 209,444 B | 2.43e10 |
| Two masks 29-bit, 49 nearest | 203,300 B | 2.34e10 |
| Two masks 29-bit, 43 dithered | 181,796 B | 3.46e10 |

The larger phase error at 43 bits is expected: each rounding error is now up to
2^11 rather than 2^4, and the errors cancel instead of being absent. The
certificate, not the measured maximum, is the correctness claim.

Server work is the same by construction: the server parses a narrower body and
lifts it to the same 54-bit words, and every matrix-vector backend does the
same fixed integer work regardless of word values. Client generation adds one
ChaCha20 draw per row. The sequential runs above showed 20-25% slower server medians for the
dithered configurations, so three interleaved rounds (`paired-*.jsonl`,
`paired.log`, 10 queries each, one-mask 49 nearest then 43 dithered) repeated
the comparison. The dithered/nearest server-median ratio was 0.62, 1.14 and
0.63 across rounds, with 1-minute load averages of 8 to 12 on 8 vCPUs: the
host cannot resolve a server-time difference in either direction, and the
earlier gap was host load. Parse time fell in every round (1.63-1.73 ms to
1.49-1.51 ms) because the body is 21,504 B smaller. Client generation ratios
were 0.80, 1.01 and 0.90, also within host noise.

## Noise accounting

Nearest rounding reserves `2^(53-t) * max_column_L1` deterministically (16 L1 at
49 bits). Dithered rounding removes that term. Conditional on every sampler draw,
the rounding errors are independent, zero-mean and lie in intervals of width
2^(54-t), so Hoeffding's lemma bounds their moment generating function by
`exp(lambda^2 * 2^(2(54-t)) * ||column||_2^2 / 8)` for every lambda. That
bound multiplies into the existing finite-sampler Chernoff calculation without
assuming independence from the secret or errors. The exporter adds the per-block
envelope `query_l2_squared`. See
[the argument](../../reinspiring/tools/security/NATIVE_CERTIFICATE.md#dithered-query-bodies).

## Host

Measured on `roman-dev-2` (`host.json`): an 8-vCPU DigitalOcean droplet that also
runs the development hub. The Mac used for earlier evidence could not run new
build scripts during this session. Certificates are deterministic and
host-independent. Timings are only meaningful as within-round comparisons.

## Reproduction

```sh
cargo build --release -p ipir-sp --features native-reinspiring --examples
N=target/release/examples/native_noise
RAYON_NUM_THREADS=6 $N 28672 32768 54 64 > noise-one-mask-n49.json
RAYON_NUM_THREADS=6 $N 28672 32768 54 64 --query-bits 43 > noise-one-mask-d43.json
RAYON_NUM_THREADS=6 $N 28672 32768 54 29 --two-mask --query-bits 44 > noise-two-mask29-d44.json
RAYON_NUM_THREADS=6 $N 65536 16384 54 29 --two-mask > noise-two-mask29-65536-n49.json
# rows cols pbits ell samples concurrency kh(0=two-mask) published query(0=nearest 49)
BENCH_THREADS=6 target/release/examples/native_e2e 28672 32768 16 2 20 4 54 64 43 > e2e-one-mask-d43.jsonl
python3 bench-results/2026-10-09-dithered-query/summarize.py
```

Each full-size noise report took 1.5 to 2 minutes and about 2.9 GB peak memory on
this host.
