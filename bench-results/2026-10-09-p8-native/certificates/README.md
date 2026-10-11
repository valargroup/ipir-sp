# p = 2^8 native certificates

Noise reports and certificates behind the p = 2^8 transport floors in
`ipir-sp/src/native.rs`. `test_certify_native.py` checks that every
certificate here is byte-identical to `certify_native.py` output on its report.
All fixtures are synthetic uniform 8-bit databases (seed 0x2417, setup
`[7;32]`, snapshot `[19;32]`); every served snapshot still needs its own
certificate.

| File stem | Rows × cols | Gadget | Query / response / masks | Certified |
|---|---|---|---|---:|
| `p8-g19-q28-r10-m22` | 28,672 × 65,536 | two-digit (19, 2) | 28 / 10 / 22 | ≤ 2^-406 |
| `p8-g27-q28-r10-m22` | 28,672 × 65,536 | one-digit (27, 1) | 28 / 10 / 22 | ≤ 2^-209 |
| `p8-g19-q28-r10-m22-rows65536` | 65,536 × 32,768 | two-digit | 28 / 10 / 22 | ≤ 2^-236 |
| `p8-g27-q28-r10-m22-rows65536` | 65,536 × 32,768 | one-digit | 28 / 10 / 22 | ≤ 2^-150 |
| `p8-g19-q27-r10-m22` | 28,672 × 65,536 | two-digit | 27 / 10 / 22 (below the floor) | ≤ 2^-138 |
| `p8-g19-q28-r9-m22` | 28,672 × 65,536 | two-digit | 28 / 9 / 22 (below the floor) | ≤ 2^-187 |

- `screen-*-p8-g{19,27}.json`: one report per gadget with lossless masks and
  `certify_native.py --screens` output, giving the width frontier the floors
  were chosen from. The frontier is not a box; the floors are set where every
  combination at or above them passed the screen for both gadgets.
- `noise-p16-regression-two-mask29-n49.json`: the recorded 2026-10-09 p = 2^16
  report regenerated on this code. It differs only by three added keys (`ell`,
  `gadget_bits`, `dropped_bits`) and still certifies at 2^-228.

Regenerate with `screen.sh` and `certify.sh`, passing a release build of the
`native_noise` example (`--features native-reinspiring`) and an output
directory. The two below-floor rows were recorded before the floors were
pinned; `native_noise` now rejects those widths.
