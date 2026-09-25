# One-key two-mask native packing, p=2^16

Experimental native profile at d=2048, q=2^54, two base-2^19 limbs, 28,672
rows and 32,768 columns. The database and setup seeds match the neighboring
K_h compression report. The one-mask and two-mask end-to-end runs were made
sequentially on the same Apple M4 Max with eight Rayon workers and three
measured queries each. Timing samples are exploratory; the exact byte counts
and correctness checks are the main result.

| Metric | One mask, K_g and K_h | Two masks, K_g only |
| --- | ---: | ---: |
| Packing-key upload | 55,296 B | 27,648 B |
| Complete request | 230,948 B | 203,300 B |
| Response | 90,180 B | 90,180 B |
| Published masks per snapshot | 262,180 B | 524,324 B |
| Retained coefficient bytes | 538,181,632 B | 537,395,200 B |
| Median client generation | 21.0 ms | 19.5 ms |
| Median server response | 29.4 ms | 28.6 ms |
| Median packing stage | 4.15 ms | 3.50 ms |
| Median client decode | 13.6 ms | 19.5 ms |

Two-mask mode saves 27,648 B per query and adds 262,144 B to the published
snapshot. If that snapshot must be transferred to the client, the total transfer
breaks even on the tenth query. The response body has the same size in both
modes. All measured queries recovered the selected row exactly.

`noise.json` contains the public, snapshot-specific original-sample weights.
`certificate.json` gives a conditional full-response failure bound of at most
2^-436 for this recorded snapshot. It does not establish the unresolved native
KDM/RLWE security assumption or approve the mode for production.

Reproduce the certificate with:

```sh
python3 reinspiring/tools/security/certify_native.py \
  bench-results/2026-09-25-two-mask/noise.json
```
