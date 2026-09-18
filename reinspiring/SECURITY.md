# Security notes for `reinspiring`

- Odd-`q` path is an exact rewrite of InspiRING packing; noise matches InsPIRe
  Theorem 2 (`e_div = 0`).
- Even-`q` (Appendix D.1) adds `∥e_div∥_∞ ≤ d²` for ternary secrets. Parameter
  sets must budget for this before claiming correctness.
- `H'` entries are stored as native words; bit-packing is intentionally avoided
  (ReinsPIRe §3.4 remark).
- Online `pack` is deterministic and allocates no secret-dependent randomness.
