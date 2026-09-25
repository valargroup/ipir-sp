# Focused follow-up: frozen sampler and certificate threshold

Date: 2026-09-25. Independent review of the changes addressing findings 2 and 3 in `review-correctness.md`. No implementation edits were made by this reviewer.

## Verdict: approve these scoped fixes

The floating-point sampler mismatch root cause is resolved for updated binaries. The default certificate threshold now implements the requested 128-bit policy. This does not change the original overall production verdict: certificate enforcement and other review findings remain separate requirements.

## What changed and why it is sufficient

- `reinspiring/src/native_gaussian.rs:7-19` constructs one immutable sampler from 131 checked-in integer CDF thresholds, with support parameter 65. The pinned backend's CDF-based `sample` uses those integer thresholds; its unused `weighted_index` field does not participate in that method.
- All native Gaussian secret and error draws use this constructor: `reinspiring/src/native.rs:321-324,359,378-386,509-520`. The prepared decoder's support bound also uses it (`native.rs:215`). The native code no longer generates a CDF with floating-point exponentials.
- `reinspiring/src/noise.rs:294-305` exports counts from this same frozen table. Thus sampler and exporter share protocol data rather than merely a nominal sigma and sampler enum.
- `reinspiring/tools/security/certify_native.py:83-101` compares every output multiplicity against the frozen table. The optional report digest is additionally checked, and output includes the computed digest. Omitting the digest in a legacy report does not bypass the complete count comparison.
- The CLI now defaults to 128 bits. Its negative test uses the saved 28-bit report without explicit flags and requires nonzero exit status.
- Preserving setup identity is justified for updated implementations and the saved fixtures because the exact distribution is unchanged. The documentation explicitly excludes older binaries with a different generated CDF and requires a new profile identity for any future distribution change. The existing ID does not itself detect such older binaries; deployment must actually use the updated implementation.

## Independent checks reproduced

1. Reconstructed bucket counts directly as the first threshold plus one, successive threshold differences, and the above-final-threshold fallback added to the zero bucket. Verified equality against all eight saved `noise*.json` reports with sampler data.
2. Verified there are exactly 131 thresholds, all in the u64 range, nondecreasing. Independently computed the little-endian threshold digest:

   `bc68011d7224eb5dcb649a206c70697d4e6bce32af77966f4ebd60c0683cac2e`

3. Ran `python3 -m unittest discover -s reinspiring/tools/security`: all 9 tests passed. This includes rejection after moving exactly one draw between buckets while preserving total mass, rejection of a wrong sampler digest, and default-threshold rejection of the 28-bit fixture.
4. Inspected the pinned backend sampler implementation and searched native source for residual CDF initialization/sample calls. No floating-point operation influences the native CDF-based sample result. Floating-point construction of the dummy one-element `WeightedIndex` remains, but its values are never used by native sampling.

I did not independently regenerate the full benchmark noise matrices, rerun Rust suites already running under the root reviewer, or audit generated machine code for constant-time behavior. The changed checker preserves the saved 32-bit score 375 and 29-bit score 228 through the passing recorded-certificate tests.

## Non-blocking

A private wrapper exposing only the intended `sample`, table and support operations would make future accidental use of the dummy `weighted_index`/`fast_sample` harder. Current source never calls that method, the module is private, and the warning is explicit, so this is a maintainability suggestion rather than a current correctness defect.

Questions for author: none for these scoped fixes.

## Follow-up: optional wrapper improvement reviewed

The non-blocking suggestion above is now addressed. `NativeGaussian` in
`reinspiring/src/native_gaussian.rs:7-19` keeps the backend value in a private
tuple field and exposes only immutable CDF/support accessors and the intended
CDF-scan `sample` operation. `gaussian()` returns the wrapper, so native callers
cannot accidentally select the backend's dummy-index `fast_sample` method.
The table, support and sample delegation are unchanged; updated exporter and
decoder call sites only use the new accessors. Inspected this follow-up and
approve it without additional findings. Rust library checks are being run by
the root reviewer; this follow-up assessment is by source inspection.
