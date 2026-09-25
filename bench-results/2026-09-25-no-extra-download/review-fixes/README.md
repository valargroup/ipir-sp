# Review fixes — 2026-09-25

Addressed all three findings selected by the user. This is a follow-up to the
independent agent reviews, not production cryptographic approval.

## Secret scratch

Prepared decoding now uses erasing guards for raw and NTT matrices, Zeroizing
residue vectors, and guarded per-block products. Final request state is allocated
before the loop so an error clears all accumulated products. Inverse NTTs operate
in guarded storage and do not copy into Spiral's unwiped thread-local scratch.
A regression test checks actual matrix storage after normal return, error return,
and panic unwinding. This covers these owned heap buffers, not CPU registers,
stack spills, swap, or all other native arithmetic paths.

## Certificate threshold

The default CLI target is now 128 failure bits. The retained 28-bit report returns
failure by default. Explicit historical targets remain available through
`--require-bits`. Regression tests cover the default rejection and explicit
historical thresholds. This is not runtime snapshot admission enforcement.

## Frozen sampler

All native Gaussian secret and error draws use the same 131 frozen integer CDF
thresholds via the pinned backend fixed scan. A private wrapper hides the unused
variable-time sampler. No floating-point CDF generation affects this path.
The table was exported from the previously tested backend and its exact output
multiplicities match all eight recorded noise reports. The SHA-256 over the
little-endian u64 thresholds is:

`bc68011d7224eb5dcb649a206c70697d4e6bce32af77966f4ebd60c0683cac2e`

Certificate acceptance checks every multiplicity, plus any supplied fingerprint,
and records the fingerprint in its output. Tests reject a one-draw redistribution
and an incorrect fingerprint. Legacy local reports lacking a fingerprint remain
acceptable only if all their counts match the frozen distribution. Setup and wire
encodings are unchanged because this preserves the recorded distribution. An older
binary with different generated counts is outside this guarantee and must be
upgraded/reanalyzed. Future distribution changes require a new profile identity.

The checked-in certificate-32.json and certificate-29.json are reevaluations of
the existing saved public weights with the hardened checker, not new full-size
exports. Scores remain 375 and 228 respectively.

## Validation

- Both complete release suites passed (one pre-existing ignored test).
- After the sampler encapsulation-only follow-up, all 16 library tests and all 9
  native integration tests passed again.
- All 9 Python security tests passed, including new negative cases.
- Clippy all targets with warnings denied, formatting, and diff whitespace checks passed.
- Full-size paired smoke runs are retained alongside this report. Each uses 30
  measured requests per mode, with request preparation charged to generation.
  They are not isolated performance acceptance runs and do not establish the 5%
  non-regression gate. Their binary includes scratch erasure and frozen sampling;
  it precedes the private-wrapper-only encapsulation change.

Independent follow-up reviewers approved the scoped fixes:
[implementation](../review-fixes-implementation.md) and
[sampler/certificate](../review-fixes-correctness.md).

Still separate: enforcing snapshot certificates at runtime, the underlying native
KDM/RLWE review, and controlled performance acceptance. No production activation.

Both paired runs completed with all 120 measured baseline/variant responses
correct. Observed ratios versus the equally prepared baseline were: 32-bit
client generation 0.942, decode 1.010, server throughput 1.030; 29-bit generation 1.024,
decode 0.962, throughput 1.066. Timing varied substantially between runs; these
figures are provisional and do not replace an isolated acceptance run. See
[performance-summary.json](performance-summary.json).
