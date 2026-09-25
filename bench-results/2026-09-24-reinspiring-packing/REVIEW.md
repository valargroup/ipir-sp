# Independent implementation review

A second agent reviewed the retained implementation under
`ai-runbook/misc/rules/reviewer.md`, as required for changes involving key
material. The review was read-only. It covered prepared uploaded-key reuse,
request association, full-sum CRT capacity, signed reconstruction, mixed-width
integer aggregation, compact matrix construction, FFT compilation, and SIMD
load bounds. This is an implementation review, not an independent cryptographic
audit approving the experimental parameter profile.

Initial verdict: **request changes**. The public FFT helper accepted a polynomial
count larger than coefficient degree, but its new power-of-two path did not
normalize the rotation before unsigned subtraction. Eight `[1,2]` polynomials
of degree two at q=16 caused a debug overflow panic. The production square-matrix
packing fixtures did not exercise this shape.

Fix: reduce the rotation modulo `2*d` before subtraction. Added the known-answer
regression `ring_fft_normalizes_rotations_when_polynomial_count_exceeds_degree`.
The reviewer independently ran it in debug mode; one test passed.

Final verdict: **approve**, no remaining blocking findings. The reviewer also
confirmed removal of the unhelpful scratch evaluator and correction of the
lift module's description of full-sum reconstruction. Hardware execution and
full-suite validation remained explicit publication gates; the final Intel
logs record those checks against source `8866066`.

The split packing API intentionally leaves distributed request/block association
to the dispatcher. Setup-ID equality alone does not establish request identity.
The integrated server retains request-local prepared keys and its existing
request-hash response binding.

## 27/28-bit refinement

A follow-up read-only review covered the additional diff in `abb6a96`. Verdict:
**approve**, no blocking findings. The reviewer checked the five-byte permutation
extraction, 37/36-bit sign extension, eight-byte tail padding, continuity across
odd-width constituent blocks, and exact 27/28-bit selection thresholds. Both
scalar boundary/tail and block roundtrip/multiplication tests were independently
rerun and passed. The subsequent Intel release suite exercised both SIMD widths;
three alternating paired benchmark repetitions confirmed the retention decision.

The refinement trades approximately 2% more packing setup time for 16 MiB less
two-limb material over sixteen blocks and a roughly 3% online improvement in its
paired trial. It does not discard coefficient bits or change noise parameters.

## Final eight-row register tiling

Required independent reviewer approved the retained eight-row configuration,
with four-row fallback, on 2026-09-24. No blockers remain. SIMD configurations
(4,4), (8,2), (16,1) preserve sixteen accumulators, vector bounds, scalar tails
and eight padding bytes. The suggested matrix coverage for rows
[4,8,12,16,20,32] was added and independently rerun successfully.
Intel release tests and exact ciphertext comparisons supplement this review;
this is not a cryptographic security approval.
