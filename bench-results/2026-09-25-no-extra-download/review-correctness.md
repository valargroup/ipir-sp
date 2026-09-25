# Independent correctness and certificate review

Date: 2026-09-25. Scope: two-mask public rounding at 32 and 29 bits, local mathematical accounting and certificate implementation. This review is a separate agent review of the current working tree, not an external professional audit. No implementation files were changed.

## Verdict: request changes before production acceptance

No mathematical error was identified in the rounded-mask error composition or finite-sampler tail calculation. For the saved benchmark reports, the existing checker reproduces the recorded full-response bounds of 2^-375 (32 bits) and 2^-228 (29 bits). Both exceed the requested 128-bit correctness target, conditional on the assumptions below. Production acceptance remains blocked by unenforced certificate/profile/sampler requirements. This verdict does not establish lattice or KDM security.

## Blocking issues

1. **High — the required snapshot correctness gate is not enforced.** `ipir-sp/src/native.rs:82-93` says a certificate is required, but setting the rounded precision accepts any value 27..32 without evidence. `ipir-sp/src/native.rs:624-630,671-678` computes statistics but does not enforce a threshold; ordinary server construction does not analyze them. Proof of concern: the same API enables the saved 28-bit profile whose checker score is only 82. This does not prove that profile actually fails often; it proves the chosen 128-bit acceptance requirement is bypassable. Minimal fix before production: create an accepted-snapshot/profile state only after a trusted local export passes the required bound, bind it to actual snapshot contents and published masks, and require that state in production use. Keep research constructors explicitly separate if uncertified experiments are needed. This is an acceptance/API gap, not a defect in the 32/29 arithmetic.

2. **Medium — the checker defaults to a weaker threshold than the requested target.** `reinspiring/tools/security/certify_native.py:173-181` defaults to 78 bits. Reproduction: running the CLI on `noise-28.json` without flags exits 0; adding `--require-bits 128` exits 1. A deployment script following the generic invocation could mistake process success for satisfying this task's target. Minimal fix: production acceptance must explicitly require 128 (or a stricter declared policy), and document/encode that policy rather than relying on the existing generic default. The 32- and 29-bit reports pass either threshold.

3. **Medium — exact sampler identity is a condition, not an enforced binding.** `reinspiring/src/noise.rs:294-305` derives counts from a floating-point-generated CDF. Actual sampling constructs that CDF as well (`reinspiring/src/native.rs:322-326`), while setup identity includes a sampler enum rather than the CDF (`reinspiring/src/native.rs:115-123`, `ipir-sp/src/native.rs:136-161`). The final certificate copies setup/database identifiers but omits a sampler fingerprint (`certify_native.py:166-167`). The documentation already acknowledges possible build/platform CDF differences (`NATIVE_CERTIFICATE.md:74-81`). Proof of concern: an exporter and client with differing CDFs can have the same setup identity, so the accepted certificate need not describe the client's exact distribution. No actual cross-platform mismatch or unsafe resulting bound was demonstrated in this review. Minimal fix: freeze the CDF as protocol data, or bind and verify its exact multiplicities in certificate acceptance on the client build; alternatively prove a conservative bound covering every allowed sampler implementation.

## Mathematical checks

- The exact added phase error is `epsilon_0*s + epsilon_1*tau_-1(s)`. `noise.rs:240-277` constructs the two multiplication/automorphism operators, adds them to the existing collapse-secret operator modulo q, and only then centers and measures weights. This preserves correlation between all occurrences of each original secret coefficient.
- Centering combined weights modulo q is legitimate: it changes an integer lift by multiples of q times integer samples. If the chosen lift plus all remaining error is inside the decoding interval, decoding succeeds.
- `noise.rs:160-178` combines disjoint original key-error and secret sample families. `ipir-sp/src/native.rs:680-690` envelopes actual database-column weights for query error; `native_noise.rs:51-56` adds that independent family. Envelopes need not be attained by the same row to be conservative.
- The deterministic budget in `certify_native.py:156-158` reserves `B_s*d^2 + 16*query_L1 + 2^31`: D.1 division, 49-bit query rounding, and 22-bit response rounding. Dependence of these terms on other errors is harmless because their magnitudes are bounded deterministically. Public-mask rounding is already incorporated in the secret weights and must not be counted as independent random noise.
- The finite sampler extraction matches the pinned backend's inclusive reverse CDF selection: the first bucket includes draw zero, repeated thresholds add no mass, and draws above the final threshold map to zero. The backend inspected was pinned `valar-spiral-rs` 0.5.3-rc.1.
- For each grid value a, the absolute-moment construction upper-bounds the MGF for both signs when `abs(u)<=a`; reserving `abs(mean)*L1` covers sampler bias. Optimizing the permitted tilt and selecting the best valid bound introduces no probabilistic selection issue.
- The Taylor recurrence rounds upward and bounds the entire remaining tail. The rational upper approximation to ln(2), downward rounding of the exponent, and `ceil(log2(2*cols))` full-response union factor are conservative. Taking the minimum block score after applying the full-response factor remains conservative; independence between output coordinates is unnecessary.
- Arithmetic overflow in the Rust norm computation is checked and fails rather than silently understating the bound.

## Reproduced checks and limits

- `python3 -m unittest discover -s reinspiring/tools/security`: 9 tests passed.
- Reevaluated all three saved reports with the existing checker and compared complete output objects to their saved certificates: exact matches, scores 375 / 228 / 82 for 32 / 29 / 28 bits.
- Reproduced the 28-bit CLI threshold discrepancy described above.
- `cargo test --release -p reinspiring --lib python_integer_trace_matches_two_mask_pack_and_weights -- --nocapture`: passed. This exercises the independent Python schoolbook oracle at d=8, checks rounded weight envelopes for all six supported precisions, and checks the exact phase change from rounding.
- An earlier test-name filter matched zero tests; it is not counted as verification. The corrected command above ran one test.
- Inspected the actual Rust exporter paths and sampler extraction. Did not regenerate the entire d=2048 benchmark database/weight export, independently reimplement the rational checker, or rerun full-size benchmarks. Recomputed certificates therefore remain conditional on the saved exported norms. Small-degree oracle checks provide additional implementation evidence, not a proof that every large-degree execution is correct.

## Assumptions and non-blocking limitations

The claim is per complete response for the exact analyzed setup/database, under the exact exported sampler distribution and fresh independent draws (the cryptographic PRNG idealization). It assumes honest execution and public masks from the analyzed snapshot, correct arithmetic/serialization/decoding, and the fixed supported gadget/transport parameters. Reports are trusted local exports; norms and copied hashes cannot prove their own provenance. The bound does not authenticate a malicious server's answer, certify privacy, or cover a lifetime of requests without an additional union bound.

The 32-bit profile has greater demonstrated correctness margin than 29 bits; neither fixture result proves universal safety for arbitrary snapshots. No additional mathematical blocker specific to 29 bits was identified.

Questions for author: none needed to reproduce these findings; deployment acceptance policy and sampler binding need implementation decisions before production approval.
