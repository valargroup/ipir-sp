# Independent implementation follow-up review

Date: 2026-09-25. Scope: fixes to the two findings in `review-implementation.md`, for both 32-bit and 29-bit routes. Read-only source review; this report is the only file written by this reviewer. This is an independent agent review, not an external audit or production approval.

## Verdict: approve (the scoped fixes)

No remaining blocking issue identified in the reviewed fixes. The initial secret-scratch and CLI acceptance-policy findings are addressed. Broader scheme assumptions, performance verification, and production admission are outside this scoped approval.

## Secret-scratch lifecycle

Reviewed `reinspiring/src/lift_ntt.rs:12-28,119-151,271-307` and `reinspiring/src/native.rs:248-268`.

- The borrowed `SecretRaw`/`SecretNtt` guards are created before secret writes, and destroy their contents before the underlying Spiral allocations are released. The guards do not move the matrix allocation and also run on normal error returns and unwinding.
- `prepare_decode_secret` builds directly into a `PreparedLiftRight` with an erasing destructor. Previously retained prime transforms are therefore protected if later work unwinds. The forward NTT uses caller-owned, guarded output. Inspection of pinned Spiral `poly::to_ntt` and its one-prime NTT path found no additional heap/TLS copy of the secret.
- `sum_cached_two` guards the right operand, product, and sum; its unguarded left operand holds only the public mask. The residue vectors are `Zeroizing`.
- Inverse NTT now operates directly in the guarded sum storage. This is necessary: pinned Spiral `from_ntt` copies input into a thread-local scratch allocation and does not wipe it. The replacement applies the same inverse transform and `crt_compose` as the dependency's original conversion, with one prime and one polynomial per context. No arithmetic change to the reconstructed coefficients was identified.
- `prepare_request` preallocates the final state, whose destructor wipes products, and wraps each returned block product in `Zeroizing` before copying it. There is no draining/flattening of unwiped secret product allocations. Preallocation avoids growth reallocations as blocks are appended.
- The conjugate-transform collect creates new coefficient vectors that are immediately owned by the erasing `PreparedLiftRight`. Its iterator performs only reversal/copying, with no recoverable error branch. I found no practical unwind path that strands a populated temporary coefficient vector in this operation; allocation failure aborts rather than returning through this API.
- The added guard regression test checks storage after normal return, error return, and panic unwinding. It is useful evidence for guard order and behavior, though not a claim to wipe every stack/register spill or memory on process abort. Those stronger claims are not made here.

The generic non-decoder arithmetic and older client paths still have broader lifecycle and local side-channel limitations; these were not newly introduced by these fixes and are not converted into a whole-program erasure guarantee by this review.

## Certificate acceptance policy

`reinspiring/tools/security/certify_native.py` now defaults `--require-bits` to 128. The rounded-report test invokes the CLI on the retained 28-bit report without an override and expects failure.

Independently reproduced:

```sh
python3 reinspiring/tools/security/certify_native.py \
  bench-results/2026-09-25-no-extra-download/noise-28.json
```

Observed exit status: **1**, with the accurate reported score of 82 and `meets_128: false`. This closes the original successful-exit misconfiguration. Historical 78-bit acceptance remains explicitly selectable, rather than silently applied by default.

## Non-blocking and questions

No new non-blocking code findings or author questions. The parent is running the implementation regression suite; this reviewer avoided duplicating broad tests. Scoped approval relies on the source inspection above and the independently reproduced CLI rejection, and should be combined with those regression results before landing.
