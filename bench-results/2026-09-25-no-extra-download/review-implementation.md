# Independent implementation review: 32-bit and 29-bit public masks

Date: 2026-09-25. Scope: the current uncommitted native implementation, particularly `ipir-sp/src/native.rs`, `reinspiring/src/native.rs`, `reinspiring/src/lift_ntt.rs`, transport tests, and certificate CLI. This is an independent agent review, not an external cryptographic audit. No implementation files were modified.

## Verdict: request changes

Both precisions use the same reviewed code paths. I found no concrete rounding, packing, setup-binding, or CRT-capacity defect specific to either precision. I would retain both as experimental configurations, but would not approve production use. Two implementation/misuse findings need resolution. The existing absence of enforced snapshot certification is a separate, declared production prerequisite.

## Blocking issues

### 1. Medium: prepared decoding leaves complete secret transforms in freed scratch allocations

Locations: `reinspiring/src/lift_ntt.rs:261-284`; `reinspiring/src/native.rs:258-266`. Applies to both 32-bit and 29-bit routes, and the prepared one-mask comparator.

`sum_cached_two` copies each secret NTT into the `right` matrix at line 269. `right`, `out`, `sum`, the temporary inverse-transform allocation at line 280, and `residues` are dropped without erasure. The pinned Spiral dependency (`f2c23c7`, `src/aligned_memory.rs:75-81`) merely deallocates its aligned memory. Its matrix types do not add erasure. `prepare_request` additionally flattens the product vectors into a new allocation without erasing the drained source storage.

Proof of concern: the last `right` scratch allocation contains an invertible NTT representation of the secret (or its conjugate), modulo a known auxiliary prime. One such representation suffices to recover the small secret coefficients. Erasing the original `PreparedLiftRight` and final `NativeDecodingState` does not erase these copies. This is a code-level lifecycle finding; I did not perform an allocator memory-recovery exploit.

The same generic arithmetic had unwiped scratch before this change, but the new prepared decoder newly feeds it a secret transform. This is not a demonstrated attack by the passive remote server. Exploitation requires access to client process memory or freed memory, beyond the documented remote threat model. Nevertheless, the new secret lifecycle should be completed before production, particularly because the new API expressly advertises erasure of retained request state.

Minimal fix: provide a decoder-specific secret-scratch path or zeroizing RAII wrappers for all secret-bearing matrices/vectors, including inverse-transform temporaries and error paths. Append/copy products into the final protected allocation and wipe each source before release. Do not rely on ordinary `Vec` destruction. Account for the added erasure work in the existing generation performance gate.

### 2. Medium: default certificate command accepts a profile below the selected 128-bit correctness target

Location: `reinspiring/tools/security/certify_native.py:170-182`.

The CLI defaults `--require-bits` to 78. Running the ordinary command on the retained 28-bit report exits successfully, even though the task explicitly rejects its 82-bit certificate against a 128-bit target:

```sh
python3 reinspiring/tools/security/certify_native.py \
  bench-results/2026-09-25-no-extra-download/noise-28.json
```

Observed exit status: 0. Output: `certified_failure_bits: 82`, `meets_78: true`, `meets_128: false`.

The reported mathematics is not false, and this does not invalidate the retained 32-bit or 29-bit certificates. It is an acceptance-policy hazard: an operator or script using exit status alone can approve a profile that misses the agreed safety target.

Minimal fix: default to 128 for this workflow or require an explicit threshold on every invocation. Add a negative CLI test proving that the ordinary acceptance command rejects the retained 28-bit report. If 78 remains useful for historical research, keep it as an explicit override.

## Declared production prerequisites, not newly discovered arithmetic bugs

- `ipir-sp/src/native.rs:82-93` permits rounded precision based only on mode, modulus, and range. `NativeServer::build` at lines 601-614 need not analyze the snapshot. This is documented experimental behavior, not a hidden production regression. Before shipping an approved route, an admission gate must bind a trusted passing analysis to the actual snapshot/setup/profile and actual published masks. Simply restricting precision to 29 or 32 is insufficient: the reported bounds are snapshot-specific.
- Public transport identifiers are consistency checks, not authentication. The documented passive-server model excludes malicious responses/decryption oracles. No claim of authenticated decoding follows from this review.
- The native KDM-RLWE assumption and local side-channel limitations are inherited. The new arithmetic still includes secret-dependent reductions/branches and has no constant-time machine-code audit. No additional remote attack was established here.
- The NTT is the pinned Spiral implementation; the conjugate-index reversal and CRT glue are local code. This review inspected their arithmetic and bounds but does not establish that the dependency or emitted machine code has been audited.

## Checked implementation properties

- Rounded publication and parsed publication both reconstruct multiples of `2^(54-t)`. Nearest rounding wraps modulo `2^54`, including the upper endpoint. For t=29 and t=32, the addition used in rounding cannot overflow `u64`.
- RNP3 parses against dimensions/precision from the local setup, checks exact length/version/setup ID, and rejects noncanonical padding. Both precision values are included in setup derivation. Private object fields prevent callers from constructing inconsistent in-memory publication fields through the public Rust API.
- Prepared request products bind to setup/profile and SHA-256 of the actual canonical mask payload. Response decoding binds setup and the hash of the request bytes. This prevents accidental state mixing, not malicious-server forgery.
- Decoder CRT selection is based on public masks and the sampler's full public support. It requires the auxiliary-prime product to be strictly greater than twice `d * support * sum(max_abs(mask))`. Secret construction is private and sampling respects that support. I found no missing factor for the two-mask sum.
- The conjugate transform reverses the bit-reversed evaluation ordering; the existing differential boundary test exercises both one- and two-mask decoding at degrees 2, 8, 64, and 2048. These tests supplement the algebraic inspection; they do not establish a negligible statistical decoding-failure rate.

## Reproduced checks

- `cargo test --release -p ipir-sp --features native-reinspiring rounded_public_masks -- --nocapture`: 2 tests passed, including all six supported precisions, round trips, malformed versions/lengths/setup bindings, and padding rejection.
- `cargo test --release -p reinspiring prepared_decode_matches_generic_at_support_boundaries -- --nocapture`: 1 test passed.
- Certificate CLI default-threshold reproducer above: exit 0 for 82 bits, confirming finding 2.
- An initial invocation of the integration tests without `--features native-reinspiring` ran zero relevant tests; it was corrected as shown above and is not counted as validation.

## Questions for author

None needed to establish these findings. Approval requires fixing the new secret-scratch lifecycle and aligning the acceptance command with the selected target. Production admission additionally requires the documented trusted snapshot gate and the broader cryptographic review.
