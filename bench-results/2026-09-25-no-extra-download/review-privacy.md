# Independent privacy review: 32-bit and 29-bit public masks

**Verdict: request changes.** Both 32-bit and 29-bit profiles have a defensible *conditional passive-server privacy argument*. I found no new server-visible disclosure caused by omitting K_h or rounding these public masks. I cannot approve production cryptographic security: the existing native KDM assumptions remain unreviewed, and the new prepared decoding path leaves copies of secret material in freed memory.

## Blocking issues

1. **Medium — prepared decoding does not erase all newly created secret copies. Both profiles affected.**

   **Locations:** `reinspiring/src/lift_ntt.rs:256–284`; `reinspiring/src/native.rs:255–266`.

   **Concern:** `prepare_decode_secret` zeroizes its retained transforms, and `NativeDecodingState::drop` clears the final products. However, `sum_cached_two` copies a secret NTT transform into `right` at line 269. The ordinary `PolyMatrixNTT` scratch allocation is subsequently dropped without explicit zeroization. It also leaves secret-dependent `out`, `sum`, inverse-NTT temporaries, and `residues`. `prepare_request` subsequently flattens intermediate product vectors into a different allocation without clearing those source vectors.

   **Proof of concern:** The scratch `right` contains a complete transform of s or tau(s) modulo an auxiliary prime. That transform is invertible; since the secret is small, recovering it from freed heap memory recovers the request secret. Clearing the retained original transform does not clear this copy.

   This is **not a remote passive-server attack** under the documented threat model. It is a new secret-lifetime hygiene gap introduced by reusing arithmetic previously described as operating on public uploaded key bodies. Existing nonprepared arithmetic also has secret-temporary cleanup gaps; this finding does not imply those were previously safe.

   **Minimal fix:** Add a secret-aware scratch path using zeroizing buffers/guards. Clear `right`, product/sum transforms, inverse-transform buffers and residue vectors, including exceptional exits. Construct final products without abandoning unzeroized intermediate allocations. Check dependency scratch allocation behavior as part of this fix. Apply to both 29/32 profiles and the prepared baseline.

2. **High for production acceptance — snapshot correctness certification remains unenforced. Both profiles affected.**

   **Location:** `ipir-sp/src/native.rs:82–93`; acknowledged explicitly in `reinspiring/SECURITY.md:208–210`.

   **Concern:** The documented requirement “Requires a snapshot certificate” is not an API precondition. A caller can instantiate either precision for an arbitrary supported database, then build and serve it without passing any certificate. Therefore correctness claims for the recorded fixture do not describe all accepted instances.

   **Minimal fix:** Before production exposure, require a verified snapshot/profile acceptance artifact bound to actual database/preprocessing content and selected precision, or provide a reviewed general bound covering every admitted instance. Keep uncertified constructors clearly restricted to research use. This is a correctness deployment gate, not evidence that the recorded 29/32 certificates are wrong.

## Privacy argument checked

- `NativeKeys::generate_internal` retains the same K_g generation formula and skips K_h in one-key mode (`reinspiring/src/native.rs:499–548`).
- Rounded public masks are functions of preprocessing available to the server. They do not disclose additional client secret values.
- Request-local prepared products stay inside private client structures.
- Precision and two-mask mode are included in setup derivation (`ipir-sp/src/native.rs:144–170`).
- Parsers use the locally supplied setup/profile to choose dimensions and precision; prepared state is also bound to a digest of actual published masks.

**Qualification on the reduction:** At the **same public-mask experiment**, deleting K_h is literal projection of the original server view, and public-mask rounding is public postprocessing. The implemented 29-, 32-, and baseline modes generate different setups because of domain separation. Therefore they are **not literally subsets of the same concrete transcript for a fixed user seed**. Transferring the projection argument to implemented profiles relies on the existing assumption that the domain-separated seeded expansion produces suitable public setups. This is reasonable within the declared model, but it must not be presented as an unconditional comparison of those fixed transcripts.

## Inherited limitations, not new regressions

- Native power-of-two, scaled-automorphic KDM-RLWE hardness is assumed, not established by these modifications. I do not know that this assumption achieves a particular concrete security level; that requires specialist analysis.
- SHA-256 setup/request digests are public consistency checks, not authentication. Responses and snapshot contents are not authenticated by this protocol.
- The passive-server result does not establish malicious-server security or permit a server-observable decryption/validation oracle.
- New prepared arithmetic contains secret-dependent branches at `lift_ntt.rs:273–277,294–304`. The documented exclusion of local timing/cache adversaries prevents this from refuting the narrow privacy claim, but production environments including those adversaries need a constant-time audit or replacement.
- Neither 29-bit nor 32-bit rounding introduces a distinct RLWR-style secrecy assumption in this implementation: only public preprocessing masks are rounded.

## Validation performed

Inspected code, threat model, setup derivation, key generation, wire binding, and prepared-secret handling. Ran:

```text
cargo test --release -p ipir-sp --features native-reinspiring \
  --test native_flow rounded_public_masks
```

Both focused tests passed, covering all 27–32 precisions, round trips, setup/mode rejection, truncation/extension and noncanonical padding.

This is an independent agent review of the implementation, **not an external human cryptographic audit**. No source files were modified.
