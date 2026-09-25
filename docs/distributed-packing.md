# Distributed packing APIs (v0.1.0-rc.5)

The release adds the APIs used by wallet-pir's coordinator/worker/router serving
path without changing its existing arithmetic or protocol defaults:

- `inspiring::prepared`: bounded serialization and immutable mapped access to
  prepared odd-modulus packing matrices.
- `reinspiring::prepared_native`: serialization and mapped native matrix storage.
- `NativePublicSetup::query_masks`: public mask access for independently prepared
  database units.
- `FirstDimKernel::try_multiply_power_of_two` and the corresponding IPIR server
  method: explicit power-of-two modulus evaluation, including the CUDA backend.
  Empty dimensions, incompatible shapes, invalid moduli and noncanonical query
  coefficients return errors.

These artifacts are trusted coordinator output, not an untrusted wire protocol.
The caller authenticates the complete file and retains the immutable inode for
as long as any mapping exists. Writers must replace paths rather than mutate
mapped files. Cached arithmetic transforms and bounds are trusted preprocessing;
representation checks do not prove arbitrary supplied preprocessing correct.

Native matrices are serialized as portable signed 32/64-bit words. This permits
loading artifacts on workers whose CPU features differ from the preparing host.
The large matrix payload remains mapped rather than reconstructed on the heap.

The native cryptographic profile remains experimental; see
[`reinspiring/SECURITY.md`](../reinspiring/SECURITY.md). A distributed dispatcher
must still enforce request, snapshot, setup and output-block bindings.

The tag contains `inspiring` rc.2, `simplepir-kernel` rc.3, `reinspiring` 0.1.1 and
`ipir-sp` rc.5. Registry publication is separate from the Git tag and must follow
dependency order.
