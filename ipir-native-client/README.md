# Native PIR client

Native PIR profiles, deterministic public setup, query generation, published-mask
parsing and response decoding. A wallet can depend on this package without the
IPIR database evaluator or the SimplePIR kernel. `ipir-sp::native` re-exports the
same types alongside its evaluator, so existing applications keep their imports.

```rust
use ipir_native_client::{NativeParams, NativeProfile, NativePublicSetup, NativeRequest, SecretDistribution};

let packing = NativeParams::new(16, 54, 16, 19, 2, SecretDistribution::Gaussian)?;
let profile = NativeProfile::new(packing, 32, 16)?.with_two_mask_output()?;
let setup = NativePublicSetup::new(profile, [11; 32], [12; 32]);
let request = NativeRequest::generate(&setup, 5)?;
// Send request.bytes() using the application's transport.
# Ok::<(), ipir_native_client::ReinspiringError>(())
```

The evaluator belongs to `ipir-sp`, not this client API:

```compile_fail
use ipir_native_client::NativeServer;
```

This is the first dependency boundary, not a complete arithmetic-library split.
ReinspiRING, InspiRING, Spiral and Rayon remain transitive dependencies. Enhance's
older parameter metadata and wallet-libraries adoption are separate follow-ups.
No profile, security claim, entropy source or wire format changes in this move.
