# Pinned IPIR-SP profiles

The production client accepts `ProductionSimplePirParams` only. Its constructor
pins the following values and derives database dimensions and query width from
the requested shape. Changing a pinned value requires a new profile ID and a
new review; callers cannot supply an altered RLWE/transport pair to
`IPIRClient::new`.

| Profile ID | `d` | `q` | `p` | `sigma_chi` | Gadget | Response moduli | Query bits |
| --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| `simplepir-p14-v1` | 2048 | 72057594037641217 | 16384 | 6.4 | `2^19`, 3 digits | `2^20`, 268369921 | Derived from `(q, p, db_rows)` |
| `simplepir-p16-q46-v1` | 2048 | 72057594037641217 | 65536 | 6.4 | `2^19`, 3 digits | `2^20`, 268369921 | Derived, at least 46 |

The constructor checks the RLWE, Spiral, transport, dimension, and cached
arithmetic values before returning the opaque profile object. Tests reject a
weak `sigma_chi`, altered transport values, inconsistent dimensions, stale
cached values, and overflowing shapes. The production flow test exercises
query and response processing with the pinned P14 parameters.

These checks prevent accidental use of an effectively unencrypted query, but
they do not establish a 128-bit security level for the single-CRT InspiRING
construction. The repository's [parameter discussion](../README.md#what-the-parameters-assume)
and [InspiRING checklist](../inspiring/SECURITY.md#parameter-checklist)
describe the current analysis and the remaining lattice-estimator and
composition review. Treat a change in sampler, RLWE modulus, gadget, plaintext
modulus, transport precision, or key-reuse policy as a new cryptographic
profile requiring that review before production use.

Arbitrary arithmetic parameters remain available to low-level research code.
The high-level client can use them only through `new_experimental` with the
`experimental-params` Cargo feature; that entry point makes no privacy claim.
