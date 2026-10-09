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
| `simplepir-p16-q48-v1` | 2048 | 72057594037641217 | 65536 | 6.4 | `2^19`, 3 digits | `2^20`, 268369921 | Derived, at least 48 |
| `simplepir-p16-q49-v1` | 2048 | 72057594037641217 | 65536 | 6.4 | `2^19`, 3 digits | `2^20`, 268369921 | Derived, at least 49 |

The constructor checks the RLWE, Spiral, transport, dimension, and cached
arithmetic values before returning the opaque profile object. Tests reject a
weak `sigma_chi`, altered transport values, inconsistent dimensions, stale
cached values, and overflowing shapes. The production flow test exercises
query and response processing with P14 and all three pinned 16-bit profiles.

These checks prevent accidental use of an effectively unencrypted query, but
they do not establish a 128-bit security level for the single-CRT InspiRING
construction. The [security analysis](SECURITY_ANALYSIS.md) estimates about
`2^131` for the cheapest attack under MATZOV. Under core-SVP (BKZ block size
about 354 at `n = 2048`, `log q = 56`, `σ = 6.4`) the same instance costs
about `2^103` classical and `2^94` quantum, so the 128-bit claim is specific to
the MATZOV cost model and its margin is about three bits.

The 48- and 49-bit profiles reduce query rounding error relative to P16Q46.
The existing snapshot certificates apply only to the evaluated 46-bit schedules;
new snapshots require their own correctness evidence.

The query mask side is expanded by the client from the setup seed through the
opaque `PublicQuerySetup` type; a server can choose the seed but cannot supply
the polynomials.

### Authenticating responses

PIR hides which row a client asks for from a server that follows the
protocol. It does not authenticate the answer. The client decodes
`round((c2 + c1·s) / Δ) mod p`, where `c1` comes from `GET /public-params` and
`c2` is the response body, and the server chooses both. Two attacks follow.

**A. Poisoned public parameters.** If the server publishes `c1 = Δ` (the
constant polynomial) and answers with an all-zero `c2`, decoded coefficient
`i` is exactly `s_i mod p` (a negative `s_i` decodes to `p - |s_i|`): the
decoded "row" is the client's secret key. If those bytes ever leave the device
(logs, telemetry, a verifier service) the server recovers `s`, adds
`<a_j, s>` back to each query coefficient, and reads the target row straight
off the query. Until `c1` is trusted, decoded output is key-equivalent.

**B. Tampered answers plus a behaviour oracle.** The server cannot forge the
presence of a nullifier it does not know, but it can erase one: blank half the
rows in a copy of the database and answer from the copy. A client whose
nullifier is in the set then sees "present" if its row was untouched and
"absent" if it was blanked. Any difference in what the client does next (stop
polling, retry, broadcast) tells the server which half the row is in.
Repeating this amplifies it: a wallet that re-checks the same nullifier on
every sync gives one bit per poll, and halving the candidate set each time
finds one of the 28,672 rows in about 15 polls.

**Mitigation.** The coordinator signs, with Ed25519, a snapshot manifest
(`ipir_sp::manifest::SnapshotManifest`) binding the profile, shape and setup
seed, the SHA-256 of the exact `/public-params` bytes, and the SHA-256 of a
row digest table holding SHA-256 of every honest decoded row. A client pins
the coordinator key, downloads the manifest, `c1` and the whole table, and
builds `VerifiedPublicParams` before its first query; that check also refuses
a `c1` whose residues modulo `Δ` are concentrated (as attack A needs) even
under a valid signature. It then decodes with
`decode_response_simplepir_verified`, which returns
`ClientError::TamperDetected` when the decoded row does not match its signed
digest. Because the whole table is downloaded, fetching it reveals nothing
about the target. `c1` is derived from the database hint, so a server that
answers from a modified database either publishes a `c1` that fails the
manifest or answers inconsistently with the signed `c1`; both are detected.

Detection is not enough on its own. The client must also keep this
invariant: **its request pattern must not depend on the decoded answer, and it
takes no irreversible action on an answer that has not verified.** Polling
cadence, retries and the decision to stop must be fixed in advance; a
`TamperDetected` result is reported and the server abandoned, not retried until
it looks different. That policy lives in the wallet, not in this crate.

The unverified decoders (`decode_response_simplepir_unverified` and
`_raw_unverified`) remain for one release and for research fixtures; their
output must be treated as key material.

The repository's [parameter discussion](../README.md#what-the-parameters-assume)
and [InspiRING checklist](../inspiring/SECURITY.md#parameter-checklist)
describe the current analysis and the remaining lattice-estimator and
composition review. Treat a change in sampler, RLWE modulus, gadget, plaintext
modulus, transport precision, or key-reuse policy as a new cryptographic
profile requiring that review before production use.

Arbitrary arithmetic parameters remain available to low-level research code.
The high-level client can use them only through `new_experimental` with the
`experimental-params` Cargo feature; that entry point makes no privacy claim.
