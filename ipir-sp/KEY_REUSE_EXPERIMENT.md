# Bounded evaluation-key reuse experiment

This is an in-process research prototype, gated behind `experimental-key-reuse`.
The production HTTP API and its fresh-secret query path are unchanged. The
prototype does not establish production security and must not be used as a
production transport without further review.

## Construction and conditional security argument

The adversary observes every public setup, uploaded evaluation key, query and
answer, including all queries in a batch. Linkage within a batch is allowed.
Clients assume honestly generated, pinned public setup and independent private
CSPRNG draws. This experiment does not implement malicious-server response
verification, authenticated setup distribution, or protection against process
memory disclosure, process snapshot rollback, or deliberate bypass of the API.

The existing query is `b = -A*s + e + delta*u`, where `u` selects a row.
Reusing both `A` and `s` exposes `delta*(u_i-u_j) + e_i-e_j` by subtraction.
Fresh errors alone do not hide that difference. The unit regression demonstrates
this attack after the actual query modulus switching and serialization.

The experiment derives independent pseudorandom query-matrix sets `A_0..A_B-1`
and publishes one evaluation-key pair for a secret `s`. It sends at most one
fresh query under each `(A_i,s)`. The stacked transcript consists of additional
structured RLWE samples with distinct public masks under the same secret, plus
one evaluation-key pair. Conditional on joint pseudorandomness of these samples
**given the evaluation key**, replacing their bodies by uniform values hides the
selectors. Query modulus switching is deterministic public post-processing.
Answers and public preprocessing reveal no additional information beyond this
transcript and the server's database, since they are computed by the server.

This argument is conditional, not a reduction proving the required joint
assumption for our implementation. Evaluation keys encrypt secret-dependent
automorphic images; ordinary RLWE alone is insufficient justification. The
YPIR paper's Theorem 3.4 similarly requires pseudorandomness given the packing
key and discusses circular security:
https://www.usenix.org/system/files/usenixsecurity24-menon.pdf.
The local packing assumptions are recorded in `../inspiring/SECURITY.md`.
Production needs specialist review of this composed transcript and a concrete
security estimate with the increased sample count and actual parameters.
Correctness tests and the absence of a subtraction distinguisher are not a proof.

## Public derivation and batch lifetime

The v1 experimental derivation seeds `ChaCha20Rng` with the 32-byte public seed,
sets its stream identifier to `u64::from_le_bytes(*b"IPIRpool")`, then draws one
32-byte setup seed per slot. Each slot uses the existing public polynomial
sampler. The public matrix pool is independent of all private key/error RNGs
and the fixed packing-mask seeds. Pool prefixes intentionally agree across
sizes 4, 8 and 16; changing the size does not grant additional use of an old
secret. Any incompatible derivation change requires a new stream domain.

`QueryPool::start_batch` always draws a new OS-random private seed. A batch has
no Clone, Debug, persistence, caller-selected seed, or counter-reset interface.
`next_query(&mut self, row)` checks the public bounds and consumes its slot
before generating the query. Exhaustion returns an error permanently. Retrying
uses the immutable `SlotQuery::bytes()` value, with no new randomness. Restart
means a new batch and secret; active process-memory cloning is outside this
prototype's model. Existing secret types do not guarantee memory zeroization.

Each client can use every pool slot; slots are consumed per secret, not globally.
Different batches reuse the same public sets with new secrets and evaluation
keys. Public matrices and snapshot-specific decoding data may remain cached
across batches without preserving the private batch state or a client key ID.

## Integration boundary

The harness serializes/deserializes keys once per reused batch and once per
fresh query. Queries and responses use existing production encodings. Server
evaluation and packing use the existing functions without cryptographic changes.
It selects preprocessing and published `c1` by the query's slot. All sets share
one encoded database and one fixed `TopKeyImages` cache. Each set retains its own
packing digit cache and published response `c1` rows.

There is deliberately no new HTTP endpoint, persistent key cache, wire version,
or durable client state. A future transport must bind parameters, setup identity,
snapshot, batch key and slot before evaluation/decoding. Rejecting duplicate
queries on the server cannot undo privacy leakage already caused by the client.
Wrong-slot decoding is tested to produce a wrong result; rounding is not an
authenticator. Cache eviction must never cause a client to reset an existing
batch's slot allocation.

## Running the experiment

```bash
cargo test -p ipir-sp --release --features experimental-key-reuse
cargo run --release -p ipir-sp --features experimental-key-reuse \
  --example key_reuse_bench -- 2048 4096 4 5
cargo run --release -p ipir-sp --features experimental-key-reuse \
  --example key_reuse_bench -- 28672 32768 4 3
```

Arguments are rows, columns, pool size and complete batches. Sizes 4, 8 and 16
are supported. All runs use production RLWE parameters, an explicitly synthetic
arithmetic-pattern database, and fresh private randomness. Every decoded
coefficient is checked; maximum sampled error must stay below `delta/8`, one
quarter of the decryption threshold. The synthetic pattern does not establish
the failure probability or the error distribution for a real nullifier snapshot.

The output records measured serialized payload lengths, preparation times,
client generation/serialization time amortized per query, separate server key
parse time, server answer time and client decoding time. The modes alternate
order across batches. Timing is a local sample, not network latency or a
statistically controlled production throughput result.

Warm traffic excludes already-cached public decoding data. Cold traffic includes
one complete initial batch: one public set for fresh keys, all pool sets for
reuse. Headers, network framing, seed metadata, cache lookup and connection setup
are excluded. Packing cache payload counts retained polynomial buffers only,
not process RSS, allocator overhead, database, client data or temporary buffers.

For `N` queries against one snapshot, in complete `B`-query batches, let `K` be
key bytes and `C` decoding bytes per set. Relative to fresh keys, reuse saves
`N*K*(1-1/B) - (B-1)*C` total bytes. Unused batch capacity reduces amortization;
snapshot invalidation can require downloading new decoding data.
