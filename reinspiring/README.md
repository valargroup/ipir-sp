# `reinspiring` — ReinspiRING.Pack crate

Standalone Rust implementation of **Algorithm 2 (`ReinspiRING`)** from:

> R. A. Mahdavi, S. Patel, J. Y. Seo, K. Yeo. *ReinsPIRe: High-Throughput,
> Low-Communication PIR with Server Preprocessing.* ePrint 2026/1934.
> <https://eprint.iacr.org/2026/1934>

ReinspiRING recompiles InspiRING’s online NTT sum of polynomial products into
a coefficient-domain matrix–vector product (`H' · y`), keeping the leftover
`t'' · y'` as a lifted-NTT multiply. For odd NTT-friendly moduli it is an
**exact** rewrite of [`inspiring::QueryPackPreprocessed::pack_b`](../inspiring/).

```rust
pub fn preprocess_from_inspiring<'a>(
    pre: &'a inspiring::QueryPackPreprocessed<'a>,
) -> Result<ReinspiringPreprocessed<'a>, ReinspiringError>;

pub fn pack<'a>(
    b_scalars: &[u64],
    keys: &inspiring::PackingKeys<'a>,
    pre: &ReinspiringPreprocessed<'a>,
) -> Result<inspiring::RlweCiphertext<'a>, ReinspiringError>;
```

See [`SPEC.md`](SPEC.md) for the paper-to-code contract.

## Scope

- Algorithm 2 only (`Preprocess` + `Pack`).
- No vReinsPIRe, no ReinsPIRe+, no PIR layers.
- Depends on `inspiring` for CRS digit material on the odd-`q` path.

## Build

```bash
cargo test -p reinspiring
cargo bench -p reinspiring --bench pack
```

## License

MIT OR Apache-2.0.
