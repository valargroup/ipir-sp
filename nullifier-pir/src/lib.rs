//! Nullifier PIR server built on SimplePIR-shaped backends.

#![deny(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod backend;
pub mod encoding;
pub mod http;
pub mod manifest;
pub mod snapshot;

pub use backend::{Backend, BackendKind, BackendMetadata, LocalIpirBackend, PirBackend};
pub use encoding::{
    decode_item_coefficients, encode_item_bytes, extract_nullifier, nullifier_offset,
    pir_row_count, ITEM_BYTES, ITEM_SIZE_BITS, NULLIFIERS_PER_ITEM, NULLIFIER_BYTES,
};
pub use snapshot::{
    download_snapshot, metadata_path, sha256_file, validate_snapshot_len, NullifierSnapshot,
    SnapshotMetadata, DEFAULT_SNAPSHOT_URL,
};
