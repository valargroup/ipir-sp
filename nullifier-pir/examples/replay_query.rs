//! Emit one `POST /query` body so the same bytes can be replayed against two
//! server builds.
//!
//! A server response is a deterministic function of `(snapshot, setup_seed,
//! query bytes)`. Any change that claims to be bit-exact — a kernel rewrite, a
//! loop reordering — must therefore return byte-identical responses for a fixed
//! query blob. Client query generation samples fresh randomness per call, so
//! the blob has to be generated once and reused rather than regenerated per
//! server; that is what this exists for.
//!
//! ```text
//! cargo run --release -p nullifier-pir --example replay_query -- \
//!     --records 49925853 --row 12345 --out /tmp/query.bin
//! curl -s --data-binary @/tmp/query.bin http://127.0.0.1:8081/query | sha256sum
//! curl -s --data-binary @/tmp/query.bin http://127.0.0.1:8082/query | sha256sum
//! ```
//!
//! The two hashes must match. This checks the online path only — the query
//! body carries the packing keys and the first-dimension query, and the
//! response is the packed `c2` rows.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ipir_sp::client::IPIRClient;
use ipir_sp::serialize::serialize_packing_keys;
use nullifier_pir::backend::seed_from_u64;
use nullifier_pir::encoding::pir_row_count;
use nullifier_pir::ITEM_SIZE_BITS;

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() -> Result<()> {
    let records: usize = arg("--records")
        .context("--records <count> is required")?
        .parse()
        .context("--records must be an integer")?;
    let row: usize = arg("--row").unwrap_or_else(|| "0".to_string()).parse()?;
    let setup_seed: u64 = arg("--setup-seed")
        .unwrap_or_else(|| "7".to_string())
        .parse()?;
    let out = PathBuf::from(arg("--out").context("--out <path> is required")?);

    let pir_item_count = pir_row_count(records);
    let client = IPIRClient::from_db_sz(pir_item_count as u64, ITEM_SIZE_BITS);
    anyhow::ensure!(
        row < client.params().db_rows,
        "row {row} is out of range for {} rows",
        client.params().db_rows
    );

    let setup = client.generate_public_query_setup_simplepir_from_seed(seed_from_u64(setup_seed));
    let (query, packing_keys, _client_seed) = client.generate_fresh_query_simplepir(&setup, row);

    let keys = serialize_packing_keys(client.rlwe_params(), &packing_keys)
        .context("serialize packing keys")?;
    let switched = query.to_switched_bytes(client.rlwe_params().q, client.params().query_bits);

    let mut body = Vec::with_capacity(keys.len() + switched.len());
    body.extend_from_slice(&keys);
    body.extend_from_slice(&switched);

    std::fs::write(&out, &body).with_context(|| format!("write {}", out.display()))?;
    println!(
        "wrote {} bytes to {} (rows={}, row={}, setup_seed={}, keys={}, query={})",
        body.len(),
        out.display(),
        client.params().db_rows,
        row,
        setup_seed,
        keys.len(),
        switched.len()
    );
    Ok(())
}
