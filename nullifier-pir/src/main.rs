use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipir_sp::client::IPIRClient;
use nullifier_pir::backend::{Backend, BackendKind, PirBackend};
use nullifier_pir::encoding::{decode_item_coefficients, extract_nullifier, nullifier_offset};
use nullifier_pir::snapshot::{
    download_snapshot, sha256_file, write_metadata, NullifierSnapshot, SnapshotMetadata,
    DEFAULT_SNAPSHOT_URL,
};
use nullifier_pir::ITEM_SIZE_BITS;

const META_ENDPOINT: &str = "/meta";
const QUERY_ENDPOINT: &str = "/query";

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Run a PIR HTTP server over 32-byte nullifier snapshots"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Download and validate a nullifier snapshot.
    Download {
        /// Snapshot URL.
        #[arg(long, default_value = DEFAULT_SNAPSHOT_URL)]
        url: String,
        /// Output file path.
        #[arg(long, default_value = "data/nullifiers.bin")]
        output: PathBuf,
    },
    /// Start the HTTP PIR server.
    Serve {
        /// Existing or downloaded snapshot path.
        #[arg(long, default_value = "data/nullifiers.bin")]
        snapshot_path: PathBuf,
        /// Download this URL first if snapshot_path does not exist.
        #[arg(long)]
        snapshot_url: Option<String>,
        /// Backend implementation.
        #[arg(long, value_enum, default_value_t = BackendKind::LocalIpir)]
        backend: BackendKind,
        /// Bind host.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Bind port.
        #[arg(long, short, default_value_t = 8080)]
        port: u16,
        /// Deterministic setup seed shared with compatible clients.
        #[arg(long, default_value_t = 7)]
        setup_seed: u64,
        /// Recompute SHA-256 for /meta. This scans the full snapshot.
        #[arg(long)]
        hash_snapshot: bool,
    },
    /// Query a server and verify an existing or absent nullifier.
    Query {
        /// Server base URL.
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server_url: String,
        /// Snapshot path used only to locate/check the target for validation.
        #[arg(long, default_value = "data/nullifiers-small-100mb.bin")]
        snapshot_path: PathBuf,
        /// 32-byte nullifier as 64 lowercase or uppercase hex characters.
        #[arg(long)]
        nullifier_hex: String,
        /// Deterministic setup seed used by the server.
        #[arg(long, default_value_t = 7)]
        setup_seed: u64,
        /// Expect the nullifier to be absent from the local snapshot.
        #[arg(long)]
        expect_absent: bool,
        /// Row to query when checking an absent nullifier.
        #[arg(long, default_value_t = 0)]
        absent_probe_row: usize,
    },
}

#[actix_web::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Download { url, output } => {
            let metadata = download_snapshot(&url, &output)?;
            println!("{}", serde_json::to_string_pretty(&metadata)?);
        }
        Command::Serve {
            snapshot_path,
            snapshot_url,
            backend,
            host,
            port,
            setup_seed,
            hash_snapshot,
        } => {
            if !snapshot_path.exists() {
                let Some(url) = snapshot_url.as_deref() else {
                    anyhow::bail!(
                        "snapshot {} does not exist; pass --snapshot-url or run download first",
                        snapshot_path.display()
                    );
                };
                download_snapshot(url, &snapshot_path)?;
            }

            let snapshot = NullifierSnapshot::open(&snapshot_path)?;
            let sha256 = if hash_snapshot {
                sha256_file(&snapshot_path).context("hash snapshot")?
            } else {
                "not-computed".to_string()
            };
            let metadata = SnapshotMetadata {
                source_url: snapshot_url,
                path: snapshot.path().to_path_buf(),
                bytes: snapshot.bytes(),
                record_count: snapshot.record_count(),
                pir_row_count: snapshot.pir_row_count(),
                nullifier_bytes: nullifier_pir::NULLIFIER_BYTES,
                nullifiers_per_item: nullifier_pir::NULLIFIERS_PER_ITEM,
                sha256,
                etag: None,
            };
            write_metadata(snapshot.path(), &metadata)?;

            let backend = Backend::prepare(backend, &snapshot, setup_seed)?;
            let backend: Arc<dyn PirBackend> = Arc::new(backend);
            println!("Listening on http://{host}:{port}");
            nullifier_pir::http::serve(host, port, backend, metadata).await?;
        }
        Command::Query {
            server_url,
            snapshot_path,
            nullifier_hex,
            setup_seed,
            expect_absent,
            absent_probe_row,
        } => {
            let target = parse_nullifier_hex(&nullifier_hex)?;
            let snapshot = NullifierSnapshot::open(&snapshot_path)?;
            let found = snapshot.find_nullifier(&target)?;

            if expect_absent {
                if let Some(index) = found {
                    anyhow::bail!(
                        "expected absent nullifier, but found it at global index {index}"
                    );
                }
                let row_bytes =
                    query_row(&server_url, setup_seed, absent_probe_row, &target, None)?;
                if row_contains_nullifier(&row_bytes, &target) {
                    anyhow::bail!(
                        "absent nullifier unexpectedly appeared in decoded row {absent_probe_row}"
                    );
                }
                println!(
                    "absent nullifier {} not found locally and not present in decoded row {}",
                    nullifier_hex.to_lowercase(),
                    absent_probe_row
                );
            } else {
                let Some(index) = found else {
                    anyhow::bail!("nullifier was not found in {}", snapshot_path.display());
                };
                let (row, offset) = nullifier_offset(index);
                let row_bytes = query_row(&server_url, setup_seed, row, &target, Some(offset))?;
                let returned = extract_nullifier(&row_bytes, offset)
                    .context("decoded row did not contain expected offset")?;
                if returned != target {
                    anyhow::bail!("decoded nullifier did not match target at row {row}");
                }
                println!(
                    "existing nullifier {} found at global index {}, row {}, offset {} and verified through PIR",
                    nullifier_hex.to_lowercase(),
                    index,
                    row,
                    offset
                );
            }
        }
    }

    Ok(())
}

fn query_row(
    server_url: &str,
    setup_seed: u64,
    row: usize,
    target: &[u8; nullifier_pir::NULLIFIER_BYTES],
    expected_offset: Option<usize>,
) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::new();
    let meta_url = format!("{}{}", server_url.trim_end_matches('/'), META_ENDPOINT);
    let meta: serde_json::Value = client
        .get(&meta_url)
        .send()
        .with_context(|| format!("GET {meta_url}"))?
        .error_for_status()?
        .json()
        .with_context(|| format!("decode {meta_url} JSON"))?;
    let pir_item_count = meta["backend"]["pir_item_count"]
        .as_u64()
        .context("missing backend.pir_item_count in /meta")?;
    let record_count = meta["backend"]["record_count"]
        .as_u64()
        .context("missing backend.record_count in /meta")?;
    let setup_seed_from_server = meta["backend"]["setup_seed"]
        .as_u64()
        .context("missing backend.setup_seed in /meta")?;
    if setup_seed_from_server != setup_seed {
        anyhow::bail!(
            "setup seed mismatch: server reports {}, client used {}",
            setup_seed_from_server,
            setup_seed
        );
    }

    let pir_client = IPIRClient::from_db_sz(pir_item_count, ITEM_SIZE_BITS);
    let query_setup = pir_client.generate_query_setup_simplepir_from_seed(
        nullifier_pir::backend::seed_from_u64(setup_seed),
    );
    let (query, client_seed) =
        pir_client.generate_query_simplepir_from_query_setup(&query_setup, row);
    let query_url = format!("{}{}", server_url.trim_end_matches('/'), QUERY_ENDPOINT);
    let response = client
        .post(&query_url)
        .body(query.to_bytes())
        .send()
        .with_context(|| format!("POST {query_url}"))?
        .error_for_status()?
        .bytes()
        .with_context(|| format!("read {query_url} response"))?;

    let decoded_coeffs = pir_client.decode_response_simplepir_raw(client_seed, &response);
    let row_bytes = decode_item_coefficients(&decoded_coeffs);
    if let Some(offset) = expected_offset {
        let returned = extract_nullifier(&row_bytes, offset)
            .context("decoded row did not contain expected nullifier offset")?;
        if &returned != target {
            anyhow::bail!("server response decoded, but expected offset did not match target");
        }
    }

    println!(
        "queried row {} against {} records and decoded {} bytes",
        row,
        record_count,
        row_bytes.len()
    );
    Ok(row_bytes)
}

fn row_contains_nullifier(row: &[u8], target: &[u8; nullifier_pir::NULLIFIER_BYTES]) -> bool {
    row.chunks_exact(nullifier_pir::NULLIFIER_BYTES)
        .any(|candidate| candidate == target)
}

fn parse_nullifier_hex(input: &str) -> Result<[u8; nullifier_pir::NULLIFIER_BYTES]> {
    let trimmed = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    if trimmed.len() != nullifier_pir::NULLIFIER_BYTES * 2 {
        anyhow::bail!(
            "nullifier hex must be {} characters, got {}",
            nullifier_pir::NULLIFIER_BYTES * 2,
            trimmed.len()
        );
    }

    let mut out = [0u8; nullifier_pir::NULLIFIER_BYTES];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&trimmed[start..start + 2], 16)
            .with_context(|| format!("invalid hex byte at offset {start}"))?;
    }
    Ok(out)
}
