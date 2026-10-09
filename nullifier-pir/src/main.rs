use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipir_sp::client::{ClientError, IPIRClient};
use ipir_sp::manifest::COORDINATOR_KEY_BYTES;
use ipir_sp::modulus_switch::recover_published_c1;
use ipir_sp::serialize::serialize_packing_keys;
use ipir_sp::{ProductionSimplePirParams, SimplePirProfile, VerifiedPublicParams};
use nullifier_pir::backend::{Backend, BackendKind, PirBackend};
use nullifier_pir::encoding::{decode_item_coefficients, extract_nullifier, nullifier_offset};
use nullifier_pir::http::{
    SERVER_MATRIX_VECTOR_TIME_HEADER, SERVER_ONLINE_DESERIALIZE_TIME_HEADER,
    SERVER_PACKING_TIME_HEADER, SERVER_PACK_PREPROCESS_TIME_HEADER,
    SERVER_SERIALIZATION_TIME_HEADER, SERVER_SETUP_DESERIALIZE_TIME_HEADER, SERVER_TIME_HEADER,
};
use nullifier_pir::manifest::{ManifestArtifacts, ManifestEnvelope};
use nullifier_pir::snapshot::{
    download_snapshot, sha256_file, write_metadata, NullifierSnapshot, SnapshotMetadata,
    DEFAULT_SNAPSHOT_URL,
};
use nullifier_pir::ITEM_SIZE_BITS;
use sha2::Digest as _;
#[cfg(feature = "ypir-artifact")]
use ypir::serialize::ToBytes as YpirToBytes;

const META_ENDPOINT: &str = "/meta";
const QUERY_ENDPOINT: &str = "/query";
const PUBLIC_PARAMS_ENDPOINT: &str = "/public-params";
const MANIFEST_ENDPOINT: &str = "/manifest";
const ROW_DIGESTS_ENDPOINT: &str = "/row-digests";
/// Exit status when a response fails row authentication.
const TAMPER_EXIT_CODE: i32 = 3;

#[derive(Debug, Clone)]
struct UploadBreakdown {
    backend: &'static str,
    components: Vec<(&'static str, usize)>,
}

impl UploadBreakdown {
    fn total(&self) -> usize {
        self.components.iter().map(|(_, bytes)| *bytes).sum()
    }

    fn format_components(&self) -> String {
        self.components
            .iter()
            .map(|(name, bytes)| format!("{name}={bytes}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, Default)]
struct ServerTimingBreakdown {
    total_us: Option<u128>,
    setup_deserialize_us: Option<u128>,
    pack_preprocess_us: Option<u128>,
    online_deserialize_us: Option<u128>,
    matrix_vector_us: Option<u128>,
    packing_us: Option<u128>,
    serialization_us: Option<u128>,
}

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
        /// DEV ONLY: sign the snapshot manifest with the hex Ed25519 seed in
        /// this file. Production signatures come from the coordinator.
        #[arg(long)]
        dev_sign_key_file: Option<PathBuf>,
    },
    /// Write manifest.json and row-digests.bin next to a snapshot.
    ///
    /// `serve` does this at startup too; this subcommand produces the bytes
    /// for the coordinator to sign without starting a server. The signature
    /// goes in manifest.sig next to them.
    Manifest {
        /// Snapshot to describe.
        #[arg(long, default_value = "data/nullifiers.bin")]
        snapshot_path: PathBuf,
        /// Setup seed the server will be started with.
        #[arg(long, default_value_t = 7)]
        setup_seed: u64,
        /// DEV ONLY: also sign with the hex Ed25519 seed in this file.
        #[arg(long)]
        dev_sign_key_file: Option<PathBuf>,
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
        /// Pinned coordinator Ed25519 public key, 64 hex characters. The
        /// manifest, `c1` and row digests are verified against it before any
        /// query is sent, and the answer is checked against its row digest.
        #[arg(long, conflicts_with = "allow_unverified")]
        coordinator_pubkey: Option<String>,
        /// Skip authentication, for fixtures and servers without a signed
        /// manifest. The decoded row is then key-equivalent under a malicious
        /// server and is not authenticated.
        #[arg(long)]
        allow_unverified: bool,
    },
}

/// Turns a `/query` response body into the decoded row bytes.
type Decoder = Box<dyn FnOnce(&[u8]) -> Result<Vec<u8>>>;

/// How the query client authenticates the server.
#[derive(Debug, Clone, Copy)]
enum Trust {
    Pinned([u8; COORDINATOR_KEY_BYTES]),
    Unverified,
}

#[actix_web::main]
async fn main() -> Result<()> {
    let result = run(Cli::parse()).await;
    if let Err(err) = &result {
        let tampered = err.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<ClientError>(),
                Some(ClientError::TamperDetected { .. })
            )
        });
        if tampered {
            eprintln!("Error: {err:#}");
            std::process::exit(TAMPER_EXIT_CODE);
        }
    }
    result
}

async fn run(cli: Cli) -> Result<()> {
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
            dev_sign_key_file,
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
            let manifest = publish_manifest(
                &snapshot,
                &backend,
                setup_seed,
                dev_sign_key_file.as_deref(),
            )?;
            let backend: Arc<dyn PirBackend> = Arc::new(backend);
            println!("Listening on http://{host}:{port}");
            nullifier_pir::http::serve(host, port, backend, metadata, manifest).await?;
        }
        Command::Manifest {
            snapshot_path,
            setup_seed,
            dev_sign_key_file,
        } => {
            let snapshot = NullifierSnapshot::open(&snapshot_path)?;
            let backend = Backend::prepare(BackendKind::LocalIpir, &snapshot, setup_seed)?;
            let artifacts = publish_manifest(
                &snapshot,
                &backend,
                setup_seed,
                dev_sign_key_file.as_deref(),
            )?
            .context("local-ipir backend has no production profile to describe")?;
            print!("{}", String::from_utf8_lossy(&artifacts.manifest));
            println!("manifest_sha256 {}", artifacts.manifest_sha256());
        }
        Command::Query {
            server_url,
            snapshot_path,
            nullifier_hex,
            setup_seed,
            expect_absent,
            absent_probe_row,
            coordinator_pubkey,
            allow_unverified,
        } => {
            let trust = match (coordinator_pubkey, allow_unverified) {
                (Some(key), false) => Trust::Pinned(parse_coordinator_key(&key)?),
                (None, true) => Trust::Unverified,
                _ => anyhow::bail!(
                    "pass --coordinator-pubkey to authenticate the server, or --allow-unverified for fixtures"
                ),
            };
            let target = parse_nullifier_hex(&nullifier_hex)?;
            let snapshot = NullifierSnapshot::open(&snapshot_path)?;
            let found = snapshot.find_nullifier(&target)?;

            if expect_absent {
                if let Some(index) = found {
                    anyhow::bail!(
                        "expected absent nullifier, but found it at global index {index}"
                    );
                }
                let row_bytes = query_row(
                    &server_url,
                    setup_seed,
                    absent_probe_row,
                    &target,
                    None,
                    trust,
                )?;
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
                let row_bytes =
                    query_row(&server_url, setup_seed, row, &target, Some(offset), trust)?;
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

/// Generate, sign (dev only) and write the manifest artefacts for a backend
/// that has a production profile. Returns what `/manifest` should serve.
fn publish_manifest(
    snapshot: &NullifierSnapshot,
    backend: &Backend,
    setup_seed: u64,
    dev_sign_key_file: Option<&Path>,
) -> Result<Option<ManifestArtifacts>> {
    let Some(params) = backend.production_params() else {
        if dev_sign_key_file.is_some() {
            anyhow::bail!("--dev-sign-key-file needs the local-ipir backend");
        }
        return Ok(None);
    };
    let dev_key = dev_sign_key_file
        .map(nullifier_pir::manifest::read_dev_signing_key)
        .transpose()?;
    if let Some(key) = &dev_key {
        eprintln!(
            "warning: signing the manifest with DEV key {}; production signatures come from the coordinator",
            hex::encode(key.verifying_key().to_bytes())
        );
    }
    let started = Instant::now();
    let (manifest, row_digests) =
        nullifier_pir::manifest::generate(snapshot, params, setup_seed, &backend.public_params())?;
    let dir = nullifier_pir::manifest::artifact_dir(snapshot.path());
    let artifacts =
        nullifier_pir::manifest::publish(&dir, &manifest, &row_digests, dev_key.as_ref())?;
    println!(
        "manifest {} sha256={} rows={} signed={} in {} ms",
        dir.join(nullifier_pir::manifest::MANIFEST_FILE).display(),
        artifacts.manifest_sha256(),
        manifest.row_count,
        artifacts.signature.is_some(),
        started.elapsed().as_millis()
    );
    Ok(Some(artifacts))
}

fn parse_coordinator_key(input: &str) -> Result<[u8; COORDINATOR_KEY_BYTES]> {
    let bytes = hex::decode(input.trim()).context("--coordinator-pubkey is not valid hex")?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "--coordinator-pubkey must be {COORDINATOR_KEY_BYTES} bytes, got {}",
            bytes.len()
        )
    })
}

fn get_bytes(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>> {
    Ok(client
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}"))?
        .bytes()
        .with_context(|| format!("read {url} body"))?
        .to_vec())
}

/// Fetch and check every snapshot artefact before the first query, so a
/// failed check sends nothing.
fn fetch_verified_params(
    client: &reqwest::blocking::Client,
    server_url: &str,
    meta: &serde_json::Value,
    profile: &ProductionSimplePirParams,
    setup_seed: u64,
    coordinator_key: &[u8; COORDINATOR_KEY_BYTES],
    public_params: &[u8],
) -> Result<VerifiedPublicParams> {
    let base = server_url.trim_end_matches('/');
    let envelope: ManifestEnvelope =
        serde_json::from_slice(&get_bytes(client, &format!("{base}{MANIFEST_ENDPOINT}"))?)
            .context("decode /manifest JSON")?;
    let (manifest, signature) = envelope.decode()?;
    let signature = signature
        .context("server has no coordinator signature for this snapshot; refusing to query")?;
    let row_digests = get_bytes(client, &format!("{base}{ROW_DIGESTS_ENDPOINT}"))?;

    let advertised = meta["manifest_sha256"]
        .as_str()
        .context("missing manifest_sha256 in /meta")?;
    let fetched = hex::encode(sha2::Sha256::digest(&manifest));
    if advertised != fetched {
        anyhow::bail!(
            "/meta advertises manifest {advertised} but /manifest served {fetched}; the snapshot changed, retry"
        );
    }

    VerifiedPublicParams::verify(
        profile,
        setup_seed,
        coordinator_key,
        &manifest,
        &signature,
        public_params,
        &row_digests,
    )
    .context("server snapshot artefacts failed verification; refusing to query")
}

fn query_row(
    server_url: &str,
    setup_seed: u64,
    row: usize,
    target: &[u8; nullifier_pir::NULLIFIER_BYTES],
    expected_offset: Option<usize>,
    trust: Trust,
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
    let backend_kind = meta["backend"]["backend"]
        .as_str()
        .context("missing backend.backend in /meta")?;
    if setup_seed_from_server != setup_seed {
        anyhow::bail!(
            "setup seed mismatch: server reports {}, client used {}",
            setup_seed_from_server,
            setup_seed
        );
    }

    let query_started = Instant::now();
    let query_gen_started = Instant::now();
    let query_url = format!("{}{}", server_url.trim_end_matches('/'), QUERY_ENDPOINT);

    let (query_body, upload_breakdown, decoder): (Vec<u8>, UploadBreakdown, Decoder) =
        if backend_kind == "ypir-artifact" {
            if let Trust::Pinned(_) = trust {
                anyhow::bail!(
                "the ypir-artifact backend has no signed manifest; pass --allow-unverified to query it"
            );
            }
            #[cfg(feature = "ypir-artifact")]
            {
                let ypir_client =
                    ypir::client::YPIRClient::from_db_sz(pir_item_count, ITEM_SIZE_BITS);
                let (query, client_seed) = ypir_client.generate_query_simplepir(row);
                let simplepir_query_bytes = query.0.as_slice().len() * std::mem::size_of::<u64>();
                let pack_pub_params_bytes = query.1.as_slice().len() * std::mem::size_of::<u64>();
                let query_body = YpirToBytes::to_bytes(&query);
                (
                    query_body,
                    UploadBreakdown {
                        backend: "ypir-artifact",
                        components: vec![
                            ("simplepir_query", simplepir_query_bytes),
                            ("pack_pub_params", pack_pub_params_bytes),
                        ],
                    },
                    Box::new(move |response| {
                        Ok(ypir_client.decode_response_simplepir(client_seed, response))
                    }),
                )
            }
            #[cfg(not(feature = "ypir-artifact"))]
            {
                anyhow::bail!(
                    "server uses ypir-artifact, but client was built without that feature"
                );
            }
        } else {
            let profile = ProductionSimplePirParams::new(
                pir_item_count,
                ITEM_SIZE_BITS,
                SimplePirProfile::P14,
            )
            .context("derive SimplePIR parameters from /meta")?;
            let pir_client = IPIRClient::new(&profile);
            // `c1` is constant for the snapshot, so it is fetched once here instead
            // of riding along with every response.
            let public_params_url = format!(
                "{}{}",
                server_url.trim_end_matches('/'),
                PUBLIC_PARAMS_ENDPOINT
            );
            let published_c1_bytes = get_bytes(&client, &public_params_url)?;
            // Everything the decoder needs is checked here, before the query is
            // built, so a failed check sends nothing.
            let published_c1 = match trust {
                Trust::Pinned(key) => Ok(fetch_verified_params(
                    &client,
                    server_url,
                    &meta,
                    &profile,
                    setup_seed,
                    &key,
                    &published_c1_bytes,
                )?),
                Trust::Unverified => {
                    eprintln!(
                    "warning: --allow-unverified: the server's c1 and answer are not authenticated"
                );
                    Err(recover_published_c1(
                        &published_c1_bytes,
                        pir_client.rlwe_params().d,
                        pir_client.params().db_cols / pir_client.rlwe_params().d,
                        pir_client.rlwe_params().q,
                    )?)
                }
            };
            let offline_query_polys = pir_client.generate_public_query_setup_simplepir_from_seed(
                nullifier_pir::backend::seed_from_u64(setup_seed),
            );
            let (query, packing_keys, client_seed) =
                pir_client.generate_fresh_query_simplepir(&offline_query_polys, row);
            let packing_keys_body = serialize_packing_keys(pir_client.rlwe_params(), &packing_keys)
                .context("serialize local ipir packing keys")?;
            let online_query_packed =
                query.to_switched_bytes(pir_client.rlwe_params().q, pir_client.params().query_bits);
            let packing_keys_bytes = packing_keys_body.len();
            let online_query_packed_bytes = online_query_packed.len();
            let mut query_body = Vec::with_capacity(packing_keys_bytes + online_query_packed_bytes);
            query_body.extend_from_slice(&packing_keys_body);
            query_body.extend_from_slice(&online_query_packed);
            (
                query_body,
                UploadBreakdown {
                    backend: "local-ipir",
                    components: vec![
                        ("packing_keys", packing_keys_bytes),
                        ("online_query", online_query_packed_bytes),
                    ],
                },
                Box::new(move |response| match published_c1 {
                    Ok(verified) => pir_client
                        .decode_response_simplepir_verified(client_seed, &verified, response, row)
                        .map_err(|err| {
                            match err {
                        ClientError::TamperDetected { .. } => anyhow::Error::new(err).context(
                            "TAMPER DETECTED: the server answered from a database that does not \
                             match the coordinator-signed snapshot; do not act on this answer",
                        ),
                        other => anyhow::Error::new(other).context("decode PIR response"),
                    }
                        }),
                    Err(published_c1) => {
                        let decoded_coeffs = pir_client.decode_response_simplepir_raw_unverified(
                            client_seed,
                            &published_c1,
                            response,
                        )?;
                        Ok(decode_item_coefficients(&decoded_coeffs))
                    }
                }),
            )
        };
    let query_gen_time = query_gen_started.elapsed();

    let (response, post_round_trip, server_timing, upload_bytes, download_bytes) =
        post_query(&client, &query_url, query_body)?;

    let decode_started = Instant::now();
    let row_bytes = decoder(&response)?;
    let decode_time = decode_started.elapsed();
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
    println!(
        "timing_us total_query={} client_query_gen={} http_post_round_trip={} server={} client_decode={}",
        query_started.elapsed().as_micros(),
        query_gen_time.as_micros(),
        post_round_trip.as_micros(),
        server_timing
            .total_us
            .map(|value| value.to_string())
            .unwrap_or_else(|| "missing".to_string()),
        decode_time.as_micros()
    );
    println!(
        "server_breakdown_us setup_deserialize={} pack_preprocess={} online_deserialize={} matrix_vector={} packing={} serialization={}",
        format_optional_us(server_timing.setup_deserialize_us),
        format_optional_us(server_timing.pack_preprocess_us),
        format_optional_us(server_timing.online_deserialize_us),
        format_optional_us(server_timing.matrix_vector_us),
        format_optional_us(server_timing.packing_us),
        format_optional_us(server_timing.serialization_us),
    );
    println!("wire_bytes upload={upload_bytes} download={download_bytes}");
    println!(
        "upload_breakdown backend={} total={} {}",
        upload_breakdown.backend,
        upload_breakdown.total(),
        upload_breakdown.format_components()
    );
    Ok(row_bytes)
}

fn format_optional_us(value: Option<u128>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "missing".to_string())
}

fn post_query(
    client: &reqwest::blocking::Client,
    query_url: &str,
    query_body: Vec<u8>,
) -> Result<(
    Vec<u8>,
    std::time::Duration,
    ServerTimingBreakdown,
    usize,
    usize,
)> {
    let upload_bytes = query_body.len();
    let post_started = Instant::now();
    let response = client
        .post(query_url)
        .body(query_body)
        .send()
        .with_context(|| format!("POST {query_url}"))?
        .error_for_status()?;
    let post_round_trip = post_started.elapsed();
    let headers = response.headers();
    let server_timing = ServerTimingBreakdown {
        total_us: parse_header_us(headers, SERVER_TIME_HEADER),
        setup_deserialize_us: parse_header_us(headers, SERVER_SETUP_DESERIALIZE_TIME_HEADER),
        pack_preprocess_us: parse_header_us(headers, SERVER_PACK_PREPROCESS_TIME_HEADER),
        online_deserialize_us: parse_header_us(headers, SERVER_ONLINE_DESERIALIZE_TIME_HEADER),
        matrix_vector_us: parse_header_us(headers, SERVER_MATRIX_VECTOR_TIME_HEADER),
        packing_us: parse_header_us(headers, SERVER_PACKING_TIME_HEADER),
        serialization_us: parse_header_us(headers, SERVER_SERIALIZATION_TIME_HEADER),
    };
    let response = response
        .bytes()
        .with_context(|| format!("read {query_url} response"))?;
    let download_bytes = response.len();
    Ok((
        response.to_vec(),
        post_round_trip,
        server_timing,
        upload_bytes,
        download_bytes,
    ))
}

fn parse_header_us(headers: &reqwest::header::HeaderMap, name: &'static str) -> Option<u128> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u128>().ok())
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
