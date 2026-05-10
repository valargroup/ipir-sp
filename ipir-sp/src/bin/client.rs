#[cfg(feature = "http_client")]
use clap::Parser;
#[cfg(feature = "http_client")]
use ipir_sp::client::IPIRClient;
#[cfg(feature = "http_client")]
use ipir_sp::serialize::serialize_packing_keys;

#[cfg(feature = "http_client")]
#[derive(Parser, Debug)]
#[command(version, about = "Run an IPIR-SP HTTP client")]
struct Args {
    /// Target row to query.
    target_row: usize,
    /// Number of items in the database.
    num_items: usize,
    /// Size of each item in bits.
    item_size_bits: Option<usize>,
    /// Server port.
    #[clap(long, short, default_value = "8080")]
    port: u16,
    /// Deterministic setup seed shared with the server.
    #[clap(long, default_value = "7")]
    setup_seed: u64,
}

#[cfg(feature = "http_client")]
fn seed_from_u64(value: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    seed
}

#[cfg(feature = "http_client")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let item_size_bits = args.item_size_bits.unwrap_or(16_384 * 8);
    let client = IPIRClient::from_db_sz(args.num_items as u64, item_size_bits as u64);
    assert!(
        args.target_row < client.params().db_rows,
        "target row out of bounds"
    );

    let setup =
        client.generate_public_query_setup_simplepir_from_seed(seed_from_u64(args.setup_seed));
    let (query, packing_keys, client_seed) =
        client.generate_fresh_query_simplepir(&setup, args.target_row);
    let packing_keys_body = serialize_packing_keys(client.rlwe_params(), &packing_keys)?;
    let online_query = query.to_packed_bytes(client.rlwe_params().q);
    let mut body = Vec::with_capacity(packing_keys_body.len() + online_query.len());
    body.extend_from_slice(&packing_keys_body);
    body.extend_from_slice(&online_query);
    let response = reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{}/query", args.port))
        .body(body)
        .send()?
        .error_for_status()?
        .bytes()?;

    let decoded = client.decode_response_simplepir(client_seed, &response);
    let preview_len = decoded.len().min(32);
    println!("Result: {:?}", &decoded[..preview_len]);
    Ok(())
}

#[cfg(not(feature = "http_client"))]
fn main() {
    panic!("This binary requires the 'http_client' feature.");
}
