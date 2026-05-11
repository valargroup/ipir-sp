#[cfg(feature = "http_server")]
use actix_cors::Cors;
#[cfg(feature = "http_server")]
use actix_web::{get, post, web, App, HttpServer};
#[cfg(feature = "http_server")]
use clap::Parser;
#[cfg(feature = "http_server")]
use inspiring::{QueryPackPreprocessed, RlweParams, TopKeyImages};
#[cfg(feature = "http_server")]
use ipir_sp::client::IPIRClient;
#[cfg(feature = "http_server")]
use ipir_sp::modulus_switch::modulus_bits;
#[cfg(feature = "http_server")]
use ipir_sp::params_for_simplepir;
#[cfg(feature = "http_server")]
use ipir_sp::serialize::{deserialize_packing_keys, serialized_packing_keys_len};
#[cfg(feature = "http_server")]
use ipir_sp::server::{build_pack_preprocessed_blocks, IPIRServer};

#[cfg(feature = "http_server")]
#[derive(Parser, Debug)]
#[command(version, about = "Run an IPIR-SP HTTP server")]
struct Args {
    /// Number of items in the database.
    num_items: usize,
    /// Size of each item in bits.
    item_size_bits: Option<usize>,
    /// Port.
    #[clap(long, short, default_value = "8080")]
    port: u16,
    /// Deterministic setup seed shared with the demo client.
    #[clap(long, default_value = "7")]
    setup_seed: u64,
}

#[cfg(feature = "http_server")]
struct ServerState {
    rlwe: &'static RlweParams,
    ypir_rows: usize,
    server: IPIRServer<u16>,
    preprocessed: Vec<QueryPackPreprocessed<'static>>,
    top_keys: TopKeyImages<'static>,
}

#[cfg(feature = "http_server")]
#[post("/query")]
async fn query(
    body: web::Bytes,
    data: web::Data<ServerState>,
) -> Result<Vec<u8>, actix_web::error::Error> {
    let packing_keys_len = serialized_packing_keys_len(data.rlwe);
    let online_query_len = (data.ypir_rows * modulus_bits(data.rlwe.q)).div_ceil(8);
    if body.len() != packing_keys_len + online_query_len {
        return Err(actix_web::error::ErrorBadRequest(format!(
            "query must be {} bytes, got {}",
            packing_keys_len + online_query_len,
            body.len()
        )));
    }
    let packing_keys = deserialize_packing_keys(data.rlwe, &body[..packing_keys_len])
        .map_err(actix_web::error::ErrorBadRequest)?;
    let online_query = &body[packing_keys_len..];
    data.server
        .perform_full_online_computation_simplepir_measured(
            data.rlwe,
            online_query,
            &packing_keys,
            &data.top_keys,
            &data.preprocessed,
        )
        .map(|(response, _)| response)
        .map_err(actix_web::error::ErrorBadRequest)
}

#[cfg(feature = "http_server")]
#[get("/")]
async fn index(data: web::Data<ServerState>) -> String {
    format!("Hello {}!", data.rlwe.d)
}

#[cfg(feature = "http_server")]
#[get("/info")]
async fn info(data: web::Data<ServerState>) -> String {
    format!(
        "rows={} cols={}",
        data.server.db_rows(),
        data.server.db_cols()
    )
}

#[cfg(feature = "http_server")]
fn seed_from_u64(value: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    seed
}

#[cfg(feature = "http_server")]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let item_size_bits = args.item_size_bits.unwrap_or(16_384 * 8);
    let (rlwe, ypir) =
        params_for_simplepir(args.num_items as u64, item_size_bits as u64).expect("valid params");
    let client = Box::leak(Box::new(IPIRClient::new(&rlwe, &ypir)));
    let setup =
        client.generate_public_query_setup_simplepir_from_seed(seed_from_u64(args.setup_seed));

    let pt_modulus = ypir.p;
    let db = (0..ypir.db_rows * ypir.db_cols).map(|idx| (idx as u64 % pt_modulus) as u16);
    let server = IPIRServer::<u16>::new_auto_kernel(ypir.clone(), db, false, true);
    let offline = server.perform_offline_precomputation_simplepir(client.rlwe_params(), &setup);
    let preprocessed = build_pack_preprocessed_blocks(client.rlwe_params(), &offline.crs_blocks)
        .expect("preprocessing builds");
    let top_keys = TopKeyImages::build(client.rlwe_params());

    let app_data = web::Data::new(ServerState {
        rlwe: client.rlwe_params(),
        ypir_rows: ypir.db_rows,
        server,
        preprocessed,
        top_keys,
    });

    println!("Listening on http://127.0.0.1:{}", args.port);
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(app_data.clone())
            .app_data(web::PayloadConfig::new(1usize << 32))
            .service(index)
            .service(query)
            .service(info)
    })
    .workers(1)
    .bind(("127.0.0.1", args.port))?
    .run()
    .await
}

#[cfg(not(feature = "http_server"))]
fn main() {
    panic!("This binary requires the 'http_server' feature.");
}
