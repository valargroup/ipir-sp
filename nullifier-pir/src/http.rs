//! Actix HTTP surface for PIR queries.

use std::sync::Arc;
use std::time::Instant;

use actix_cors::Cors;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use serde::Serialize;

use crate::backend::PirBackend;
use crate::manifest::ManifestArtifacts;
use crate::snapshot::SnapshotMetadata;

pub const SERVER_TIME_HEADER: &str = "x-nullifier-pir-server-time-us";
pub const SERVER_SETUP_DESERIALIZE_TIME_HEADER: &str =
    "x-nullifier-pir-server-setup-deserialize-us";
pub const SERVER_PACK_PREPROCESS_TIME_HEADER: &str = "x-nullifier-pir-server-pack-preprocess-us";
pub const SERVER_ONLINE_DESERIALIZE_TIME_HEADER: &str =
    "x-nullifier-pir-server-online-deserialize-us";
pub const SERVER_MATRIX_VECTOR_TIME_HEADER: &str = "x-nullifier-pir-server-matrix-vector-us";
pub const SERVER_PACKING_TIME_HEADER: &str = "x-nullifier-pir-server-packing-us";
pub const SERVER_SERIALIZATION_TIME_HEADER: &str = "x-nullifier-pir-server-serialization-us";

#[derive(Clone)]
pub struct AppState {
    pub backend: Arc<dyn PirBackend>,
    pub snapshot: SnapshotMetadata,
    /// Snapshot manifest and row digests; `None` when the backend has none.
    pub manifest: Option<Arc<ManifestArtifacts>>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct MetaResponse {
    snapshot: SnapshotMetadata,
    backend: crate::backend::BackendMetadata,
    /// SHA-256 of the `GET /manifest` bytes, so a client can tell that a
    /// cached manifest and digest table are stale. Absent without a manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_sha256: Option<String>,
}

#[get("/health")]
async fn health() -> impl Responder {
    web::Json(HealthResponse { ok: true })
}

#[get("/meta")]
async fn meta(data: web::Data<AppState>) -> impl Responder {
    web::Json(MetaResponse {
        snapshot: data.snapshot.clone(),
        backend: data.backend.meta(),
        manifest_sha256: data.manifest.as_ref().map(|m| m.manifest_sha256()),
    })
}

#[get("/public-params")]
async fn public_params(data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(data.backend.public_params())
}

/// The exact signed manifest bytes (base64) and their signature (hex).
#[get("/manifest")]
async fn snapshot_manifest(data: web::Data<AppState>) -> HttpResponse {
    match &data.manifest {
        Some(manifest) => HttpResponse::Ok().json(manifest.envelope()),
        None => HttpResponse::NotFound().body("no snapshot manifest for this backend"),
    }
}

/// One 32-byte SHA-256 per PIR row, row-major. Clients download the whole
/// table, so fetching it reveals nothing about which row they will query.
#[get("/row-digests")]
async fn row_digest_table(data: web::Data<AppState>) -> HttpResponse {
    match &data.manifest {
        Some(manifest) => HttpResponse::Ok()
            .content_type("application/octet-stream")
            .body(manifest.row_digests.clone()),
        None => HttpResponse::NotFound().body("no row digests for this backend"),
    }
}

#[post("/query")]
async fn query(body: web::Bytes, data: web::Data<AppState>) -> actix_web::Result<HttpResponse> {
    let started = Instant::now();
    let answer = data
        .backend
        .answer_query(&body)
        .map_err(actix_web::error::ErrorBadRequest)?;
    let server_time_us = started.elapsed().as_micros().to_string();
    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header((SERVER_TIME_HEADER, server_time_us))
        .insert_header((
            SERVER_SETUP_DESERIALIZE_TIME_HEADER,
            answer.breakdown.setup_deserialize_us.to_string(),
        ))
        .insert_header((
            SERVER_PACK_PREPROCESS_TIME_HEADER,
            answer.breakdown.pack_preprocess_us.to_string(),
        ))
        .insert_header((
            SERVER_ONLINE_DESERIALIZE_TIME_HEADER,
            answer.breakdown.online_deserialize_us.to_string(),
        ))
        .insert_header((
            SERVER_MATRIX_VECTOR_TIME_HEADER,
            answer.breakdown.matrix_vector_us.to_string(),
        ))
        .insert_header((
            SERVER_PACKING_TIME_HEADER,
            answer.breakdown.packing_us.to_string(),
        ))
        .insert_header((
            SERVER_SERIALIZATION_TIME_HEADER,
            answer.breakdown.serialization_us.to_string(),
        ))
        .body(answer.body))
}

pub async fn serve(
    bind_host: String,
    port: u16,
    backend: Arc<dyn PirBackend>,
    snapshot: SnapshotMetadata,
    manifest: Option<ManifestArtifacts>,
) -> Result<()> {
    let state = web::Data::new(AppState {
        backend,
        snapshot,
        manifest: manifest.map(Arc::new),
    });
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(state.clone())
            .app_data(web::PayloadConfig::new(1usize << 32))
            .service(health)
            .service(meta)
            .service(public_params)
            .service(snapshot_manifest)
            .service(row_digest_table)
            .service(query)
    })
    .workers(1)
    .bind((bind_host, port))?
    .run()
    .await?;
    Ok(())
}
