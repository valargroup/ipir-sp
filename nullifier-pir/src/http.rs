//! Actix HTTP surface for PIR queries.

use std::sync::Arc;
use std::time::Instant;

use actix_cors::Cors;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use serde::Serialize;

use crate::backend::PirBackend;
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
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct MetaResponse {
    snapshot: SnapshotMetadata,
    backend: crate::backend::BackendMetadata,
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
    })
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
) -> Result<()> {
    let state = web::Data::new(AppState { backend, snapshot });
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(state.clone())
            .app_data(web::PayloadConfig::new(1usize << 32))
            .service(health)
            .service(meta)
            .service(query)
    })
    .workers(1)
    .bind((bind_host, port))?
    .run()
    .await?;
    Ok(())
}
