//! Actix HTTP surface for PIR queries.

use std::sync::Arc;
use std::time::Instant;

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

/// Headroom above the backend's exact query length in the request-body limit.
/// Queries have one fixed size, so this only absorbs framing differences;
/// anything larger is refused with 413 before it is buffered.
pub const QUERY_BODY_SLACK_BYTES: usize = 4096;

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

#[get("/public-params")]
async fn public_params(data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(data.backend.public_params())
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

/// Register the PIR routes, state and request-body limit on an app.
///
/// There is no CORS layer: clients are native, so a browser page on another
/// origin gets no permission to read responses from this server.
pub fn configure(state: web::Data<AppState>) -> impl Fn(&mut web::ServiceConfig) + Clone {
    let body_limit = state.backend.query_len() + QUERY_BODY_SLACK_BYTES;
    move |cfg| {
        cfg.app_data(state.clone())
            .app_data(web::PayloadConfig::new(body_limit))
            .service(health)
            .service(meta)
            .service(public_params)
            .service(query);
    }
}

pub async fn serve(
    bind_host: String,
    port: u16,
    backend: Arc<dyn PirBackend>,
    snapshot: SnapshotMetadata,
) -> Result<()> {
    let routes = configure(web::Data::new(AppState { backend, snapshot }));
    HttpServer::new(move || App::new().configure(routes.clone()))
        .workers(1)
        .bind((bind_host, port))?
        .run()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use actix_web::http::{header, Method, StatusCode};
    use actix_web::test;

    use super::*;
    use crate::backend::{BackendKind, BackendMetadata, QueryAnswer, ServerBreakdown};

    const QUERY_LEN: usize = 1000;

    /// Backend that accepts exactly `QUERY_LEN` bytes and counts calls.
    struct FixedLenBackend {
        calls: AtomicUsize,
    }

    impl PirBackend for FixedLenBackend {
        fn meta(&self) -> BackendMetadata {
            BackendMetadata {
                backend: BackendKind::LocalIpir,
                record_count: 0,
                pir_item_count: 0,
                db_rows: 0,
                db_cols: 0,
                item_size_bits: 0,
                setup_seed: 0,
                published_c1_len: 0,
            }
        }

        fn query_len(&self) -> usize {
            QUERY_LEN
        }

        fn answer_query(&self, body: &[u8]) -> Result<QueryAnswer> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            anyhow::ensure!(body.len() == QUERY_LEN, "wrong length {}", body.len());
            Ok(QueryAnswer {
                body: vec![1, 2, 3],
                breakdown: ServerBreakdown::default(),
            })
        }
    }

    fn state() -> (web::Data<AppState>, Arc<FixedLenBackend>) {
        let backend = Arc::new(FixedLenBackend {
            calls: AtomicUsize::new(0),
        });
        let state = web::Data::new(AppState {
            backend: backend.clone(),
            snapshot: SnapshotMetadata {
                source_url: None,
                path: "snapshot.bin".into(),
                bytes: 0,
                record_count: 0,
                pir_row_count: 0,
                nullifier_bytes: 32,
                nullifiers_per_item: 0,
                sha256: String::new(),
                etag: None,
            },
        });
        (state, backend)
    }

    async fn post_query(len: usize) -> (StatusCode, usize) {
        let (state, backend) = state();
        let app = test::init_service(App::new().configure(configure(state))).await;
        let req = test::TestRequest::post()
            .uri("/query")
            .set_payload(vec![0u8; len])
            .to_request();
        let status = test::call_service(&app, req).await.status();
        (status, backend.calls.load(Ordering::SeqCst))
    }

    #[actix_web::test]
    async fn exact_length_query_reaches_backend() {
        assert_eq!(post_query(QUERY_LEN).await, (StatusCode::OK, 1));
    }

    #[actix_web::test]
    async fn body_within_slack_reaches_backend_and_is_rejected_there() {
        assert_eq!(
            post_query(QUERY_LEN + QUERY_BODY_SLACK_BYTES).await,
            (StatusCode::BAD_REQUEST, 1)
        );
    }

    #[actix_web::test]
    async fn body_over_limit_is_refused_before_backend() {
        assert_eq!(
            post_query(QUERY_LEN + QUERY_BODY_SLACK_BYTES + 1).await,
            (StatusCode::PAYLOAD_TOO_LARGE, 0)
        );
    }

    #[actix_web::test]
    async fn cross_origin_requests_get_no_cors_grant() {
        let (state, _) = state();
        let app = test::init_service(App::new().configure(configure(state))).await;

        let simple = test::TestRequest::get()
            .uri("/health")
            .insert_header((header::ORIGIN, "https://evil.example"))
            .to_request();
        let resp = test::call_service(&app, simple).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());

        let preflight = test::TestRequest::default()
            .method(Method::OPTIONS)
            .uri("/query")
            .insert_header((header::ORIGIN, "https://evil.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
            .to_request();
        let resp = test::call_service(&app, preflight).await;
        assert!(!resp.status().is_success());
        assert!(resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }
}
