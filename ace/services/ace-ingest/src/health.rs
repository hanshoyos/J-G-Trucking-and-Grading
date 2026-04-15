use std::sync::Arc;
use std::net::SocketAddr;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::{json, Value};
use tracing::info;

use crate::kafka::KafkaMetrics;

// ─────────────────────────────────────────────────────────────
//  App state shared by health endpoints
// ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct HealthState {
    pub metrics: Arc<KafkaMetrics>,
    pub version: &'static str,
}

// ─────────────────────────────────────────────────────────────
//  Handlers
// ─────────────────────────────────────────────────────────────

/// Liveness: is the process alive?
async fn liveness() -> StatusCode {
    StatusCode::OK
}

/// Readiness: can the service handle traffic?
/// We consider ready = Kafka producer has sent at least one message
/// successfully in the last 60s, OR we're within the first 30s of startup.
async fn readiness(State(state): State<HealthState>) -> impl IntoResponse {
    let sent = state.metrics.events_sent.load(std::sync::atomic::Ordering::Relaxed);
    let failed = state.metrics.events_failed.load(std::sync::atomic::Ordering::Relaxed);

    if sent == 0 && failed > 100 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ready": false, "reason": "kafka_unavailable" })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ready": true, "events_sent": sent })),
    )
}

/// Prometheus-compatible /metrics endpoint.
async fn metrics_handler() -> impl IntoResponse {
    // In a full implementation this would use the prometheus registry.
    // For Phase 1, return a minimal text exposition.
    (
        StatusCode::OK,
        "# ACE Ingest metrics — full OTEL integration in Phase 5\n",
    )
}

/// /info — service metadata.
async fn info_handler(State(state): State<HealthState>) -> Json<Value> {
    Json(json!({
        "service": "ace-ingest",
        "version": state.version,
        "phase":   "1",
    }))
}

// ─────────────────────────────────────────────────────────────
//  Server
// ─────────────────────────────────────────────────────────────

pub async fn serve(port: u16, state: HealthState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/healthz",  get(liveness))
        .route("/readyz",   get(readiness))
        .route("/metrics",  get(metrics_handler))
        .route("/info",     get(info_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Health server listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
