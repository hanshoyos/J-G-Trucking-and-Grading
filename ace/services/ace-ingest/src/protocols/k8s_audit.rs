/// Kubernetes Audit Log webhook receiver.
///
/// The Kubernetes API server can be configured to POST audit events to an
/// external webhook.  This handler implements that receiver endpoint.
///
/// K8s audit events arrive as JSON batches:
///   POST /k8s/audit
///   Content-Type: application/json
///   Authorization: Bearer <token>
///
/// Ref: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#webhook-backend
use std::net::SocketAddr;

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use axum::http::Request;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use crate::config::K8sAuditConfig;
use crate::protocols::{ProtocolHandler, RawEvent, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  Partial K8s audit event shape (enough to extract key fields)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct K8sAuditEventList {
    kind:  Option<String>,
    items: Option<Vec<serde_json::Value>>,

    // Single-event format (older K8s versions)
    #[serde(flatten)]
    single: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────
//  Axum state
// ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct K8sState {
    sender:        tokio::sync::mpsc::Sender<RawEvent>,
    tenant_id:     String,
    collector_id:  String,
    webhook_token: Option<String>,
}

// ─────────────────────────────────────────────────────────────
//  Auth middleware
// ─────────────────────────────────────────────────────────────

async fn bearer_auth_middleware(
    State(state): State<K8sState>,
    req:          Request<axum::body::Body>,
    next:         Next,
) -> Response {
    if let Some(expected) = &state.webhook_token {
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let token = auth_header.and_then(|h| h.strip_prefix("Bearer "));
        if token != Some(expected.as_str()) {
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    }
    next.run(req).await
}

// ─────────────────────────────────────────────────────────────
//  HTTP handler
// ─────────────────────────────────────────────────────────────

async fn handle_k8s_audit(
    State(state): State<K8sState>,
    headers:      HeaderMap,
    body:         Bytes,
) -> impl IntoResponse {
    if body.is_empty() {
        return StatusCode::BAD_REQUEST;
    }

    // Attempt to count events for logging; forward raw bytes as-is.
    let event_count: usize = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("items")
                .and_then(|i| i.as_array())
                .map(|a| a.len())
                .or(Some(1))
        })
        .unwrap_or(1);

    debug!("k8s_audit: received batch of ~{event_count} events ({} bytes)", body.len());

    let src_addr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let event = RawEvent::new(
        state.tenant_id.clone(),
        // K8s is IT infrastructure but we use CLOUD for container-platform events
        // since the correlation engine has specialized K8s rules.
        SourceDomain::Cloud,
        "k8s_audit",
        state.collector_id.clone(),
        body.to_vec(),
        src_addr,
    );

    if state.sender.send(event).await.is_err() {
        warn!("k8s_audit: channel closed");
        return StatusCode::SERVICE_UNAVAILABLE;
    }

    StatusCode::OK
}

// ─────────────────────────────────────────────────────────────
//  Handler
// ─────────────────────────────────────────────────────────────

pub struct K8sAuditHandler {
    cfg:          K8sAuditConfig,
    tenant_id:    String,
    collector_id: String,
}

impl K8sAuditHandler {
    pub fn new(cfg: K8sAuditConfig, tenant_id: String, collector_id: String) -> Self {
        Self { cfg, tenant_id, collector_id }
    }
}

#[async_trait]
impl ProtocolHandler for K8sAuditHandler {
    fn name(&self) -> &'static str {
        "k8s_audit"
    }

    async fn run(
        self: Box<Self>,
        sender: tokio::sync::mpsc::Sender<RawEvent>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) {
        let bind_addr = format!("{}:{}", self.cfg.bind_address, self.cfg.port);

        let state = K8sState {
            sender:        sender.clone(),
            tenant_id:     self.tenant_id.clone(),
            collector_id:  self.collector_id.clone(),
            webhook_token: self.cfg.webhook_token.clone(),
        };

        let app = Router::new()
            .route("/k8s/audit", post(handle_k8s_audit))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                bearer_auth_middleware,
            ))
            .with_state(state);

        let addr: SocketAddr = match bind_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                error!("k8s_audit: invalid bind address {bind_addr}: {e}");
                return;
            }
        };

        info!("k8s_audit webhook receiver listening on {bind_addr}");

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("k8s_audit: bind failed on {bind_addr}: {e}");
                return;
            }
        };

        tokio::select! {
            res = axum::serve(listener, app) => {
                if let Err(e) = res {
                    error!("k8s_audit server error: {e}");
                }
            }
            _ = shutdown.recv() => {
                info!("k8s_audit handler shutting down");
            }
        }
    }
}
