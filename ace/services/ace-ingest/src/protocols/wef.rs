/// Windows Event Forwarding (WEF) receiver.
///
/// Implements the WS-Management / WinRM protocol subset that Windows uses
/// to push events via the WS-Eventing subscription model.  Windows sends
/// events as SOAP/XML over HTTP(S) POST to `/wef/events`.
///
/// For Phase 1 we extract the raw XML batch and forward it as a RawEvent;
/// deep XML parsing happens in ace-normalize.
use std::net::SocketAddr;

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use tracing::{debug, error, info, warn};

use crate::config::WefConfig;
use crate::protocols::{ProtocolHandler, RawEvent, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  Axum shared state
// ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct WefState {
    sender:       tokio::sync::mpsc::Sender<RawEvent>,
    tenant_id:    String,
    collector_id: String,
}

// ─────────────────────────────────────────────────────────────
//  HTTP handler
// ─────────────────────────────────────────────────────────────

async fn handle_wef_events(
    State(state):  State<WefState>,
    headers:       HeaderMap,
    body:          Bytes,
) -> impl IntoResponse {
    if body.is_empty() {
        return StatusCode::BAD_REQUEST;
    }

    debug!("wef: received {} bytes", body.len());

    let src_addr = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let event = RawEvent::new(
        state.tenant_id.clone(),
        SourceDomain::It,
        "wef_xml",
        state.collector_id.clone(),
        body.to_vec(),
        src_addr,
    );

    if state.sender.send(event).await.is_err() {
        warn!("wef: channel closed");
        return StatusCode::SERVICE_UNAVAILABLE;
    }

    // WS-Eventing expects 200 OK with an empty SOAP envelope on success.
    StatusCode::OK
}

/// WinRM subscription setup endpoint — acknowledge with 200.
async fn handle_wef_subscribe() -> StatusCode {
    StatusCode::OK
}

// ─────────────────────────────────────────────────────────────
//  Handler
// ─────────────────────────────────────────────────────────────

pub struct WefHandler {
    cfg:          WefConfig,
    tenant_id:    String,
    collector_id: String,
}

impl WefHandler {
    pub fn new(cfg: WefConfig, tenant_id: String, collector_id: String) -> Self {
        Self { cfg, tenant_id, collector_id }
    }
}

#[async_trait]
impl ProtocolHandler for WefHandler {
    fn name(&self) -> &'static str {
        "wef"
    }

    async fn run(
        self: Box<Self>,
        sender: tokio::sync::mpsc::Sender<RawEvent>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) {
        let bind_addr = format!("{}:{}", self.cfg.bind_address, self.cfg.port);

        let state = WefState {
            sender:       sender.clone(),
            tenant_id:    self.tenant_id.clone(),
            collector_id: self.collector_id.clone(),
        };

        let app = Router::new()
            .route("/wef/events",    post(handle_wef_events))
            .route("/wef/subscribe", post(handle_wef_subscribe))
            .with_state(state);

        let addr: SocketAddr = match bind_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                error!("wef: invalid bind address {bind_addr}: {e}");
                return;
            }
        };

        info!("wef receiver listening on {bind_addr}");

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("wef: bind failed on {bind_addr}: {e}");
                return;
            }
        };

        tokio::select! {
            res = axum::serve(listener, app) => {
                if let Err(e) = res {
                    error!("wef server error: {e}");
                }
            }
            _ = shutdown.recv() => {
                info!("wef handler shutting down");
            }
        }
    }
}
