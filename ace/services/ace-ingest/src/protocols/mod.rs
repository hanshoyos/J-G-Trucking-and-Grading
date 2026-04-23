pub mod cloudtrail;
pub mod k8s_audit;
pub mod modbus;
pub mod syslog;
pub mod wef;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────
//  Raw event — the minimal, source-agnostic envelope produced
//  by every protocol handler before it hits Kafka.
// ─────────────────────────────────────────────────────────────

/// Broad security domain of the event source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SourceDomain {
    It,
    Ot,
    Cloud,
    Hybrid,
}

/// Minimal envelope from any ingest handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    /// UUIDv7 — globally unique and time-sortable.
    pub event_id: String,

    pub tenant_id: String,

    /// Unix nanoseconds at which ACE received this event.
    pub timestamp_ingest: i64,

    pub source_domain: SourceDomain,

    /// Fine-grained source type: "syslog_rfc5424", "modbus_tcp", etc.
    pub source_type: String,

    pub collector_id: String,

    /// The original bytes, unmodified.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,

    /// Originating network endpoint (IP:port) when available.
    pub src_addr: Option<String>,
}

impl RawEvent {
    pub fn new(
        tenant_id:     String,
        source_domain: SourceDomain,
        source_type:   &'static str,
        collector_id:  String,
        payload:       Vec<u8>,
        src_addr:      Option<String>,
    ) -> Self {
        Self {
            event_id:         Uuid::now_v7().to_string(),
            tenant_id,
            timestamp_ingest: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            source_domain,
            source_type:      source_type.to_string(),
            collector_id,
            payload,
            src_addr,
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  Protocol handler trait
// ─────────────────────────────────────────────────────────────

#[async_trait]
pub trait ProtocolHandler: Send + Sync + 'static {
    /// Human-readable name used in logs and metrics.
    fn name(&self) -> &'static str;

    /// Long-running loop. Implementations should select on `shutdown`
    /// to perform a clean exit.
    async fn run(
        self: Box<Self>,
        sender: tokio::sync::mpsc::Sender<RawEvent>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    );
}
