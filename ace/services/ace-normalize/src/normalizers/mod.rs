pub mod cloudtrail;
pub mod k8s_audit;
pub mod modbus;
pub mod syslog;
pub mod wef;

use crate::error::NormalizeResult;
use crate::schema::AceEvent;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────
//  Raw event — mirrors the struct produced by ace-ingest
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub event_id:         String,
    pub tenant_id:        String,
    pub timestamp_ingest: i64,
    pub source_domain:    String,
    pub source_type:      String,
    pub collector_id:     String,
    #[serde(with = "serde_bytes")]
    pub payload:          Vec<u8>,
    pub src_addr:         Option<String>,
}

// ─────────────────────────────────────────────────────────────
//  Normalizer trait
// ─────────────────────────────────────────────────────────────

pub trait Normalizer: Send + Sync + 'static {
    /// Source types this normalizer handles (e.g. `["syslog_rfc5424", "syslog_rfc3164"]`).
    fn handles(&self) -> &[&'static str];

    /// Normalize a raw event into an `AceEvent`.
    fn normalize(&self, raw: &RawEvent) -> NormalizeResult<AceEvent>;
}

// ─────────────────────────────────────────────────────────────
//  Registry
// ─────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::sync::Arc;

pub struct NormalizerRegistry {
    map: HashMap<String, Arc<dyn Normalizer>>,
}

impl NormalizerRegistry {
    pub fn build() -> Self {
        let mut map: HashMap<String, Arc<dyn Normalizer>> = HashMap::new();

        let normalizers: Vec<Arc<dyn Normalizer>> = vec![
            Arc::new(syslog::SyslogNormalizer),
            Arc::new(modbus::ModbusNormalizer),
            Arc::new(cloudtrail::CloudTrailNormalizer),
            Arc::new(wef::WefNormalizer),
            Arc::new(k8s_audit::K8sAuditNormalizer),
        ];

        for n in normalizers {
            for &source_type in n.handles() {
                map.insert(source_type.to_string(), n.clone());
            }
        }

        Self { map }
    }

    /// Look up the normalizer for a given source_type.
    pub fn get(&self, source_type: &str) -> Option<&Arc<dyn Normalizer>> {
        self.map.get(source_type)
    }
}
