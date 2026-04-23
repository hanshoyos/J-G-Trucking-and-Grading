/// ACE Common Event Format (ACE-CEF) — in-process Rust representation.
///
/// This is a copy of the schema from ace-normalize, extended with AceAlert
/// for the correlation engine output.
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────
//  Enumerations
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum SourceDomain {
    #[default]
    It,
    Ot,
    Cloud,
    Hybrid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MitreFramework {
    Enterprise,
    Ics,
    Mobile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Outcome {
    Success,
    Failure,
    Attempt,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

// ─────────────────────────────────────────────────────────────
//  MITRE mapping
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub framework:    MitreFramework,
    pub technique_id: String,
    pub technique:    String,
    pub tactic:       String,
    /// 0.0 – 1.0 mapping confidence.
    pub confidence:   f32,
}

// ─────────────────────────────────────────────────────────────
//  Normalized fields
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NormalizedFields {
    // Network
    pub src_ip:   Option<String>,
    pub dst_ip:   Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,

    // Identity / process
    pub user:        Option<String>,
    pub process:     Option<String>,
    pub command:     Option<String>,
    pub file_path:   Option<String>,
    pub hash_sha256: Option<String>,

    // Action
    pub action:  Option<String>,
    pub outcome: Option<Outcome>,

    // ── OT ───────────────────────────────────────────────────
    pub plc_address:      Option<String>,
    pub function_code:    Option<u32>,
    pub register_value:   Option<String>,
    pub hmi_action:       Option<String>,
    pub setpoint_change:  Option<String>,
    pub firmware_version: Option<String>,
    pub purdue_level:     Option<u32>,

    // ── Cloud ─────────────────────────────────────────────────
    pub cloud_provider:   Option<CloudProvider>,
    pub cloud_account_id: Option<String>,
    pub cloud_region:     Option<String>,
    pub api_call:         Option<String>,
    pub iam_principal:    Option<String>,
    pub resource_arn:     Option<String>,
    pub cloud_request_id: Option<String>,

    // ── DNS / HTTP ────────────────────────────────────────────
    pub dns_query:       Option<String>,
    pub http_method:     Option<String>,
    pub http_url:        Option<String>,
    pub http_status:     Option<u32>,
    pub http_user_agent: Option<String>,

    // ── GeoIP ─────────────────────────────────────────────────
    pub src_country: Option<String>,
    pub src_asn:     Option<String>,
    pub dst_country: Option<String>,
    pub dst_asn:     Option<String>,

    // Catch-all for protocol-specific fields.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────
//  ACE event
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AceEvent {
    /// UUIDv7 — globally unique and time-sortable.
    pub event_id:  String,
    pub tenant_id: String,

    /// When the original event occurred (source clock).
    pub timestamp_source: DateTime<Utc>,
    /// When ACE received it.
    pub timestamp_ingest: DateTime<Utc>,

    pub source_domain: SourceDomain,
    pub source_type:   String,
    pub severity:      Severity,

    /// FK into ace-asset-inventory (populated by enrichment).
    pub source_asset_id: Option<String>,

    pub collector_id:      String,
    pub collector_version: String,

    pub normalized: NormalizedFields,

    /// Original bytes, zstd-compressed.
    #[serde(with = "serde_bytes")]
    pub raw_event: Vec<u8>,

    #[serde(default)]
    pub mitre_mappings: Vec<MitreMapping>,

    /// 0.0 – 100.0 composite threat score.
    pub threat_score: f32,

    #[serde(default)]
    pub tags: Vec<String>,

    /// Set by ace-correlate once the event is grouped into a session.
    pub session_id: Option<String>,
}

impl AceEvent {
    /// Create a new ACE event with a freshly generated UUIDv7.
    pub fn new(
        tenant_id:        String,
        source_domain:    SourceDomain,
        source_type:      String,
        collector_id:     String,
        timestamp_source: DateTime<Utc>,
        raw_event:        Vec<u8>,
    ) -> Self {
        Self {
            event_id:          Uuid::now_v7().to_string(),
            tenant_id,
            timestamp_source,
            timestamp_ingest:  Utc::now(),
            source_domain,
            source_type,
            severity:          Severity::Info,
            source_asset_id:   None,
            collector_id,
            collector_version: env!("CARGO_PKG_VERSION").to_string(),
            normalized:        NormalizedFields::default(),
            raw_event,
            mitre_mappings:    Vec::new(),
            threat_score:      0.0,
            tags:              Vec::new(),
            session_id:        None,
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  ACE alert
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AceAlert {
    /// UUIDv7 — globally unique and time-sortable.
    pub alert_id:      String,
    pub tenant_id:     String,
    pub session_id:    String,
    pub rule_name:     String,
    pub rule_version:  String,
    pub severity:      Severity,
    pub title:         String,
    pub description:   String,
    pub timestamp:     DateTime<Utc>,
    /// Contributing event IDs.
    pub event_ids:     Vec<String>,
    pub mitre_mappings: Vec<MitreMapping>,
    /// 0.0 – 100.0 composite threat score.
    pub threat_score:  f32,
    pub tags:          Vec<String>,
    pub source_domains: Vec<SourceDomain>,
    pub affected_assets: Vec<String>,
}

impl AceAlert {
    /// Create a new alert with a freshly generated UUIDv7.
    pub fn new(
        tenant_id:    String,
        session_id:   String,
        rule_name:    String,
        rule_version: String,
        severity:     Severity,
        title:        String,
        description:  String,
    ) -> Self {
        Self {
            alert_id:        Uuid::now_v7().to_string(),
            tenant_id,
            session_id,
            rule_name,
            rule_version,
            severity,
            title,
            description,
            timestamp:       Utc::now(),
            event_ids:       Vec::new(),
            mitre_mappings:  Vec::new(),
            threat_score:    0.0,
            tags:            Vec::new(),
            source_domains:  Vec::new(),
            affected_assets: Vec::new(),
        }
    }
}
