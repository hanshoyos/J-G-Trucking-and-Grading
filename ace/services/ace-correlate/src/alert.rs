/// `CorrelatedAlert` — the output type produced by the correlation engine
/// when a rule fires.  One alert is emitted per rule-session pair, published
/// to `ace.alerts` and consumed by `ace-respond`.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::{Severity, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  CorrelatedAlert
// ─────────────────────────────────────────────────────────────

/// A fully enriched alert emitted when a correlation rule fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedAlert {
    /// UUIDv7 — globally unique and time-sortable.
    pub alert_id: String,

    /// The tenant this alert belongs to.
    pub tenant_id: String,

    /// The session that grouped the contributing events.
    pub session_id: String,

    /// Machine-readable rule identifier (snake_case).
    pub rule_id: String,

    /// Human-readable rule display name.
    pub rule_name: String,

    /// Alert severity derived from the rule definition.
    pub severity: Severity,

    /// Confidence that this is a true positive (0.0–1.0).
    pub confidence: f32,

    /// Composite threat score at time of firing (0.0–100.0).
    pub threat_score: f32,

    /// Timestamp of the earliest contributing event.
    pub first_seen: DateTime<Utc>,

    /// Timestamp of the latest contributing event (= trigger event).
    pub last_seen: DateTime<Utc>,

    /// Total number of events that contributed to this alert.
    pub event_count: u32,

    /// IDs of every contributing event (for pivot / investigation).
    pub contributing_event_ids: Vec<String>,

    /// Unique source domains observed across contributing events.
    pub source_domains: Vec<SourceDomain>,

    /// MITRE ATT&CK technique IDs from rule definition and contributing events.
    pub mitre_techniques: Vec<String>,

    /// Kill-chain phase label (e.g. "lateral-movement"), if the rule provides one.
    pub kill_chain_phase: Option<String>,

    /// Human-readable description of what the rule detected.
    pub description: String,

    /// IPs, usernames, resource ARNs and hostnames involved.
    pub affected_assets: Vec<String>,

    /// Tags from the rule and contributing events.
    pub tags: Vec<String>,
}

impl CorrelatedAlert {
    /// Allocate a new alert with a freshly generated UUIDv7.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id:              String,
        session_id:             String,
        rule_id:                String,
        rule_name:              String,
        severity:               Severity,
        confidence:             f32,
        threat_score:           f32,
        first_seen:             DateTime<Utc>,
        last_seen:              DateTime<Utc>,
        event_count:            u32,
        contributing_event_ids: Vec<String>,
        source_domains:         Vec<SourceDomain>,
        mitre_techniques:       Vec<String>,
        kill_chain_phase:       Option<String>,
        description:            String,
        affected_assets:        Vec<String>,
        tags:                   Vec<String>,
    ) -> Self {
        Self {
            alert_id: Uuid::now_v7().to_string(),
            tenant_id,
            session_id,
            rule_id,
            rule_name,
            severity,
            confidence,
            threat_score,
            first_seen,
            last_seen,
            event_count,
            contributing_event_ids,
            source_domains,
            mitre_techniques,
            kill_chain_phase,
            description,
            affected_assets,
            tags,
        }
    }
}
