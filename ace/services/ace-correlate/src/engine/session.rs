use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::engine::rule::Rule;
use crate::schema::{AceEvent, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  ThreatSession
// ─────────────────────────────────────────────────────────────

/// Aggregated state for a potential attack chain.
///
/// A session groups related events from the same "actor" (src_ip / user /
/// cloud principal) across any number of correlation rules.  The engine
/// assigns a `session_id` to every contributing event and uses sessions to
/// de-duplicate alerts for the same ongoing attack.
#[derive(Debug, Clone)]
pub struct ThreatSession {
    pub session_id: String,
    pub tenant_id: String,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub event_count: u32,
    pub rule_ids: Vec<String>,
    /// Unique source domains seen across all contributing events.
    pub source_domains: Vec<SourceDomain>,
    /// Unique MITRE technique IDs seen across all contributing events.
    pub mitre_techniques: Vec<String>,
    /// Unique IPs (src/dst) seen across all contributing events.
    pub affected_ips: Vec<String>,
    /// Unique users seen across all contributing events.
    pub affected_users: Vec<String>,
    /// Unique cloud resource ARNs / hostnames.
    pub affected_assets: Vec<String>,
    /// Cumulative threat score (sum of rule deltas).
    pub threat_score: f32,
}

impl ThreatSession {
    /// Allocate a brand-new session for `tenant_id`.
    pub fn new(tenant_id: String) -> Self {
        let now = Utc::now();
        Self {
            session_id: Uuid::now_v7().to_string(),
            tenant_id,
            created_at: now,
            last_updated: now,
            event_count: 0,
            rule_ids: Vec::new(),
            source_domains: Vec::new(),
            mitre_techniques: Vec::new(),
            affected_ips: Vec::new(),
            affected_users: Vec::new(),
            affected_assets: Vec::new(),
            threat_score: 0.0,
        }
    }

    /// Merge relevant metadata from a single event into this session.
    pub fn absorb_event(&mut self, event: &AceEvent) {
        self.last_updated = Utc::now();
        self.event_count += 1;

        // Deduplicate source domain
        if !self.source_domains.contains(&event.source_domain) {
            self.source_domains.push(event.source_domain);
        }

        // MITRE techniques
        for m in &event.mitre_mappings {
            if !self.mitre_techniques.contains(&m.technique_id) {
                self.mitre_techniques.push(m.technique_id.clone());
            }
        }

        // Affected IPs
        if let Some(ref ip) = event.normalized.src_ip {
            if !self.affected_ips.contains(ip) {
                self.affected_ips.push(ip.clone());
            }
        }
        if let Some(ref ip) = event.normalized.dst_ip {
            if !self.affected_ips.contains(ip) {
                self.affected_ips.push(ip.clone());
            }
        }

        // Users
        if let Some(ref user) = event.normalized.user {
            if !self.affected_users.contains(user) {
                self.affected_users.push(user.clone());
            }
        }

        // Cloud assets
        if let Some(ref arn) = event.normalized.resource_arn {
            if !self.affected_assets.contains(arn) {
                self.affected_assets.push(arn.clone());
            }
        }

        // Threat score contribution
        self.threat_score += event.threat_score;
    }

    /// Record that a rule fired against this session.
    pub fn absorb_match(&mut self, rule: &Rule) {
        if !self.rule_ids.contains(&rule.id) {
            self.rule_ids.push(rule.id.clone());
        }
        self.threat_score += rule.threat_score_delta;
        // Cap at 100.0
        if self.threat_score > 100.0 {
            self.threat_score = 100.0;
        }

        // Merge MITRE techniques from rule definition
        for t in &rule.mitre_techniques {
            if !self.mitre_techniques.contains(t) {
                self.mitre_techniques.push(t.clone());
            }
        }

        self.last_updated = Utc::now();
    }

    /// All unique assets — IPs + users combined for alert enrichment.
    pub fn all_assets(&self) -> Vec<String> {
        let mut out = self.affected_assets.clone();
        out.extend(self.affected_ips.iter().cloned());
        out.extend(self.affected_users.iter().cloned());
        out.dedup();
        out
    }
}
