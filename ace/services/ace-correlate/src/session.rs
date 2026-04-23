/// ThreatSession — aggregated state for a potential attack chain.
///
/// Groups related events from the same "actor" (src_ip / user / cloud principal)
/// and accumulates threat score, MITRE techniques, and affected assets.
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::rules::RuleRef;
use crate::schema::{AceEvent, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  ThreatSession
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreatSession {
    pub session_id:      String,
    pub tenant_id:       String,
    pub created_at:      DateTime<Utc>,
    pub last_updated:    DateTime<Utc>,
    pub event_count:     u32,
    /// Rule names that have fired against this session.
    pub rule_ids:        Vec<String>,
    /// Unique source domains seen across contributing events.
    pub source_domains:  Vec<SourceDomain>,
    /// Unique MITRE technique IDs seen.
    pub mitre_techniques: Vec<String>,
    /// Unique src/dst IPs.
    pub affected_ips:    Vec<String>,
    /// Unique users.
    pub affected_users:  Vec<String>,
    /// Unique cloud resource ARNs / hostnames.
    pub affected_assets: Vec<String>,
    /// Cumulative threat score (capped at 100.0).
    pub threat_score:    f32,
}

impl ThreatSession {
    pub fn new(tenant_id: String) -> Self {
        let now = Utc::now();
        Self {
            session_id:       Uuid::now_v7().to_string(),
            tenant_id,
            created_at:       now,
            last_updated:     now,
            event_count:      0,
            rule_ids:         Vec::new(),
            source_domains:   Vec::new(),
            mitre_techniques: Vec::new(),
            affected_ips:     Vec::new(),
            affected_users:   Vec::new(),
            affected_assets:  Vec::new(),
            threat_score:     0.0,
        }
    }

    /// Merge metadata from a newly seen event into the session.
    pub fn absorb_event(&mut self, event: &AceEvent) {
        self.last_updated = Utc::now();
        self.event_count += 1;

        if !self.source_domains.contains(&event.source_domain) {
            self.source_domains.push(event.source_domain);
        }

        for m in &event.mitre_mappings {
            if !self.mitre_techniques.contains(&m.technique_id) {
                self.mitre_techniques.push(m.technique_id.clone());
            }
        }

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
        if let Some(ref user) = event.normalized.user {
            if !self.affected_users.contains(user) {
                self.affected_users.push(user.clone());
            }
        }
        if let Some(ref arn) = event.normalized.resource_arn {
            if !self.affected_assets.contains(arn) {
                self.affected_assets.push(arn.clone());
            }
        }

        // Absorb the event's existing threat score contribution.
        self.threat_score = (self.threat_score + event.threat_score * 0.1).min(100.0);
    }

    /// Record that a correlation rule fired against this session.
    pub fn absorb_match(&mut self, rule: &RuleRef) {
        if !self.rule_ids.contains(&rule.name) {
            self.rule_ids.push(rule.name.clone());
        }
        self.threat_score = (self.threat_score + rule.threat_score_delta).min(100.0);

        // Merge MITRE techniques from the rule's mapping list.
        for m in &rule.mitre_mappings {
            if !self.mitre_techniques.contains(&m.technique_id) {
                self.mitre_techniques.push(m.technique_id.clone());
            }
        }

        self.last_updated = Utc::now();
    }

    /// Combined affected-entity list used to populate alert.affected_assets.
    pub fn all_assets(&self) -> Vec<String> {
        let mut out = self.affected_assets.clone();
        out.extend(self.affected_ips.iter().cloned());
        out.extend(self.affected_users.iter().cloned());
        out.dedup();
        out
    }
}
