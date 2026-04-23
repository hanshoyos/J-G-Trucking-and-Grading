pub mod builtin;
pub mod loader;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::schema::{AceEvent, MitreMapping, Severity, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  Event condition
// ─────────────────────────────────────────────────────────────

/// A condition matcher for a single event in a multi-step rule sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCondition {
    pub source_domain:   Option<SourceDomain>,
    pub source_type:     Option<String>,
    /// MITRE technique prefix — e.g. "T1078", "T1110".
    pub mitre_technique: Option<String>,
    pub min_severity:    Option<Severity>,
    pub action:          Option<String>,
    /// Exact match or substring match for src_ip.
    pub src_ip:          Option<String>,
    /// Exact match or substring match for dst_ip.
    pub dst_ip:          Option<String>,
    pub user:            Option<String>,
    pub tag:             Option<String>,
    /// Max seconds after previous condition match (for ordered sequences).
    pub within_seconds:  Option<u64>,
}

impl EventCondition {
    /// Returns `true` if `event` satisfies every `Some` field of this condition.
    pub fn matches(&self, event: &AceEvent) -> bool {
        if let Some(ref domain) = self.source_domain {
            if &event.source_domain != domain {
                return false;
            }
        }

        if let Some(ref st) = self.source_type {
            if &event.source_type != st {
                return false;
            }
        }

        if let Some(ref technique) = self.mitre_technique {
            let found = event
                .mitre_mappings
                .iter()
                .any(|m| m.technique_id.starts_with(technique.as_str()));
            if !found {
                return false;
            }
        }

        if let Some(ref min_sev) = self.min_severity {
            if &event.severity < min_sev {
                return false;
            }
        }

        if let Some(ref action) = self.action {
            match &event.normalized.action {
                Some(a) if a == action => {}
                _ => return false,
            }
        }

        if let Some(ref src) = self.src_ip {
            match &event.normalized.src_ip {
                Some(ip) if ip.contains(src.as_str()) => {}
                _ => return false,
            }
        }

        if let Some(ref dst) = self.dst_ip {
            match &event.normalized.dst_ip {
                Some(ip) if ip.contains(dst.as_str()) => {}
                _ => return false,
            }
        }

        if let Some(ref user) = self.user {
            match &event.normalized.user {
                Some(u) if u == user => {}
                _ => return false,
            }
        }

        if let Some(ref tag) = self.tag {
            if !event.tags.iter().any(|t| t == tag) {
                return false;
            }
        }

        true
    }
}

// ─────────────────────────────────────────────────────────────
//  Rule
// ─────────────────────────────────────────────────────────────

/// A correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name:        String,
    pub version:     String,
    pub description: String,
    pub severity:    Severity,
    /// Total lookback window in seconds.
    pub window_secs: u64,
    pub conditions:  Vec<EventCondition>,
    /// Minimum number of conditions that must match (defaults to all).
    #[serde(default)]
    pub min_match:   usize,
    /// Require distinct src_ips across matching events.
    #[serde(default)]
    pub unique_ips:  bool,
    /// Require distinct users across matching events.
    #[serde(default)]
    pub unique_users: bool,
    #[serde(default)]
    pub tags:        Vec<String>,
    #[serde(default)]
    pub mitre_mappings: Vec<MitreMapping>,
    /// Generate an AceAlert when this rule fires.
    #[serde(default = "default_alert")]
    pub alert:       bool,
    /// Added to every event's threat_score when this rule fires.
    #[serde(default)]
    pub threat_score_delta: f32,
}

fn default_alert() -> bool { true }

impl Rule {
    /// Effective minimum match count: if `min_match` was left at 0 we treat it
    /// as "all conditions must match".
    pub fn effective_min_match(&self) -> usize {
        if self.min_match == 0 {
            self.conditions.len()
        } else {
            self.min_match
        }
    }
}

pub type RuleRef = Arc<Rule>;

// ─────────────────────────────────────────────────────────────
//  Rule registry
// ─────────────────────────────────────────────────────────────

pub struct RuleRegistry {
    pub rules: Vec<RuleRef>,
}

impl RuleRegistry {
    /// Load only the built-in rules.
    pub fn from_builtin() -> Self {
        let rules = builtin::BUILTIN_RULES
            .iter()
            .map(|r| Arc::new(r.clone()))
            .collect();
        Self { rules }
    }

    /// Load YAML rule files from `dir`, returning the parsed rules.
    /// Errors are logged but non-fatal; the returned `Vec` may be empty.
    pub fn load_dir(dir: &str) -> anyhow::Result<Vec<RuleRef>> {
        loader::load_yaml_rules(dir)
    }

    /// Build a registry with built-in rules plus any YAML files in `dir`.
    pub fn build(rules_dir: &str) -> Self {
        let mut rules: Vec<RuleRef> = builtin::BUILTIN_RULES
            .iter()
            .map(|r| Arc::new(r.clone()))
            .collect();

        match Self::load_dir(rules_dir) {
            Ok(extra) => {
                tracing::info!(
                    count = extra.len(),
                    dir = %rules_dir,
                    "Loaded YAML rules"
                );
                rules.extend(extra);
            }
            Err(e) => {
                tracing::warn!(dir = %rules_dir, error = %e, "Could not load YAML rules");
            }
        }

        Self { rules }
    }
}
