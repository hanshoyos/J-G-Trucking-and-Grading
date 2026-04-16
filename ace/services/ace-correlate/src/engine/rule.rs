/// Rule DSL types for the ACE correlation engine.
///
/// A `Rule` describes a multi-event threat pattern.  The engine evaluates
/// every incoming event against each rule and fires an alert when enough
/// matching events accumulate inside the rule's time window.
use serde::{Deserialize, Serialize};

use crate::schema::{AceEvent, Outcome, Severity, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  Condition
// ─────────────────────────────────────────────────────────────

/// A single event-level predicate.  Every `Some` field must match;
/// `None` means "accept any value for this field".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Condition {
    /// `event.source_domain` must equal this value.
    pub source_domain: Option<SourceDomain>,

    /// `event.source_type` must equal this value (case-sensitive).
    pub source_type: Option<String>,

    /// The event must have at least one MITRE mapping whose `technique_id`
    /// *starts with* this string — e.g. `"T1078"` matches `"T1078.004"`.
    pub mitre_technique: Option<String>,

    /// `event.severity` must be >= this value.
    pub severity_min: Option<Severity>,

    /// `event.normalized.action` must equal this value.
    pub action: Option<String>,

    /// `event.normalized.outcome` must equal this value.
    pub outcome: Option<Outcome>,

    /// Substring (case-insensitive) match against `event.normalized.command`.
    pub command_contains: Option<String>,

    /// Exact match against `event.normalized.api_call` (cloud events).
    pub api_call: Option<String>,

    /// Modbus function code exact match against `event.normalized.function_code`.
    pub function_code: Option<u32>,

    /// The event must have at least one tag equal to this value.
    pub has_tag: Option<String>,

    /// Max seconds after the previous condition's match timestamp.
    /// Only relevant for ordered multi-condition rules (index > 0).
    pub within_seconds: Option<u64>,
}

impl Condition {
    /// Returns `true` when every populated field matches `event`.
    pub fn matches(&self, event: &AceEvent) -> bool {
        if let Some(d) = self.source_domain {
            if event.source_domain != d {
                return false;
            }
        }

        if let Some(ref st) = self.source_type {
            if event.source_type != *st {
                return false;
            }
        }

        if let Some(ref technique) = self.mitre_technique {
            let has = event
                .mitre_mappings
                .iter()
                .any(|m| m.technique_id.starts_with(technique.as_str()));
            if !has {
                return false;
            }
        }

        if let Some(smin) = self.severity_min {
            if event.severity < smin {
                return false;
            }
        }

        if let Some(ref a) = self.action {
            if event.normalized.action.as_deref() != Some(a.as_str()) {
                return false;
            }
        }

        if let Some(o) = self.outcome {
            if event.normalized.outcome != Some(o) {
                return false;
            }
        }

        if let Some(ref substr) = self.command_contains {
            match &event.normalized.command {
                Some(cmd) if cmd.to_lowercase().contains(substr.to_lowercase().as_str()) => {}
                _ => return false,
            }
        }

        if let Some(ref api) = self.api_call {
            if event.normalized.api_call.as_deref() != Some(api.as_str()) {
                return false;
            }
        }

        if let Some(fc) = self.function_code {
            if event.normalized.function_code != Some(fc) {
                return false;
            }
        }

        if let Some(ref tag) = self.has_tag {
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

/// A correlation rule that fires when `threshold` matching events accumulate
/// within `window_secs` seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Machine-readable unique identifier (snake_case).
    pub id: String,

    /// Human-readable display name.
    pub name: String,

    pub description: String,

    pub severity: Severity,

    /// Confidence this rule produces true positives (0.0–1.0).
    pub confidence: f32,

    /// Ordered list of event-level predicates.  The engine uses a greedy
    /// sequential match: each condition must be satisfied by an event that
    /// occurs *after* the event that satisfied the previous condition.
    pub conditions: Vec<Condition>,

    /// Lookback window in seconds.  Events older than `now - window_secs` are
    /// evicted before threshold evaluation.
    pub window_secs: u64,

    /// Minimum number of conditions that must be satisfied for the rule to fire.
    /// `0` means "all conditions must match".
    pub threshold: usize,

    /// MITRE ATT&CK technique IDs associated with this rule (for alert enrichment).
    pub mitre_techniques: Vec<String>,

    /// Optional kill-chain phase label (e.g. "lateral-movement").
    pub kill_chain_phase: Option<String>,

    pub tags: Vec<String>,

    /// Threat-score delta added to the trigger event when the rule fires.
    pub threat_score_delta: f32,
}

impl Rule {
    /// Effective minimum match count: `0` → all conditions must match.
    pub fn effective_threshold(&self) -> usize {
        if self.threshold == 0 {
            self.conditions.len()
        } else {
            self.threshold
        }
    }
}
