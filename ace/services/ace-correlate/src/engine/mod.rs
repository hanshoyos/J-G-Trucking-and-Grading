/// Correlation engine — evaluates incoming `AceEvent`s against every loaded rule.
///
/// # Architecture
///
/// - `rules`    — `Vec<Arc<Rule>>` loaded from built-ins + optional YAML files.
/// - `windows`  — `DashMap<WindowKey, TimeWindow>` keyed by `"<rule_name>:<tenant>:<actor>"`.
///               Each window stores (timestamp, event_id) pairs within the rule's lookback period.
/// - `sessions` — `DashMap<SessionKey, ThreatSession>` keyed by `"<tenant>:<actor>"`.
///               Sessions group related events into potential kill chains.
///
/// All maps use interior mutability so the engine can be shared via `Arc` across the main
/// correlation task and the periodic GC task without requiring a coarse lock.
pub mod rule;

use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;
use tracing::{debug, info};

use crate::config::EngineConfig;
use crate::rules::{Rule, RuleRef, RuleRegistry};
use crate::schema::{AceAlert, AceEvent};
use crate::session::ThreatSession;
use crate::window::TimeWindow;

// ─────────────────────────────────────────────────────────────
//  Key helpers
// ─────────────────────────────────────────────────────────────

/// Best-effort actor identity extracted from the event.
fn actor_key(event: &AceEvent) -> String {
    if let Some(ref ip) = event.normalized.src_ip {
        return ip.clone();
    }
    if let Some(ref user) = event.normalized.user {
        return user.clone();
    }
    if let Some(ref principal) = event.normalized.iam_principal {
        return principal.clone();
    }
    "unknown".to_string()
}

fn session_key(event: &AceEvent) -> String {
    format!("{}:{}", event.tenant_id, actor_key(event))
}

fn window_key(rule_name: &str, sess_key: &str) -> String {
    format!("{rule_name}:{sess_key}")
}

// ─────────────────────────────────────────────────────────────
//  CorrelationEngine
// ─────────────────────────────────────────────────────────────

pub struct CorrelationEngine {
    rules:        Vec<RuleRef>,
    windows:      DashMap<String, TimeWindow>,
    sessions:     DashMap<String, ThreatSession>,
    /// Reused from EngineConfig — used as the session eviction limit.
    max_sessions: usize,
}

impl CorrelationEngine {
    pub fn new(registry: RuleRegistry, cfg: EngineConfig) -> Self {
        info!(
            rule_count = registry.rules.len(),
            "Building correlation engine"
        );
        Self {
            rules:        registry.rules,
            windows:      DashMap::new(),
            sessions:     DashMap::new(),
            max_sessions: cfg.max_window_events,
        }
    }

    // ── Public API ─────────────────────────────────────────────

    /// Process one normalized event.  Returns any alerts that fired.
    ///
    /// Side-effects:
    /// - `event.session_id` is populated.
    /// - `event.threat_score` may be incremented.
    pub fn process(&self, event: &mut AceEvent) -> Vec<AceAlert> {
        let sk = session_key(event);

        // ── Assign / update session ─────────────────────────
        let session_id = {
            let mut sess = self
                .sessions
                .entry(sk.clone())
                .or_insert_with(|| ThreatSession::new(event.tenant_id.clone()));
            sess.absorb_event(event);
            sess.session_id.clone()
        };
        event.session_id = Some(session_id.clone());

        // ── Evict excess sessions (simple LRU: remove oldest) ─
        if self.sessions.len() > self.max_sessions {
            // Remove an arbitrary entry — keeping overhead minimal.
            if let Some(key) = self.sessions.iter().next().map(|e| e.key().clone()) {
                self.sessions.remove(&key);
            }
        }

        // ── Evaluate every rule ─────────────────────────────
        let mut alerts = Vec::new();

        for rule_arc in &self.rules {
            let rule: &Rule = rule_arc.as_ref();
            let wk           = window_key(&rule.name, &sk);

            // Does this event satisfy *any* condition in the rule?
            let matches_any = rule.conditions.iter().any(|c| c.matches(event));
            if !matches_any {
                continue;
            }

            // Push event into the time window for this (rule, actor).
            {
                let mut w = self
                    .windows
                    .entry(wk.clone())
                    .or_insert_with(|| TimeWindow::new(rule.window_secs));
                w.push(event.timestamp_source, event.event_id.clone());
            }

            // Check whether the threshold has been reached.
            let fire = {
                let w          = self.windows.get(&wk).expect("just inserted");
                let threshold  = rule.effective_min_match();
                if threshold == 0 {
                    // Rule has no conditions → always fire (shouldn't happen in practice).
                    true
                } else if rule.conditions.len() == 1 {
                    // Single-condition rule fires immediately.
                    true
                } else {
                    // Multi-condition: fire when the window holds enough matches.
                    w.count() >= threshold
                }
            };

            if fire && rule.alert {
                // Apply threat-score delta to event.
                event.threat_score = (event.threat_score + rule.threat_score_delta).min(100.0);

                // Record rule match in session.
                if let Some(mut sess) = self.sessions.get_mut(&sk) {
                    sess.absorb_match(rule_arc);
                }

                // Collect metadata from session snapshot.
                let (sess_score, sess_domains, sess_assets) = self
                    .sessions
                    .get(&sk)
                    .map(|s| {
                        (
                            s.threat_score,
                            s.source_domains.clone(),
                            s.all_assets(),
                        )
                    })
                    .unwrap_or_default();

                let event_ids = self
                    .windows
                    .get(&wk)
                    .map(|w| w.event_ids())
                    .unwrap_or_default();

                let mitre_techniques: Vec<String> = rule
                    .mitre_mappings
                    .iter()
                    .map(|m| m.technique_id.clone())
                    .collect();

                let title = rule
                    .name
                    .replace('_', " ")
                    .split_whitespace()
                    .map(|w| {
                        let mut chars = w.chars();
                        match chars.next() {
                            None => String::new(),
                            Some(first) => {
                                first.to_uppercase().collect::<String>() + chars.as_str()
                            }
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");

                let mut alert = AceAlert::new(
                    event.tenant_id.clone(),
                    session_id.clone(),
                    rule.name.clone(),
                    rule.version.clone(),
                    rule.severity,
                    title,
                    rule.description.clone(),
                );
                alert.event_ids       = event_ids;
                alert.mitre_mappings  = rule.mitre_mappings.clone();
                alert.threat_score    = sess_score;
                alert.tags            = rule.tags.clone();
                alert.source_domains  = sess_domains;
                alert.affected_assets = sess_assets;

                debug!(
                    rule    = %rule.name,
                    session = %session_id,
                    score   = alert.threat_score,
                    "Rule fired"
                );

                alerts.push(alert);
            }
        }

        alerts
    }

    /// Evict stale entries from all time windows.  Call periodically.
    pub fn gc_windows(&self) {
        let now          = Utc::now();
        let mut to_remove: Vec<String> = Vec::new();

        for mut entry in self.windows.iter_mut() {
            entry.value_mut().evict_old(now);
            if entry.value().is_empty() {
                to_remove.push(entry.key().clone());
            }
        }

        let removed = to_remove.len();
        for k in to_remove {
            self.windows.remove(&k);
        }

        debug!(
            remaining = self.windows.len(),
            removed,
            "Window GC complete"
        );
    }
}
