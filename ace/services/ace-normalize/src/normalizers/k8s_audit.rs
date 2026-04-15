/// Kubernetes Audit Log normalizer.
///
/// K8s audit events are JSON objects following the `audit.k8s.io/v1` API.
/// We extract resource, verb, user, and outcome, then map sensitive
/// operations to MITRE ATT&CK Enterprise (Cloud) techniques.
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::error::{NormalizeError, NormalizeResult};
use crate::schema::{AceEvent, CloudProvider, MitreFramework, MitreMapping, NormalizedFields, Outcome, Severity, SourceDomain};
use crate::normalizers::{Normalizer, RawEvent};

// ─────────────────────────────────────────────────────────────
//  K8s audit event shape (subset)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct K8sAuditEvent {
    request_uri:          Option<String>,
    verb:                 Option<String>,
    source_ips:           Option<Vec<String>>,
    user_agent:           Option<String>,
    response_status:      Option<ResponseStatus>,
    request_received_timestamp: Option<String>,
    #[serde(rename = "objectRef")]
    object_ref:           Option<ObjectRef>,
    user:                 Option<K8sUser>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResponseStatus {
    code: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectRef {
    resource:    Option<String>,
    namespace:   Option<String>,
    name:        Option<String>,
    api_group:   Option<String>,
    api_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct K8sUser {
    username: Option<String>,
    groups:   Option<Vec<String>>,
}

// Wrapper for batch (EventList) or single event
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct K8sAuditEventList {
    items: Option<Vec<K8sAuditEvent>>,
    #[serde(flatten)]
    single: Option<K8sAuditEvent>,
}

pub struct K8sAuditNormalizer;

impl Normalizer for K8sAuditNormalizer {
    fn handles(&self) -> &[&'static str] {
        &["k8s_audit"]
    }

    fn normalize(&self, raw: &RawEvent) -> NormalizeResult<AceEvent> {
        // Try to parse as a list first, fall back to single event.
        let events: Vec<K8sAuditEvent> =
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw.payload) {
                if v.get("items").is_some() {
                    serde_json::from_value::<Vec<K8sAuditEvent>>(
                        v.get("items").unwrap().clone(),
                    )
                    .unwrap_or_default()
                } else {
                    // Single event; wrap it.
                    serde_json::from_value::<K8sAuditEvent>(v)
                        .map(|e| vec![e])
                        .unwrap_or_default()
                }
            } else {
                return Err(NormalizeError::Deserialize {
                    source_type: "k8s_audit".into(),
                    message:     "invalid JSON".into(),
                });
            };

        // If we got a batch we emit the FIRST event as the normalized event
        // (the batch will be split by the pipeline in Phase 2; for now
        // we emit one AceEvent per RawEvent batch that represents the batch).
        let event = match events.into_iter().next() {
            Some(e) => e,
            None    => {
                return Err(NormalizeError::Deserialize {
                    source_type: "k8s_audit".into(),
                    message:     "empty event list".into(),
                });
            }
        };

        let ts = event
            .request_received_timestamp
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let mut fields   = NormalizedFields::default();
        let mut mitre    = Vec::new();
        let mut severity = Severity::Info;

        // User / identity
        if let Some(user) = &event.user {
            fields.user          = user.username.clone();
            fields.iam_principal = user.username.clone();
        }

        // Network
        if let Some(ips) = &event.source_ips {
            fields.src_ip = ips.first().cloned();
        }
        fields.http_user_agent = event.user_agent.clone();
        fields.cloud_provider  = Some(CloudProvider::Aws); // overridden by actual cluster context

        // Action
        let verb     = event.verb.clone().unwrap_or_default();
        let resource = event
            .object_ref
            .as_ref()
            .and_then(|o| o.resource.clone())
            .unwrap_or_default();
        let api_call = format!("{verb}/{resource}");

        fields.action       = Some(format!("k8s:{verb}:{resource}"));
        fields.api_call     = Some(api_call.clone());
        fields.resource_arn = event.object_ref.as_ref().and_then(|o| {
            let ns = o.namespace.as_deref().unwrap_or("cluster");
            let name = o.name.as_deref().unwrap_or("-");
            Some(format!("k8s/{ns}/{resource}/{name}"))
        });

        // Outcome from HTTP status code
        let status_code = event
            .response_status
            .as_ref()
            .and_then(|s| s.code);
        fields.outcome = status_code.map(|c| {
            if c >= 200 && c < 300 {
                Outcome::Success
            } else if c == 401 || c == 403 {
                Outcome::Failure
            } else {
                Outcome::Unknown
            }
        });

        // ── MITRE mappings ─────────────────────────────────────

        // Privileged pod creation → T1610 Deploy Container
        if verb == "create" && resource == "pods" {
            mitre.push(MitreMapping {
                framework:    MitreFramework::Enterprise,
                technique_id: "T1610".to_string(),
                technique:    "Deploy Container".to_string(),
                tactic:       "defense-evasion".to_string(),
                confidence:   0.50,
            });
        }

        // RBAC manipulation → T1098 Account Manipulation
        if matches!(verb.as_str(), "create" | "update" | "patch")
            && matches!(
                resource.as_str(),
                "clusterrolebindings" | "rolebindings" | "clusterroles" | "roles"
            )
        {
            mitre.push(MitreMapping {
                framework:    MitreFramework::Enterprise,
                technique_id: "T1098".to_string(),
                technique:    "Account Manipulation".to_string(),
                tactic:       "persistence".to_string(),
                confidence:   0.75,
            });
            severity = Severity::High;
        }

        // Secret access → T1552.007 Container API
        if resource == "secrets" && matches!(verb.as_str(), "get" | "list" | "watch") {
            mitre.push(MitreMapping {
                framework:    MitreFramework::Enterprise,
                technique_id: "T1552.007".to_string(),
                technique:    "Unsecured Credentials: Container API".to_string(),
                tactic:       "credential-access".to_string(),
                confidence:   0.65,
            });
            severity = Severity::Medium;
        }

        // Unauthorized (403) on sensitive resources
        if fields.outcome == Some(Outcome::Failure) && !resource.is_empty() {
            mitre.push(MitreMapping {
                framework:    MitreFramework::Enterprise,
                technique_id: "T1078".to_string(),
                technique:    "Valid Accounts".to_string(),
                tactic:       "defense-evasion".to_string(),
                confidence:   0.35,
            });
        }

        let raw_compressed = zstd::encode_all(raw.payload.as_slice(), 3)
            .unwrap_or_else(|_| raw.payload.clone());

        let mut ace_event = AceEvent::new(
            raw.tenant_id.clone(),
            SourceDomain::Cloud,
            "k8s_audit".to_string(),
            raw.collector_id.clone(),
            ts,
            raw_compressed,
        );
        ace_event.severity       = severity;
        ace_event.normalized     = fields;
        ace_event.mitre_mappings  = mitre;
        ace_event.tags.push("kubernetes".to_string());
        ace_event.tags.push("k8s_audit".to_string());

        Ok(ace_event)
    }
}
