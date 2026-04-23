/// AWS CloudTrail event normalizer.
///
/// CloudTrail events are JSON objects.  We extract the key fields into
/// `NormalizedFields` and emit MITRE ATT&CK Enterprise mappings for
/// high-signal API calls (credential access, privilege escalation, etc.).
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{NormalizeError, NormalizeResult};
use crate::schema::{
    AceEvent, CloudProvider, MitreFramework, MitreMapping, NormalizedFields, Outcome, Severity,
    SourceDomain,
};
use crate::normalizers::{Normalizer, RawEvent};

// ─────────────────────────────────────────────────────────────
//  CloudTrail record shape
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloudTrailRecord {
    event_time:       Option<String>,
    event_source:     Option<String>,
    event_name:       Option<String>,
    aws_region:       Option<String>,
    source_ip_address: Option<String>,
    user_agent:       Option<String>,
    error_code:       Option<String>,
    request_id:       Option<String>,

    user_identity: Option<UserIdentity>,
    request_parameters: Option<Value>,
    response_elements:  Option<Value>,
    resources:          Option<Vec<Resource>>,

    recipient_account_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserIdentity {
    #[serde(rename = "type")]
    identity_type: Option<String>,
    arn:           Option<String>,
    user_name:     Option<String>,
    account_id:    Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Resource {
    arn:           Option<String>,
    account_id:    Option<String>,
    r#type:        Option<String>,
}

// ─────────────────────────────────────────────────────────────
//  Normalizer
// ─────────────────────────────────────────────────────────────

pub struct CloudTrailNormalizer;

impl Normalizer for CloudTrailNormalizer {
    fn handles(&self) -> &[&'static str] {
        &["cloudtrail"]
    }

    fn normalize(&self, raw: &RawEvent) -> NormalizeResult<AceEvent> {
        let record: CloudTrailRecord =
            serde_json::from_slice(&raw.payload).map_err(|e| NormalizeError::Deserialize {
                source_type: "cloudtrail".into(),
                message:     e.to_string(),
            })?;

        let mut fields  = NormalizedFields::default();
        let mut mitre   = Vec::new();
        let mut severity = Severity::Info;

        // Timestamps
        let ts = record
            .event_time
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        // Identity
        if let Some(ui) = &record.user_identity {
            fields.iam_principal  = ui.arn.clone();
            fields.user           = ui.user_name.clone().or_else(|| ui.arn.clone());
            fields.cloud_account_id = ui.account_id.clone()
                .or_else(|| record.recipient_account_id.clone());
        }

        // API call semantics
        let event_name = record.event_name.clone().unwrap_or_default();
        let api_call   = format!(
            "{}:{}",
            record.event_source.as_deref().unwrap_or("unknown"),
            event_name
        );
        fields.api_call       = Some(api_call.clone());
        fields.cloud_provider = Some(CloudProvider::Aws);
        fields.cloud_region   = record.aws_region.clone();
        fields.cloud_request_id = record.request_id.clone();
        fields.src_ip         = record.source_ip_address.clone();
        fields.http_user_agent = record.user_agent.clone();
        fields.action         = Some(event_name.clone());

        // Outcome from errorCode
        fields.outcome = if record.error_code.is_some() {
            Some(Outcome::Failure)
        } else {
            Some(Outcome::Success)
        };

        // First resource ARN
        if let Some(resources) = &record.resources {
            if let Some(r) = resources.first() {
                fields.resource_arn = r.arn.clone();
            }
        }

        // ── MITRE ATT&CK Enterprise mappings ──────────────────
        // Privilege escalation via IAM policy manipulation
        if matches!(
            event_name.as_str(),
            "CreatePolicy" | "AttachUserPolicy" | "AttachRolePolicy"
            | "PutUserPolicy" | "PutRolePolicy" | "AddUserToGroup"
        ) {
            mitre.push(MitreMapping {
                framework:    MitreFramework::Enterprise,
                technique_id: "T1098.001".to_string(),
                technique:    "Account Manipulation: Additional Cloud Credentials".to_string(),
                tactic:       "persistence".to_string(),
                confidence:   0.80,
            });
            severity = Severity::High;
        }

        // T1078.004 — Valid Accounts: Cloud Accounts
        if event_name.as_str() == "ConsoleLogin" && fields.outcome == Some(Outcome::Success) {
            mitre.push(MitreMapping {
                framework:    MitreFramework::Enterprise,
                technique_id: "T1078.004".to_string(),
                technique:    "Valid Accounts: Cloud Accounts".to_string(),
                tactic:       "defense-evasion".to_string(),
                confidence:   0.50,
            });
        }

        // T1530 — Data from Cloud Storage (S3 GetObject)
        if event_name.as_str() == "GetObject"
            && record.event_source.as_deref() == Some("s3.amazonaws.com")
        {
            mitre.push(MitreMapping {
                framework:    MitreFramework::Enterprise,
                technique_id: "T1530".to_string(),
                technique:    "Data from Cloud Storage".to_string(),
                tactic:       "collection".to_string(),
                confidence:   0.40,
            });
        }

        // T1548.005 — Abuse Elevation Control: Temporary Elevated Cloud Access
        if matches!(event_name.as_str(), "AssumeRole" | "AssumeRoleWithWebIdentity") {
            mitre.push(MitreMapping {
                framework:    MitreFramework::Enterprise,
                technique_id: "T1548.005".to_string(),
                technique:    "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access".to_string(),
                tactic:       "privilege-escalation".to_string(),
                confidence:   0.55,
            });
        }

        // Failed console logins → brute force
        if event_name.as_str() == "ConsoleLogin" && fields.outcome == Some(Outcome::Failure) {
            mitre.push(MitreMapping {
                framework:    MitreFramework::Enterprise,
                technique_id: "T1110".to_string(),
                technique:    "Brute Force".to_string(),
                tactic:       "credential-access".to_string(),
                confidence:   0.45,
            });
        }

        let raw_compressed = zstd::encode_all(raw.payload.as_slice(), 3)
            .unwrap_or_else(|_| raw.payload.clone());

        let mut event = AceEvent::new(
            raw.tenant_id.clone(),
            SourceDomain::Cloud,
            "cloudtrail".to_string(),
            raw.collector_id.clone(),
            ts,
            raw_compressed,
        );
        event.severity       = severity;
        event.normalized     = fields;
        event.mitre_mappings  = mitre;
        event.tags.push("cloud".to_string());
        event.tags.push("aws".to_string());
        event.tags.push("cloudtrail".to_string());

        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw(json: serde_json::Value) -> RawEvent {
        RawEvent {
            event_id:         "id".into(),
            tenant_id:        "t1".into(),
            timestamp_ingest: 0,
            source_domain:    "CLOUD".into(),
            source_type:      "cloudtrail".into(),
            collector_id:     "c1".into(),
            payload:          serde_json::to_vec(&json).unwrap(),
            src_addr:         None,
        }
    }

    #[test]
    fn console_login_success_maps_t1078() {
        let record = serde_json::json!({
            "eventTime":   "2024-01-01T12:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName":   "ConsoleLogin",
            "awsRegion":   "us-east-1",
            "userIdentity": { "type": "IAMUser", "arn": "arn:aws:iam::123:user/attacker" },
        });
        let raw   = make_raw(record);
        let norm  = CloudTrailNormalizer;
        let event = norm.normalize(&raw).expect("normalize ok");
        let ids: Vec<&str> = event
            .mitre_mappings
            .iter()
            .map(|m| m.technique_id.as_str())
            .collect();
        assert!(ids.contains(&"T1078.004"), "should map T1078.004");
    }

    #[test]
    fn iam_policy_attach_is_high() {
        let record = serde_json::json!({
            "eventTime":   "2024-01-01T12:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName":   "AttachUserPolicy",
            "awsRegion":   "us-east-1",
            "userIdentity": { "type": "IAMUser", "arn": "arn:aws:iam::123:user/alice" },
        });
        let raw   = make_raw(record);
        let norm  = CloudTrailNormalizer;
        let event = norm.normalize(&raw).expect("normalize ok");
        assert_eq!(event.severity, Severity::High);
    }
}
