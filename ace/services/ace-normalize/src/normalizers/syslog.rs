use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

use crate::error::{NormalizeError, NormalizeResult};
use crate::schema::{AceEvent, NormalizedFields, Outcome, Severity, SourceDomain};
use crate::normalizers::{Normalizer, RawEvent};

pub struct SyslogNormalizer;

impl Normalizer for SyslogNormalizer {
    fn handles(&self) -> &[&'static str] {
        &[
            "syslog_rfc5424",
            "syslog_rfc3164",
            "syslog_cef",
            "syslog_leef",
            "syslog_unknown",
        ]
    }

    fn normalize(&self, raw: &RawEvent) -> NormalizeResult<AceEvent> {
        let payload_str = std::str::from_utf8(&raw.payload).map_err(|e| {
            NormalizeError::Deserialize {
                source_type: raw.source_type.clone(),
                message:     e.to_string(),
            }
        })?;

        let (severity, fields, timestamp) = match raw.source_type.as_str() {
            "syslog_cef"   => parse_cef(payload_str),
            "syslog_leef"  => parse_leef(payload_str),
            "syslog_rfc5424" | "syslog_rfc3164" | _ => parse_generic_syslog(payload_str),
        };

        let raw_compressed = compress(&raw.payload);

        let mut event = AceEvent::new(
            raw.tenant_id.clone(),
            SourceDomain::It,
            raw.source_type.clone(),
            raw.collector_id.clone(),
            timestamp,
            raw_compressed,
        );
        event.severity   = severity;
        event.normalized = fields;

        // Tag syslog events.
        event.tags.push("syslog".to_string());

        Ok(event)
    }
}

// ─────────────────────────────────────────────────────────────
//  Generic syslog parser
// ─────────────────────────────────────────────────────────────

fn parse_generic_syslog(msg: &str) -> (Severity, NormalizedFields, DateTime<Utc>) {
    let mut fields   = NormalizedFields::default();
    let mut severity = Severity::Info;
    let mut ts       = Utc::now();

    // Extract PRI if present: <34>
    let rest = if msg.starts_with('<') {
        if let Some(end) = msg.find('>') {
            let pri_str = &msg[1..end];
            if let Ok(pri) = pri_str.parse::<u8>() {
                severity = syslog_severity_to_ace(pri & 0x07);
            }
            &msg[end + 1..]
        } else {
            msg
        }
    } else {
        msg
    };

    // Attempt RFC 5424 timestamp (ISO 8601): `1 2003-10-11T22:14:15.003Z …`
    let parts: Vec<&str> = rest.splitn(7, ' ').collect();
    if parts.len() >= 2 {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(parts[1]) {
            ts = parsed.with_timezone(&Utc);
        }
        // hostname / app-name
        if parts.len() >= 3 && parts[2] != "-" {
            fields.extra.insert(
                "hostname".to_string(),
                Value::String(parts[2].to_string()),
            );
        }
        if parts.len() >= 4 && parts[3] != "-" {
            fields.process = Some(parts[3].to_string());
        }
    }

    (severity, fields, ts)
}

// ─────────────────────────────────────────────────────────────
//  CEF parser  (CEF:0|Vendor|Product|Version|SignatureId|Name|Severity|ext)
// ─────────────────────────────────────────────────────────────

fn parse_cef(msg: &str) -> (Severity, NormalizedFields, DateTime<Utc>) {
    let mut fields = NormalizedFields::default();

    // Find CEF: prefix (may be preceded by a syslog header)
    let cef_start = match msg.find("CEF:") {
        Some(i) => i,
        None    => return (Severity::Info, fields, Utc::now()),
    };
    let cef_body = &msg[cef_start..];
    let parts: Vec<&str> = cef_body.splitn(8, '|').collect();

    let severity_num: u8 = parts
        .get(6)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let severity = cef_severity_to_ace(severity_num);

    // Parse extension key=value pairs.
    if let Some(ext) = parts.get(7) {
        for kv in ext.split_whitespace() {
            if let Some((k, v)) = kv.split_once('=') {
                match k {
                    "src"      => fields.src_ip   = Some(v.to_string()),
                    "dst"      => fields.dst_ip   = Some(v.to_string()),
                    "spt"      => fields.src_port = v.parse().ok(),
                    "dpt"      => fields.dst_port = v.parse().ok(),
                    "suser"    => fields.user     = Some(v.to_string()),
                    "act"      => fields.action   = Some(v.to_string()),
                    "outcome"  => fields.outcome  = parse_outcome(v),
                    "proto"    => fields.protocol = Some(v.to_string()),
                    "filePath" => fields.file_path = Some(v.to_string()),
                    _          => { fields.extra.insert(k.to_string(), Value::String(v.to_string())); }
                }
            }
        }
    }

    (severity, fields, Utc::now())
}

// ─────────────────────────────────────────────────────────────
//  LEEF parser (LEEF:1.0|Vendor|Product|Version|EventId|key=value …)
// ─────────────────────────────────────────────────────────────

fn parse_leef(msg: &str) -> (Severity, NormalizedFields, DateTime<Utc>) {
    let mut fields = NormalizedFields::default();

    let leef_start = match msg.find("LEEF:") {
        Some(i) => i,
        None    => return (Severity::Info, fields, Utc::now()),
    };
    let leef_body = &msg[leef_start..];
    let parts: Vec<&str> = leef_body.splitn(6, '|').collect();

    // The 6th part is the tab-delimited key=value extension.
    if let Some(ext) = parts.get(5) {
        for kv in ext.split('\t') {
            if let Some((k, v)) = kv.split_once('=') {
                match k {
                    "src"      => fields.src_ip   = Some(v.to_string()),
                    "dst"      => fields.dst_ip   = Some(v.to_string()),
                    "srcPort"  => fields.src_port = v.parse().ok(),
                    "dstPort"  => fields.dst_port = v.parse().ok(),
                    "usrName"  => fields.user     = Some(v.to_string()),
                    _          => { fields.extra.insert(k.to_string(), Value::String(v.to_string())); }
                }
            }
        }
    }

    (Severity::Info, fields, Utc::now())
}

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────

fn syslog_severity_to_ace(sev: u8) -> Severity {
    match sev {
        0 | 1 => Severity::Critical,
        2     => Severity::Critical,
        3     => Severity::High,
        4     => Severity::Medium,
        5 | 6 => Severity::Low,
        _     => Severity::Info,
    }
}

fn cef_severity_to_ace(sev: u8) -> Severity {
    match sev {
        0..=3  => Severity::Low,
        4..=6  => Severity::Medium,
        7..=8  => Severity::High,
        9..=10 => Severity::Critical,
        _      => Severity::Info,
    }
}

fn parse_outcome(s: &str) -> Option<Outcome> {
    match s.to_lowercase().as_str() {
        "success" | "allow" | "permitted" => Some(Outcome::Success),
        "failure" | "deny" | "blocked"    => Some(Outcome::Failure),
        _                                 => Some(Outcome::Unknown),
    }
}

fn compress(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 3).unwrap_or_else(|_| data.to_vec())
}

// ─────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rfc5424() {
        let raw = RawEvent {
            event_id:         "test-id".into(),
            tenant_id:        "t1".into(),
            timestamp_ingest: 0,
            source_domain:    "IT".into(),
            source_type:      "syslog_rfc5424".into(),
            collector_id:     "c1".into(),
            payload: b"<34>1 2003-10-11T22:14:15.003Z mymachine su 123 ID47 - test message".to_vec(),
            src_addr: None,
        };
        let norm = SyslogNormalizer;
        let event = norm.normalize(&raw).expect("normalize ok");
        assert_eq!(event.source_type, "syslog_rfc5424");
        assert_eq!(event.severity, Severity::Critical);
    }

    #[test]
    fn normalize_cef() {
        let raw = RawEvent {
            event_id:         "test-cef".into(),
            tenant_id:        "t1".into(),
            timestamp_ingest: 0,
            source_domain:    "IT".into(),
            source_type:      "syslog_cef".into(),
            collector_id:     "c1".into(),
            payload: b"<13>Oct 11 12:34:56 host CEF:0|Palo Alto Networks|PAN-OS|10|THREAT|Threat|8|src=1.2.3.4 dst=5.6.7.8 spt=12345 dpt=80 proto=TCP".to_vec(),
            src_addr: None,
        };
        let norm = SyslogNormalizer;
        let event = norm.normalize(&raw).expect("normalize ok");
        assert_eq!(event.normalized.src_ip, Some("1.2.3.4".to_string()));
        assert_eq!(event.normalized.dst_port, Some(80));
        assert_eq!(event.severity, Severity::High);
    }
}
