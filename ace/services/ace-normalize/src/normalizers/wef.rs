/// Windows Event Forwarding (WEF) normalizer.
///
/// WEF events are XML documents that follow the Windows Event Schema.
/// We parse the key elements and map well-known EventIDs to MITRE
/// ATT&CK Enterprise techniques.
use chrono::{DateTime, Utc};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use std::collections::HashMap;

use crate::error::{NormalizeError, NormalizeResult};
use crate::schema::{AceEvent, MitreFramework, MitreMapping, NormalizedFields, Outcome, Severity, SourceDomain};
use crate::normalizers::{Normalizer, RawEvent};

pub struct WefNormalizer;

impl Normalizer for WefNormalizer {
    fn handles(&self) -> &[&'static str] {
        &["wef_xml"]
    }

    fn normalize(&self, raw: &RawEvent) -> NormalizeResult<AceEvent> {
        let xml_str = std::str::from_utf8(&raw.payload).map_err(|e| {
            NormalizeError::Deserialize {
                source_type: "wef_xml".into(),
                message:     e.to_string(),
            }
        })?;

        let parsed   = parse_windows_event(xml_str);
        let event_id = parsed.get("EventID").and_then(|v| v.parse::<u32>().ok());
        let ts       = parsed
            .get("TimeCreated")
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let mut fields   = NormalizedFields::default();
        let mut mitre    = Vec::new();
        let mut severity = Severity::Info;

        // Extract common fields from EventData.
        fields.user       = parsed.get("SubjectUserName").or_else(|| parsed.get("TargetUserName")).cloned();
        fields.src_ip     = parsed.get("IpAddress").cloned().filter(|s| s != "-");
        fields.process    = parsed.get("ProcessName").cloned();
        fields.command    = parsed.get("CommandLine").cloned();
        fields.file_path  = parsed.get("ObjectName").cloned();

        if let Some(outcome_str) = parsed.get("Keywords") {
            fields.outcome = if outcome_str.contains("Audit Success") || outcome_str.contains("0x8020000000000000") {
                Some(Outcome::Success)
            } else if outcome_str.contains("Audit Failure") || outcome_str.contains("0x8010000000000000") {
                Some(Outcome::Failure)
            } else {
                None
            };
        }

        // ── EventID → MITRE mappings ───────────────────────────
        if let Some(eid) = event_id {
            fields.action = Some(format!("WindowsEvent:{eid}"));
            fields.extra.insert(
                "event_id".to_string(),
                serde_json::Value::Number(eid.into()),
            );

            match eid {
                // Logon success
                4624 => {
                    fields.action = Some("authentication".to_string());
                    fields.outcome = Some(Outcome::Success);
                    mitre.push(mitre_map("T1078", "Valid Accounts", "defense-evasion", 0.40));
                }
                // Logon failure
                4625 => {
                    fields.action  = Some("authentication".to_string());
                    fields.outcome = Some(Outcome::Failure);
                    severity       = Severity::Medium;
                    mitre.push(mitre_map("T1110", "Brute Force", "credential-access", 0.55));
                }
                // Kerberos pre-auth failure — Kerberoasting / AS-REP roasting
                4768 | 4769 | 4771 => {
                    severity = Severity::High;
                    mitre.push(mitre_map(
                        "T1558.003",
                        "Steal or Forge Kerberos Tickets: Kerberoasting",
                        "credential-access",
                        0.70,
                    ));
                }
                // Pass-the-Hash: NTLM logon with high privilege
                4648 => {
                    mitre.push(mitre_map(
                        "T1550.002",
                        "Use Alternate Authentication Material: Pass the Hash",
                        "lateral-movement",
                        0.55,
                    ));
                }
                // DCSync (directory services replication)
                4662 => {
                    severity = Severity::Critical;
                    mitre.push(mitre_map(
                        "T1003.006",
                        "OS Credential Dumping: DCSync",
                        "credential-access",
                        0.85,
                    ));
                }
                // Process creation
                4688 => {
                    fields.action = Some("process_creation".to_string());
                    if let Some(cmd) = &fields.command {
                        if is_suspicious_command(cmd) {
                            severity = Severity::Medium;
                            mitre.push(mitre_map(
                                "T1059",
                                "Command and Scripting Interpreter",
                                "execution",
                                0.60,
                            ));
                        }
                    }
                }
                // Scheduled task creation
                4698 | 4702 => {
                    mitre.push(mitre_map(
                        "T1053.005",
                        "Scheduled Task/Job: Scheduled Task",
                        "persistence",
                        0.75,
                    ));
                    severity = Severity::Medium;
                }
                // Service installed
                7045 => {
                    mitre.push(mitre_map(
                        "T1543.003",
                        "Create or Modify System Process: Windows Service",
                        "persistence",
                        0.70,
                    ));
                    severity = Severity::Medium;
                }
                // PowerShell script block logging
                4104 => {
                    fields.action = Some("powershell_execution".to_string());
                    if let Some(script) = parsed.get("ScriptBlockText") {
                        fields.command = Some(script.chars().take(2048).collect());
                        if is_suspicious_powershell(script) {
                            severity = Severity::High;
                            mitre.push(mitre_map(
                                "T1059.001",
                                "Command and Scripting Interpreter: PowerShell",
                                "execution",
                                0.80,
                            ));
                        }
                    }
                }
                _ => {}
            }
        }

        let raw_compressed = zstd::encode_all(raw.payload.as_slice(), 3)
            .unwrap_or_else(|_| raw.payload.clone());

        let mut event = AceEvent::new(
            raw.tenant_id.clone(),
            SourceDomain::It,
            "wef_xml".to_string(),
            raw.collector_id.clone(),
            ts,
            raw_compressed,
        );
        event.severity       = severity;
        event.normalized     = fields;
        event.mitre_mappings  = mitre;
        event.tags.push("windows".to_string());
        event.tags.push("wef".to_string());

        Ok(event)
    }
}

// ─────────────────────────────────────────────────────────────
//  XML parser — minimal Windows Event Schema extraction
// ─────────────────────────────────────────────────────────────

fn parse_windows_event(xml: &str) -> HashMap<String, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut result    = HashMap::new();
    let mut buf       = Vec::new();
    let mut cur_key   = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) => {
                let name = std::str::from_utf8(e.local_name().into_inner())
                    .unwrap_or("")
                    .to_string();

                // Handle <Data Name="X"> pattern used in EventData
                let attr_name = e.attributes()
                    .filter_map(|a| a.ok())
                    .find(|a| a.key.local_name().into_inner() == b"Name")
                    .and_then(|a| std::str::from_utf8(a.value.as_ref()).ok().map(String::from));

                cur_key = attr_name.unwrap_or(name);
            }
            Ok(XmlEvent::Text(t)) => {
                if !cur_key.is_empty() {
                    let text = t
                        .unescape()
                        .map(|c| c.into_owned())
                        .unwrap_or_default();
                    if !text.is_empty() {
                        result.entry(cur_key.clone()).or_insert(text);
                    }
                }
            }
            Ok(XmlEvent::End(_)) => {
                cur_key.clear();
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    result
}

// ─────────────────────────────────────────────────────────────
//  Heuristic helpers
// ─────────────────────────────────────────────────────────────

fn is_suspicious_command(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    lower.contains("mimikatz")
        || lower.contains("invoke-expression")
        || lower.contains("iex")
        || lower.contains("downloadstring")
        || lower.contains("encodedcommand")
        || lower.contains("bypass")
        || lower.contains("-nop")
        || lower.contains("lsass")
}

fn is_suspicious_powershell(script: &str) -> bool {
    let lower = script.to_lowercase();
    lower.contains("invoke-mimikatz")
        || lower.contains("add-type -assembly")
        || lower.contains("reflectivepeinjection")
        || lower.contains("[system.reflection.assembly]")
        || lower.contains("net.webclient")
        || lower.contains("downloadfile")
}

fn mitre_map(id: &str, name: &str, tactic: &str, confidence: f32) -> MitreMapping {
    MitreMapping {
        framework:    MitreFramework::Enterprise,
        technique_id: id.to_string(),
        technique:    name.to_string(),
        tactic:       tactic.to_string(),
        confidence,
    }
}
