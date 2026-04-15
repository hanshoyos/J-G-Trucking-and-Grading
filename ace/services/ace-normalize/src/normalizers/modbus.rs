/// Modbus/TCP normalizer.
///
/// The raw payload from ace-ingest is a JSON-serialized `ModbusFrame`.
/// We extract the OT-specific fields into `NormalizedFields` and tag
/// write operations with appropriate MITRE ATT&CK for ICS mappings.
use chrono::Utc;
use serde::Deserialize;

use crate::error::{NormalizeError, NormalizeResult};
use crate::schema::{AceEvent, MitreFramework, MitreMapping, NormalizedFields, Severity, SourceDomain};
use crate::normalizers::{Normalizer, RawEvent};

// ─────────────────────────────────────────────────────────────
//  Frame shape (must match ace-ingest's ModbusFrame)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ModbusFrame {
    transaction_id: u16,
    unit_id:        u8,
    function_code:  u8,
    function_name:  String,
    is_write:       bool,
    data_hex:       String,
    data_len:       u16,
    src_addr:       String,
    dst_addr:       String,
}

// ─────────────────────────────────────────────────────────────
//  Normalizer
// ─────────────────────────────────────────────────────────────

pub struct ModbusNormalizer;

impl Normalizer for ModbusNormalizer {
    fn handles(&self) -> &[&'static str] {
        &["modbus_tcp"]
    }

    fn normalize(&self, raw: &RawEvent) -> NormalizeResult<AceEvent> {
        let frame: ModbusFrame =
            serde_json::from_slice(&raw.payload).map_err(|e| NormalizeError::Deserialize {
                source_type: "modbus_tcp".into(),
                message:     e.to_string(),
            })?;

        let mut fields       = NormalizedFields::default();
        let mut mitre        = Vec::new();
        let mut severity     = Severity::Info;

        // Network fields.
        if let Some((ip, port)) = frame.src_addr.rsplit_once(':') {
            fields.src_ip   = Some(ip.to_string());
            fields.src_port = port.parse().ok();
        }
        if let Some((ip, port)) = frame.dst_addr.rsplit_once(':') {
            fields.dst_ip   = Some(ip.to_string());
            fields.dst_port = port.parse().ok();
        }
        fields.protocol = Some("modbus-tcp".to_string());

        // OT-specific fields.
        fields.function_code = Some(frame.function_code as u32);
        fields.plc_address   = Some(format!("unit:{}", frame.unit_id));
        fields.action        = Some(frame.function_name.clone());

        // Write operations deserve higher severity and MITRE ICS mappings.
        if frame.is_write {
            severity = Severity::Medium;

            // T0836 — Modify Parameter (setpoint / register write)
            mitre.push(MitreMapping {
                framework:    MitreFramework::Ics,
                technique_id: "T0836".to_string(),
                technique:    "Modify Parameter".to_string(),
                tactic:       "impair-process-control".to_string(),
                confidence:   0.70,
            });

            // If this is a WriteSingleRegister or WriteMultipleRegisters,
            // add T0855 — Unauthorized Command Message
            if matches!(frame.function_code, 0x05 | 0x06 | 0x0F | 0x10) {
                mitre.push(MitreMapping {
                    framework:    MitreFramework::Ics,
                    technique_id: "T0855".to_string(),
                    technique:    "Unauthorized Command Message".to_string(),
                    tactic:       "impair-process-control".to_string(),
                    confidence:   0.60,
                });
                severity = Severity::High;
            }

            fields.register_value = Some(frame.data_hex.clone());
        }

        let raw_compressed = zstd::encode_all(raw.payload.as_slice(), 3)
            .unwrap_or_else(|_| raw.payload.clone());

        let mut event = AceEvent::new(
            raw.tenant_id.clone(),
            SourceDomain::Ot,
            "modbus_tcp".to_string(),
            raw.collector_id.clone(),
            Utc::now(),
            raw_compressed,
        );
        event.severity      = severity;
        event.normalized    = fields;
        event.mitre_mappings = mitre;
        event.tags.push("ot".to_string());
        event.tags.push("modbus".to_string());

        if frame.is_write {
            event.tags.push("ot-write".to_string());
        }

        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw(payload_json: &[u8]) -> RawEvent {
        RawEvent {
            event_id:         "test-id".into(),
            tenant_id:        "tenant".into(),
            timestamp_ingest: 0,
            source_domain:    "OT".into(),
            source_type:      "modbus_tcp".into(),
            collector_id:     "c1".into(),
            payload:          payload_json.to_vec(),
            src_addr:         None,
        }
    }

    #[test]
    fn write_register_gets_high_severity() {
        let frame = serde_json::json!({
            "transaction_id": 1,
            "unit_id": 1,
            "function_code": 6,
            "function_name": "WriteSingleRegister",
            "is_write": true,
            "data_hex": "00ff",
            "data_len": 6,
            "src_addr": "10.0.0.1:1024",
            "dst_addr": "10.0.0.2:502"
        });
        let raw = make_raw(frame.to_string().as_bytes());
        let norm = ModbusNormalizer;
        let event = norm.normalize(&raw).expect("normalize ok");
        assert_eq!(event.severity, Severity::High);
        assert!(!event.mitre_mappings.is_empty());
        assert!(event.tags.contains(&"ot-write".to_string()));
    }

    #[test]
    fn read_register_is_info() {
        let frame = serde_json::json!({
            "transaction_id": 2,
            "unit_id": 1,
            "function_code": 3,
            "function_name": "ReadHoldingRegisters",
            "is_write": false,
            "data_hex": "006b0003",
            "data_len": 6,
            "src_addr": "10.0.0.1:2000",
            "dst_addr": "10.0.0.2:502"
        });
        let raw = make_raw(frame.to_string().as_bytes());
        let norm = ModbusNormalizer;
        let event = norm.normalize(&raw).expect("normalize ok");
        assert_eq!(event.severity, Severity::Info);
        assert!(event.mitre_mappings.is_empty());
    }
}
