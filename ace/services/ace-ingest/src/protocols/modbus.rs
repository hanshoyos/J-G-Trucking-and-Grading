/// Modbus/TCP passive tap handler.
///
/// Listens on TCP (default port 502) and decodes the Modbus Application
/// Protocol (MBAP header + PDU) from every connection.  As a passive tap
/// this handler **never writes** to the connected devices — it only reads
/// and records.
///
/// Modbus MBAP header (7 bytes):
///   [0..1] Transaction ID  (u16 BE)
///   [2..3] Protocol ID     (u16 BE, always 0)
///   [4..5] Length          (u16 BE, number of following bytes)
///   [6]    Unit ID         (u8)
///
/// PDU:
///   [0]    Function code   (u8)
///   [1..]  Data            (variable)
use std::net::SocketAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::config::ModbusConfig;
use crate::protocols::{ProtocolHandler, RawEvent, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  Modbus PDU semantics
// ─────────────────────────────────────────────────────────────

/// Human-readable labels for the most common Modbus function codes.
fn function_code_name(fc: u8) -> &'static str {
    match fc {
        0x01 => "ReadCoils",
        0x02 => "ReadDiscreteInputs",
        0x03 => "ReadHoldingRegisters",
        0x04 => "ReadInputRegisters",
        0x05 => "WriteSingleCoil",
        0x06 => "WriteSingleRegister",
        0x0F => "WriteMultipleCoils",
        0x10 => "WriteMultipleRegisters",
        0x16 => "MaskWriteRegister",
        0x17 => "ReadWriteMultipleRegisters",
        0x2B => "EncapsulatedInterfaceTransport",
        0x7F..=0xFF => "ExceptionResponse",
        _ => "Unknown",
    }
}

/// Whether a function code represents a *write* operation to a PLC.
/// Used by the correlation engine to flag safety-relevant events.
pub fn is_write_function_code(fc: u8) -> bool {
    matches!(
        fc,
        0x05 | 0x06 | 0x0F | 0x10 | 0x16 | 0x17
    )
}

// ─────────────────────────────────────────────────────────────
//  Decoded frame (serialized into the RawEvent payload)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ModbusFrame {
    pub transaction_id: u16,
    pub unit_id:        u8,
    pub function_code:  u8,
    pub function_name:  String,
    pub is_write:       bool,
    pub data_hex:       String, // hex-encoded PDU data bytes
    pub data_len:       u16,
    pub src_addr:       String,
    pub dst_addr:       String,
}

// ─────────────────────────────────────────────────────────────
//  MBAP + PDU parser
// ─────────────────────────────────────────────────────────────

/// Parse a single Modbus/TCP frame from a byte slice.
/// Returns `None` if the slice is too short or protocol ID is invalid.
fn parse_mbap_pdu(
    bytes:    &[u8],
    src_addr: &str,
    dst_addr: &str,
) -> Option<ModbusFrame> {
    if bytes.len() < 8 {
        return None; // Need at least MBAP (7) + FC (1)
    }

    let txn_id   = u16::from_be_bytes([bytes[0], bytes[1]]);
    let proto_id = u16::from_be_bytes([bytes[2], bytes[3]]);
    let length   = u16::from_be_bytes([bytes[4], bytes[5]]);
    let unit_id  = bytes[6];
    let fc       = bytes[7];

    if proto_id != 0 {
        return None; // Not Modbus/TCP
    }

    let data_start = 8usize;
    let data_end   = data_start + (length as usize).saturating_sub(2);
    let data_bytes = bytes
        .get(data_start..data_end.min(bytes.len()))
        .unwrap_or(&[]);
    let data_hex   = hex::encode(data_bytes);

    Some(ModbusFrame {
        transaction_id: txn_id,
        unit_id,
        function_code: fc,
        function_name: function_code_name(fc).to_string(),
        is_write:      is_write_function_code(fc),
        data_hex,
        data_len:      length,
        src_addr:      src_addr.to_string(),
        dst_addr:      dst_addr.to_string(),
    })
}

// ─────────────────────────────────────────────────────────────
//  Handler
// ─────────────────────────────────────────────────────────────

pub struct ModbusHandler {
    cfg:          ModbusConfig,
    tenant_id:    String,
    collector_id: String,
}

impl ModbusHandler {
    pub fn new(cfg: ModbusConfig, tenant_id: String, collector_id: String) -> Self {
        Self { cfg, tenant_id, collector_id }
    }
}

#[async_trait]
impl ProtocolHandler for ModbusHandler {
    fn name(&self) -> &'static str {
        "modbus_tcp"
    }

    async fn run(
        self: Box<Self>,
        sender: tokio::sync::mpsc::Sender<RawEvent>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) {
        let bind_addr = format!("{}:{}", self.cfg.bind_address, self.cfg.listen_port);
        let listener  = match TcpListener::bind(&bind_addr).await {
            Ok(l) => {
                info!("modbus_tcp passive tap listening on {bind_addr}");
                l
            }
            Err(e) => {
                error!("modbus_tcp bind failed on {bind_addr}: {e}");
                return;
            }
        };

        let local_addr = listener.local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((mut stream, src)) => {
                            debug!("modbus_tcp: connection from {src}");
                            let tx        = sender.clone();
                            let tenant    = self.tenant_id.clone();
                            let collector = self.collector_id.clone();
                            let dst       = local_addr.clone();

                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 512];
                                loop {
                                    match stream.read(&mut buf).await {
                                        Ok(0) => break, // EOF
                                        Ok(n) => {
                                            let raw = buf[..n].to_vec();
                                            if let Some(frame) = parse_mbap_pdu(
                                                &raw,
                                                &src.to_string(),
                                                &dst,
                                            ) {
                                                debug!(
                                                    fc   = frame.function_code,
                                                    name = %frame.function_name,
                                                    write = frame.is_write,
                                                    "modbus frame"
                                                );
                                                let payload = serde_json::to_vec(&frame)
                                                    .unwrap_or(raw);
                                                let event = RawEvent::new(
                                                    tenant.clone(),
                                                    SourceDomain::Ot,
                                                    "modbus_tcp",
                                                    collector.clone(),
                                                    payload,
                                                    Some(src.to_string()),
                                                );
                                                if tx.send(event).await.is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            debug!("modbus_tcp read error from {src}: {e}");
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => error!("modbus_tcp accept error: {e}"),
                    }
                }
                _ = shutdown.recv() => {
                    info!("modbus_tcp handler shutting down");
                    break;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn modbus_read_holding_request() -> Vec<u8> {
        // Txn=1, Proto=0, Len=6, Unit=1, FC=03, Addr=0x006B, Count=0x0003
        vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x6B, 0x00, 0x03]
    }

    fn modbus_write_single_register() -> Vec<u8> {
        // FC=06: WriteSingleRegister
        vec![0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0xFF]
    }

    #[test]
    fn parse_read_holding_registers() {
        let bytes = modbus_read_holding_request();
        let frame = parse_mbap_pdu(&bytes, "10.0.0.1:502", "10.0.0.2:1024")
            .expect("should parse");
        assert_eq!(frame.function_code, 0x03);
        assert_eq!(frame.function_name, "ReadHoldingRegisters");
        assert!(!frame.is_write);
    }

    #[test]
    fn parse_write_single_register_flagged() {
        let bytes = modbus_write_single_register();
        let frame = parse_mbap_pdu(&bytes, "10.0.0.10:502", "10.0.0.20:5001")
            .expect("should parse");
        assert_eq!(frame.function_code, 0x06);
        assert!(frame.is_write, "write single register must be flagged as write");
    }

    #[test]
    fn invalid_protocol_id_rejected() {
        let mut bytes = modbus_read_holding_request();
        bytes[2] = 0x00;
        bytes[3] = 0x01; // proto_id = 1, not Modbus
        assert!(parse_mbap_pdu(&bytes, "a", "b").is_none());
    }
}
