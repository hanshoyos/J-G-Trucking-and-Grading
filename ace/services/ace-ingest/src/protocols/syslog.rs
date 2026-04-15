/// Syslog protocol handler — RFC 5424, RFC 3164, CEF, and LEEF.
///
/// Listens on both UDP (port 514 default) and TCP (port 6514 default).
/// Parsing is done with `winnow` zero-copy combinators.
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};
use winnow::{
    ascii::{digit1, space0, space1},
    combinator::{alt, opt, preceded, rest},
    token::{take_till, take_while},
    PResult, Parser,
};

use crate::config::SyslogConfig;
use crate::protocols::{ProtocolHandler, RawEvent, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  Parsed syslog structures
// ─────────────────────────────────────────────────────────────

/// RFC 5424 priority contains facility (high 5 bits) and severity (low 3 bits).
#[derive(Debug, Clone)]
pub struct Priority {
    pub facility: u8,
    pub severity: u8,
}

impl Priority {
    fn from_raw(raw: u8) -> Self {
        Self {
            facility: raw >> 3,
            severity: raw & 0x07,
        }
    }
}

/// Parsed RFC 5424 header fields.
#[derive(Debug, Clone)]
pub struct Rfc5424Header<'a> {
    pub priority:   Priority,
    pub version:    u8,
    pub timestamp:  &'a str,
    pub hostname:   &'a str,
    pub app_name:   &'a str,
    pub proc_id:    &'a str,
    pub msg_id:     &'a str,
}

/// Parsed RFC 3164 header fields.
#[derive(Debug, Clone)]
pub struct Rfc3164Header<'a> {
    pub priority:  Priority,
    pub timestamp: &'a str,
    pub hostname:  &'a str,
}

// ─────────────────────────────────────────────────────────────
//  winnow parsers
// ─────────────────────────────────────────────────────────────

/// Parse `<PRI>` — e.g. `<34>`.
fn parse_pri(input: &mut &str) -> PResult<Priority> {
    let raw: u8 = preceded(
        '<',
        (
            digit1.try_map(|s: &str| s.parse::<u8>()),
            '>',
        ),
    )
    .map(|(n, _)| n)
    .parse_next(input)?;
    Ok(Priority::from_raw(raw))
}

/// Parse the version field in RFC 5424 (`1` space).
fn parse_version(input: &mut &str) -> PResult<u8> {
    (digit1.try_map(|s: &str| s.parse::<u8>()), space1)
        .map(|(v, _)| v)
        .parse_next(input)
}

/// Parse a NILVALUE (`-`) or a run of non-space bytes.
fn nil_or_value<'a>(input: &mut &'a str) -> PResult<&'a str> {
    alt(("-", take_till(1.., |c: char| c == ' '))).parse_next(input)
}

/// Parse a full RFC 5424 syslog message header.
pub fn parse_rfc5424<'a>(input: &mut &'a str) -> PResult<Rfc5424Header<'a>> {
    let priority  = parse_pri.parse_next(input)?;
    let version   = parse_version.parse_next(input)?;
    let timestamp = nil_or_value.parse_next(input)?;
    let _         = space1.parse_next(input)?;
    let hostname  = nil_or_value.parse_next(input)?;
    let _         = space1.parse_next(input)?;
    let app_name  = nil_or_value.parse_next(input)?;
    let _         = space1.parse_next(input)?;
    let proc_id   = nil_or_value.parse_next(input)?;
    let _         = space1.parse_next(input)?;
    let msg_id    = nil_or_value.parse_next(input)?;
    Ok(Rfc5424Header {
        priority,
        version,
        timestamp,
        hostname,
        app_name,
        proc_id,
        msg_id,
    })
}

/// Parse RFC 3164 timestamp: `Mmm DD HH:MM:SS` (15 chars).
fn parse_rfc3164_timestamp<'a>(input: &mut &'a str) -> PResult<&'a str> {
    take_while(15..=16, |c: char| !c.is_control()).parse_next(input)
}

/// Parse a full RFC 3164 syslog header.
pub fn parse_rfc3164<'a>(input: &mut &'a str) -> PResult<Rfc3164Header<'a>> {
    let priority  = parse_pri.parse_next(input)?;
    let timestamp = parse_rfc3164_timestamp.parse_next(input)?;
    let _         = space1.parse_next(input)?;
    let hostname  = take_till(1.., |c: char| c == ' ').parse_next(input)?;
    let _         = space0.parse_next(input)?;
    Ok(Rfc3164Header { priority, timestamp, hostname })
}

// ─────────────────────────────────────────────────────────────
//  Handler
// ─────────────────────────────────────────────────────────────

pub struct SyslogHandler {
    cfg:          SyslogConfig,
    tenant_id:    String,
    collector_id: String,
}

impl SyslogHandler {
    pub fn new(cfg: SyslogConfig, tenant_id: String, collector_id: String) -> Self {
        Self { cfg, tenant_id, collector_id }
    }

    async fn handle_datagram(
        payload:      Vec<u8>,
        src_addr:     SocketAddr,
        sender:       &tokio::sync::mpsc::Sender<RawEvent>,
        tenant_id:    &str,
        collector_id: &str,
    ) {
        let source_type = detect_syslog_variant(&payload);
        let event = RawEvent::new(
            tenant_id.to_string(),
            SourceDomain::It,
            source_type,
            collector_id.to_string(),
            payload,
            Some(src_addr.to_string()),
        );
        if let Err(e) = sender.send(event).await {
            warn!("syslog: channel full, dropping event: {e}");
        }
    }
}

/// Heuristically detect which syslog dialect the payload is.
fn detect_syslog_variant(bytes: &[u8]) -> &'static str {
    let head = std::str::from_utf8(&bytes[..bytes.len().min(32)]).unwrap_or("");
    if head.contains("CEF:") {
        "syslog_cef"
    } else if head.contains("LEEF:") {
        "syslog_leef"
    } else if head.starts_with('<')
        && head
            .chars()
            .nth(1)
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    {
        // Try to distinguish RFC 5424 vs 3164 by the version field
        let after_pri = head.find('>').map(|i| &head[i + 1..]).unwrap_or("");
        if after_pri.starts_with('1') {
            "syslog_rfc5424"
        } else {
            "syslog_rfc3164"
        }
    } else {
        "syslog_unknown"
    }
}

#[async_trait]
impl ProtocolHandler for SyslogHandler {
    fn name(&self) -> &'static str {
        "syslog"
    }

    async fn run(
        self: Box<Self>,
        sender: tokio::sync::mpsc::Sender<RawEvent>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) {
        let udp_addr = format!("{}:{}", self.cfg.bind_address, self.cfg.udp_port);
        let tcp_addr = format!("{}:{}", self.cfg.bind_address, self.cfg.tcp_port);

        // ── UDP socket ──────────────────────────────────────────
        let udp_sock = match UdpSocket::bind(&udp_addr).await {
            Ok(s) => {
                info!("syslog UDP listening on {udp_addr}");
                Arc::new(s)
            }
            Err(e) => {
                error!("syslog UDP bind failed on {udp_addr}: {e}");
                return;
            }
        };

        // ── TCP listener ────────────────────────────────────────
        let tcp_listener = match TcpListener::bind(&tcp_addr).await {
            Ok(l) => {
                info!("syslog TCP listening on {tcp_addr}");
                l
            }
            Err(e) => {
                error!("syslog TCP bind failed on {tcp_addr}: {e}");
                return;
            }
        };

        let udp_sock_clone  = udp_sock.clone();
        let sender_udp      = sender.clone();
        let tenant_udp      = self.tenant_id.clone();
        let collector_udp   = self.collector_id.clone();

        // ── Spawn UDP receive loop ───────────────────────────────
        let udp_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                match udp_sock_clone.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        let payload = buf[..len].to_vec();
                        debug!("syslog UDP: {} bytes from {src}", len);
                        SyslogHandler::handle_datagram(
                            payload, src, &sender_udp, &tenant_udp, &collector_udp,
                        )
                        .await;
                    }
                    Err(e) => {
                        error!("syslog UDP recv error: {e}");
                    }
                }
            }
        });

        let sender_tcp    = sender.clone();
        let tenant_tcp    = self.tenant_id.clone();
        let collector_tcp = self.collector_id.clone();

        // ── Spawn TCP accept loop ────────────────────────────────
        let tcp_handle = tokio::spawn(async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((stream, src)) => {
                        debug!("syslog TCP: connection from {src}");
                        let tx        = sender_tcp.clone();
                        let tenant    = tenant_tcp.clone();
                        let collector = collector_tcp.clone();
                        tokio::spawn(async move {
                            let reader = BufReader::new(stream);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                let payload = line.into_bytes();
                                let source_type = detect_syslog_variant(&payload);
                                let event = RawEvent::new(
                                    tenant.clone(),
                                    SourceDomain::It,
                                    source_type,
                                    collector.clone(),
                                    payload,
                                    Some(src.to_string()),
                                );
                                if tx.send(event).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("syslog TCP accept error: {e}");
                    }
                }
            }
        });

        // ── Wait for shutdown ────────────────────────────────────
        let _ = shutdown.recv().await;
        info!("syslog handler shutting down");
        udp_handle.abort();
        tcp_handle.abort();
    }
}

// ─────────────────────────────────────────────────────────────
//  Unit tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rfc5424_basic() {
        let mut input =
            "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'test'";
        let hdr = parse_rfc5424(&mut input).expect("parse should succeed");
        assert_eq!(hdr.priority.facility, 4); // auth facility
        assert_eq!(hdr.priority.severity, 2); // critical
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.hostname, "mymachine.example.com");
        assert_eq!(hdr.app_name, "su");
    }

    #[test]
    fn detect_cef_variant() {
        let payload = b"<13>Oct 11 12:34:56 host CEF:0|Vendor|Product|1.0|100|Test|5|src=1.2.3.4";
        assert_eq!(detect_syslog_variant(payload), "syslog_cef");
    }

    #[test]
    fn detect_rfc5424_variant() {
        let payload = b"<34>1 2003-10-11T22:14:15.003Z mymachine su - ID47 - msg";
        assert_eq!(detect_syslog_variant(payload), "syslog_rfc5424");
    }
}
