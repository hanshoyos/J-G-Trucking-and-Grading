use serde::Deserialize;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────
//  Top-level service configuration
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Kubernetes / collector identity tag embedded on every event.
    #[serde(default = "default_collector_id")]
    pub collector_id: String,

    /// Tenant identifier for multi-tenant deployments.
    #[serde(default = "default_tenant")]
    pub tenant_id: String,

    /// Port for the Axum health / metrics server.
    #[serde(default = "default_health_port")]
    pub health_port: u16,

    pub kafka: KafkaConfig,

    #[serde(default)]
    pub protocols: ProtocolsConfig,

    #[serde(default)]
    pub observability: ObservabilityConfig,
}

fn default_collector_id() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "ace-ingest-unknown".to_string())
}

fn default_tenant() -> String {
    "default".to_string()
}

fn default_health_port() -> u16 {
    8080
}

// ─────────────────────────────────────────────────────────────
//  Kafka
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct KafkaConfig {
    /// Comma-separated Kafka brokers.
    pub brokers: String,

    /// Topic for raw (pre-normalization) events.
    #[serde(default = "default_raw_topic")]
    pub raw_topic: String,

    /// Kafka producer queue buffer max messages.
    #[serde(default = "default_queue_max")]
    pub queue_buffering_max_messages: u32,

    /// Produce acknowledgement mode: "all", "1", "0".
    #[serde(default = "default_acks")]
    pub acks: String,

    /// Optional SASL config.
    pub sasl: Option<KafkaSaslConfig>,

    /// Spill-to-disk high-watermark (bytes). When the Kafka send queue
    /// exceeds this, events overflow to a local temp file ring buffer.
    #[serde(default = "default_spill_hwm")]
    pub spill_high_watermark_bytes: usize,
}

fn default_raw_topic() -> String {
    "ace.events.raw".to_string()
}

fn default_queue_max() -> u32 {
    1_000_000
}

fn default_acks() -> String {
    "1".to_string()
}

fn default_spill_hwm() -> usize {
    256 * 1024 * 1024 // 256 MiB
}

#[derive(Debug, Clone, Deserialize)]
pub struct KafkaSaslConfig {
    pub mechanism: String,
    pub username: String,
    pub password: String,
}

// ─────────────────────────────────────────────────────────────
//  Protocol handlers
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProtocolsConfig {
    #[serde(default)]
    pub syslog: SyslogConfig,

    #[serde(default)]
    pub modbus: ModbusConfig,

    #[serde(default)]
    pub cloudtrail: CloudTrailConfig,

    #[serde(default)]
    pub wef: WefConfig,

    #[serde(default)]
    pub k8s_audit: K8sAuditConfig,
}

// ─── Syslog (RFC 5424 / RFC 3164 / CEF / LEEF) ───────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SyslogConfig {
    #[serde(default = "bool_true")]
    pub enabled: bool,

    #[serde(default = "default_syslog_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_syslog_tcp_port")]
    pub tcp_port: u16,

    #[serde(default = "default_syslog_bind")]
    pub bind_address: String,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled:      true,
            udp_port:     514,
            tcp_port:     6514,
            bind_address: "0.0.0.0".to_string(),
        }
    }
}

fn default_syslog_udp_port() -> u16 {
    514
}
fn default_syslog_tcp_port() -> u16 {
    6514
}
fn default_syslog_bind() -> String {
    "0.0.0.0".to_string()
}

// ─── Modbus/TCP passive tap ───────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ModbusConfig {
    #[serde(default = "bool_false")]
    pub enabled: bool,

    #[serde(default = "default_modbus_port")]
    pub listen_port: u16,

    #[serde(default = "default_modbus_bind")]
    pub bind_address: String,
}

impl Default for ModbusConfig {
    fn default() -> Self {
        Self {
            enabled:      false,
            listen_port:  502,
            bind_address: "0.0.0.0".to_string(),
        }
    }
}

fn default_modbus_port() -> u16 {
    502
}
fn default_modbus_bind() -> String {
    "0.0.0.0".to_string()
}

// ─── AWS CloudTrail ──────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CloudTrailConfig {
    #[serde(default)]
    pub enabled: bool,

    /// SQS queue URL that receives S3-event notifications for CloudTrail logs.
    pub sqs_queue_url: Option<String>,

    /// AWS region.
    #[serde(default = "default_aws_region")]
    pub aws_region: String,

    /// Polling interval.
    #[serde(
        default = "default_poll_seconds",
        deserialize_with = "de_secs_as_duration"
    )]
    pub poll_interval: Duration,
}

fn default_aws_region() -> String {
    "us-east-1".to_string()
}

fn default_poll_seconds() -> Duration {
    Duration::from_secs(10)
}

fn de_secs_as_duration<'de, D>(d: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(d)?;
    Ok(Duration::from_secs(secs))
}

// ─── Windows Event Forwarding ─────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct WefConfig {
    #[serde(default = "bool_false")]
    pub enabled: bool,

    #[serde(default = "default_wef_port")]
    pub port: u16,

    #[serde(default = "default_wef_bind")]
    pub bind_address: String,

    /// Optional TLS certificate file paths.
    pub tls_cert_path: Option<String>,
    pub tls_key_path:  Option<String>,
}

impl Default for WefConfig {
    fn default() -> Self {
        Self {
            enabled:       false,
            port:          5985,
            bind_address:  "0.0.0.0".to_string(),
            tls_cert_path: None,
            tls_key_path:  None,
        }
    }
}

fn default_wef_port() -> u16 {
    5985
}
fn default_wef_bind() -> String {
    "0.0.0.0".to_string()
}

// ─── Kubernetes Audit Webhook ─────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct K8sAuditConfig {
    #[serde(default = "bool_false")]
    pub enabled: bool,

    #[serde(default = "default_k8s_port")]
    pub port: u16,

    #[serde(default = "default_k8s_bind")]
    pub bind_address: String,

    /// Shared token for webhook bearer-auth.
    pub webhook_token: Option<String>,
}

impl Default for K8sAuditConfig {
    fn default() -> Self {
        Self {
            enabled:       false,
            port:          9443,
            bind_address:  "0.0.0.0".to_string(),
            webhook_token: None,
        }
    }
}

fn default_k8s_port() -> u16 {
    9443
}
fn default_k8s_bind() -> String {
    "0.0.0.0".to_string()
}

// ─────────────────────────────────────────────────────────────
//  Observability
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    /// OTLP endpoint (gRPC) for traces.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,

    #[serde(default = "log_level_default")]
    pub log_level: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            log_level:     "info".to_string(),
        }
    }
}

fn log_level_default() -> String {
    "info".to_string()
}

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────

fn bool_true() -> bool {
    true
}
fn bool_false() -> bool {
    false
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            // 1. Base defaults embedded in code (above)
            // 2. /etc/ace-ingest/config.yaml (optional)
            .add_source(
                config::File::with_name("/etc/ace-ingest/config")
                    .required(false),
            )
            // 3. ./config.yaml (for local dev)
            .add_source(
                config::File::with_name("config")
                    .required(false),
            )
            // 4. Environment variables: ACE_INGEST__KAFKA__BROKERS etc.
            .add_source(
                config::Environment::with_prefix("ACE_INGEST")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        Ok(cfg.try_deserialize()?)
    }
}
