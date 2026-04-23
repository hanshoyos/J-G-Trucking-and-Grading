use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_collector_id")]
    pub collector_id: String,

    #[serde(default = "default_tenant")]
    pub tenant_id: String,

    #[serde(default = "default_health_port")]
    pub health_port: u16,

    pub kafka: KafkaConfig,

    #[serde(default)]
    pub geoip_db_path: Option<String>,

    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_collector_id() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "ace-normalize-unknown".to_string())
}
fn default_tenant() -> String    { "default".to_string() }
fn default_health_port() -> u16  { 8081 }
fn default_log_level() -> String { "info".to_string() }

#[derive(Debug, Clone, Deserialize)]
pub struct KafkaConfig {
    pub brokers: String,

    #[serde(default = "default_raw_topic")]
    pub raw_topic: String,

    #[serde(default = "default_normalized_topic")]
    pub normalized_topic: String,

    #[serde(default = "default_consumer_group")]
    pub consumer_group: String,

    pub sasl: Option<SaslConfig>,
}

fn default_raw_topic() -> String        { "ace.events.raw".to_string() }
fn default_normalized_topic() -> String { "ace.events.normalized".to_string() }
fn default_consumer_group() -> String   { "ace-normalize".to_string() }

#[derive(Debug, Clone, Deserialize)]
pub struct SaslConfig {
    pub mechanism: String,
    pub username:  String,
    pub password:  String,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name("/etc/ace-normalize/config").required(false))
            .add_source(config::File::with_name("config").required(false))
            .add_source(
                config::Environment::with_prefix("ACE_NORMALIZE")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;
        Ok(cfg.try_deserialize()?)
    }
}
