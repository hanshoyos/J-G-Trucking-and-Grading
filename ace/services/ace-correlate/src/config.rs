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
    pub engine: EngineConfig,

    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_collector_id() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "ace-correlate-unknown".to_string())
}
fn default_tenant() -> String    { "default".to_string() }
fn default_health_port() -> u16  { 8082 }
fn default_log_level() -> String { "info".to_string() }

#[derive(Debug, Clone, Deserialize)]
pub struct KafkaConfig {
    pub brokers: String,

    #[serde(default = "default_normalized_topic")]
    pub normalized_topic: String,

    #[serde(default = "default_enriched_topic")]
    pub enriched_topic: String,

    #[serde(default = "default_alerts_topic")]
    pub alerts_topic: String,

    #[serde(default = "default_group_id")]
    pub group_id: String,

    #[serde(default = "default_consumer_threads")]
    pub consumer_threads: usize,
}

fn default_normalized_topic() -> String { "ace.events.normalized".to_string() }
fn default_enriched_topic() -> String   { "ace.events.enriched".to_string() }
fn default_alerts_topic() -> String     { "ace.alerts".to_string() }
fn default_group_id() -> String         { "ace-correlate".to_string() }
fn default_consumer_threads() -> usize  { 4 }

#[derive(Debug, Clone, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_rules_dir")]
    pub rules_dir: String,

    #[serde(default = "default_window_gc_interval_secs")]
    pub window_gc_interval_secs: u64,

    #[serde(default = "default_max_window_events")]
    pub max_window_events: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            rules_dir:               default_rules_dir(),
            window_gc_interval_secs: default_window_gc_interval_secs(),
            max_window_events:       default_max_window_events(),
        }
    }
}

fn default_rules_dir() -> String              { "/etc/ace-correlate/rules".to_string() }
fn default_window_gc_interval_secs() -> u64   { 60 }
fn default_max_window_events() -> usize       { 10_000 }

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name("/etc/ace-correlate/config").required(false))
            .add_source(config::File::with_name("config").required(false))
            .add_source(
                config::Environment::with_prefix("ACE_CORRELATE")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;
        Ok(cfg.try_deserialize()?)
    }
}
