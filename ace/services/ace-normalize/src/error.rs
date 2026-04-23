use thiserror::Error;

#[derive(Debug, Error)]
pub enum NormalizeError {
    #[error("Kafka error: {0}")]
    Kafka(#[from] rdkafka::error::KafkaError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Deserialization error for source_type '{source_type}': {message}")]
    Deserialize {
        source_type: String,
        message:     String,
    },

    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("GeoIP lookup error: {0}")]
    GeoIp(String),
}

pub type NormalizeResult<T> = Result<T, NormalizeError>;
