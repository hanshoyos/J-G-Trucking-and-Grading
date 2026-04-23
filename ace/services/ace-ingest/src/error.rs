use thiserror::Error;

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("Kafka producer error: {0}")]
    Kafka(#[from] rdkafka::error::KafkaError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error in {protocol}: {message}")]
    Parse {
        protocol: &'static str,
        message:  String,
    },

    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("AWS SQS error: {0}")]
    AwsSqs(String),

    #[error("AWS S3 error: {0}")]
    AwsS3(String),

    #[error("Back-pressure spill error: {0}")]
    Spill(String),

    #[error("Shutdown requested")]
    Shutdown,
}

pub type IngestResult<T> = Result<T, IngestError>;
