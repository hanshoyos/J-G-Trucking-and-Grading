use thiserror::Error;

#[derive(Debug, Error)]
pub enum CorrelateError {
    #[error("Kafka error: {0}")]
    Kafka(#[from] rdkafka::error::KafkaError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Rule parse error in {file}: {message}")]
    RuleParse { file: String, message: String },
}

pub type CorrelateResult<T> = Result<T, CorrelateError>;
