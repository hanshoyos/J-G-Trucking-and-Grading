use rdkafka::{
    config::ClientConfig,
    consumer::{Consumer, StreamConsumer},
    producer::{FutureProducer, FutureRecord},
    message::Message,
};
use std::time::Duration;
use tracing::info;

use crate::config::Config;
use crate::schema::{AceAlert, AceEvent};

// ─────────────────────────────────────────────────────────────
//  Consumer
// ─────────────────────────────────────────────────────────────

pub fn create_consumer(cfg: &Config) -> anyhow::Result<StreamConsumer> {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", &cfg.kafka.brokers)
        .set("group.id", &cfg.kafka.group_id)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .set("fetch.min.bytes", "65536")
        .set("fetch.wait.max.ms", "50")
        .create()?;

    consumer.subscribe(&[&cfg.kafka.normalized_topic])?;
    info!(
        topic = %cfg.kafka.normalized_topic,
        group = %cfg.kafka.group_id,
        "Kafka consumer subscribed"
    );
    Ok(consumer)
}

// ─────────────────────────────────────────────────────────────
//  Producer
// ─────────────────────────────────────────────────────────────

pub fn create_producer(cfg: &Config) -> anyhow::Result<FutureProducer> {
    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &cfg.kafka.brokers)
        .set("message.timeout.ms", "5000")
        .set("acks", "all")
        .set("enable.idempotence", "true")
        .set("compression.type", "lz4")
        .set("linger.ms", "5")
        .create()?;
    Ok(producer)
}

// ─────────────────────────────────────────────────────────────
//  Send helpers
// ─────────────────────────────────────────────────────────────

pub async fn send_enriched(
    producer: &FutureProducer,
    topic:    &str,
    event:    &AceEvent,
) -> Result<(), rdkafka::error::KafkaError> {
    let payload = serde_json::to_vec(event).expect("AceEvent serialization cannot fail");
    let key     = event.event_id.as_str();
    let record  = FutureRecord::to(topic).key(key).payload(&payload);
    producer
        .send(record, Duration::from_secs(5))
        .await
        .map(|_| ())
        .map_err(|(e, _)| e)
}

pub async fn send_alert(
    producer: &FutureProducer,
    topic:    &str,
    alert:    &AceAlert,
) -> Result<(), rdkafka::error::KafkaError> {
    let payload = serde_json::to_vec(alert).expect("AceAlert serialization cannot fail");
    let key     = alert.alert_id.as_str();
    let record  = FutureRecord::to(topic).key(key).payload(&payload);
    producer
        .send(record, Duration::from_secs(5))
        .await
        .map(|_| ())
        .map_err(|(e, _)| e)
}

// Re-export so main.rs can use rdkafka traits without extra imports.
pub use rdkafka::consumer::CommitMode;
pub use rdkafka::message::Message as KafkaMessage;
