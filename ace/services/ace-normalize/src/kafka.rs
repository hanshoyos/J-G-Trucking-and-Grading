use rdkafka::{
    config::ClientConfig,
    consumer::{CommitMode, Consumer, StreamConsumer},
    message::Message,
    producer::{FutureProducer, FutureRecord},
};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::NormalizeResult;
use crate::normalizers::RawEvent;
use crate::schema::AceEvent;

// ─────────────────────────────────────────────────────────────
//  Consumer
// ─────────────────────────────────────────────────────────────

pub fn create_consumer(cfg: &Config) -> anyhow::Result<StreamConsumer> {
    let mut client_cfg = ClientConfig::new();
    client_cfg
        .set("bootstrap.servers", &cfg.kafka.brokers)
        .set("group.id", &cfg.kafka.consumer_group)
        .set("enable.auto.commit", "false")  // manual commit after processing
        .set("auto.offset.reset", "earliest")
        .set("fetch.min.bytes", "65536")
        .set("fetch.wait.max.ms", "50");

    if let Some(sasl) = &cfg.kafka.sasl {
        client_cfg
            .set("security.protocol", "SASL_PLAINTEXT")
            .set("sasl.mechanism", &sasl.mechanism)
            .set("sasl.username", &sasl.username)
            .set("sasl.password", &sasl.password);
    }

    let consumer: StreamConsumer = client_cfg.create()?;
    consumer.subscribe(&[&cfg.kafka.raw_topic])?;
    info!(
        topic = %cfg.kafka.raw_topic,
        group = %cfg.kafka.consumer_group,
        "Kafka consumer subscribed"
    );
    Ok(consumer)
}

// ─────────────────────────────────────────────────────────────
//  Producer
// ─────────────────────────────────────────────────────────────

pub fn create_producer(cfg: &Config) -> anyhow::Result<FutureProducer> {
    let mut client_cfg = ClientConfig::new();
    client_cfg
        .set("bootstrap.servers", &cfg.kafka.brokers)
        .set("message.timeout.ms", "5000")
        .set("acks", "1")
        .set("enable.idempotence", "true")
        .set("compression.type", "lz4")
        .set("linger.ms", "5");

    if let Some(sasl) = &cfg.kafka.sasl {
        client_cfg
            .set("security.protocol", "SASL_PLAINTEXT")
            .set("sasl.mechanism", &sasl.mechanism)
            .set("sasl.username", &sasl.username)
            .set("sasl.password", &sasl.password);
    }

    Ok(client_cfg.create()?)
}

pub async fn send_normalized(
    producer: &FutureProducer,
    topic:    &str,
    event:    &AceEvent,
) -> Result<(), rdkafka::error::KafkaError> {
    let payload  = serde_json::to_vec(event).expect("AceEvent serialization cannot fail");
    let key      = event.event_id.as_str();
    let record   = FutureRecord::to(topic).key(key).payload(&payload);
    producer
        .send(record, Duration::from_secs(5))
        .await
        .map(|_| ())
        .map_err(|(e, _)| e)
}
