use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde::Serialize;

use crate::config::KafkaConfig;
use crate::error::IngestError;

// ─────────────────────────────────────────────────────────────
//  Metrics counters (exported via /metrics)
// ─────────────────────────────────────────────────────────────

pub struct KafkaMetrics {
    pub events_sent:   AtomicU64,
    pub events_failed: AtomicU64,
    pub bytes_sent:    AtomicU64,
    pub spilled:       AtomicU64,
}

impl Default for KafkaMetrics {
    fn default() -> Self {
        Self {
            events_sent:   AtomicU64::new(0),
            events_failed: AtomicU64::new(0),
            bytes_sent:    AtomicU64::new(0),
            spilled:       AtomicU64::new(0),
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  Producer wrapper with back-pressure tracking
// ─────────────────────────────────────────────────────────────

pub struct AceProducer {
    inner:   FutureProducer,
    metrics: Arc<KafkaMetrics>,
    timeout: Duration,
}

impl AceProducer {
    pub fn new(producer: FutureProducer, metrics: Arc<KafkaMetrics>) -> Self {
        Self {
            inner: producer,
            metrics,
            timeout: Duration::from_secs(5),
        }
    }

    /// Serialize `event` as JSON and produce it to `topic`.
    /// Returns immediately if Kafka is available; returns an error on
    /// timeout (caller may then spill to disk).
    pub async fn send<T: Serialize>(
        &self,
        topic: &str,
        key: &str,
        event: &T,
    ) -> Result<(), IngestError> {
        let payload = serde_json::to_vec(event)?;
        let payload_len = payload.len() as u64;

        let record = FutureRecord::to(topic).key(key).payload(&payload);

        match self.inner.send(record, self.timeout).await {
            Ok(_) => {
                self.metrics.events_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add(payload_len, Ordering::Relaxed);
                Ok(())
            }
            Err((e, _)) => {
                self.metrics.events_failed.fetch_add(1, Ordering::Relaxed);
                Err(IngestError::Kafka(e))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  Factory
// ─────────────────────────────────────────────────────────────

pub fn create_producer(cfg: &KafkaConfig) -> anyhow::Result<FutureProducer> {
    let mut client_cfg = ClientConfig::new();
    client_cfg
        .set("bootstrap.servers", &cfg.brokers)
        .set("message.timeout.ms", "5000")
        .set(
            "queue.buffering.max.messages",
            cfg.queue_buffering_max_messages.to_string(),
        )
        .set("acks", &cfg.acks)
        // Enable idempotent delivery
        .set("enable.idempotence", "true")
        // Compress with lz4 for throughput
        .set("compression.type", "lz4")
        .set("linger.ms", "5")
        .set("batch.num.messages", "10000");

    if let Some(sasl) = &cfg.sasl {
        client_cfg
            .set("security.protocol", "SASL_PLAINTEXT")
            .set("sasl.mechanism", &sasl.mechanism)
            .set("sasl.username", &sasl.username)
            .set("sasl.password", &sasl.password);
    }

    let producer: FutureProducer = client_cfg.create()?;
    Ok(producer)
}
