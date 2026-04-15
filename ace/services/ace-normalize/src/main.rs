/// ace-normalize — Transforms raw events from `ace.events.raw` into
/// normalized ACE-CEF events on `ace.events.normalized`.
use std::net::SocketAddr;
use std::sync::Arc;
use axum::routing::get;

use rdkafka::consumer::{CommitMode, Consumer};
use rdkafka::message::Message;
use tracing::{error, info, warn};

mod config;
mod enrichment;
mod error;
mod kafka;
mod normalizers;
mod schema;

use config::Config;
use enrichment::EnrichmentPipeline;
use normalizers::{NormalizerRegistry, RawEvent};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::load()?;

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.log_level)),
        )
        .init();

    info!(
        version   = env!("CARGO_PKG_VERSION"),
        collector = %cfg.collector_id,
        "ACE Normalize starting"
    );

    // ── Setup ──────────────────────────────────────────────────
    let consumer  = kafka::create_consumer(&cfg)?;
    let producer  = kafka::create_producer(&cfg)?;
    let registry  = Arc::new(NormalizerRegistry::build());
    let enricher  = Arc::new(EnrichmentPipeline::new(cfg.geoip_db_path.as_deref()));

    let norm_topic = cfg.kafka.normalized_topic.clone();

    // ── Health server ──────────────────────────────────────────
    let health_port = cfg.health_port;
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/readyz",  get(|| async { "ok" }));
        let addr = SocketAddr::from(([0, 0, 0, 0], health_port));
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        info!("Health server on {addr}");
        axum::serve(listener, app).await.unwrap();
    });

    // ── Main normalization loop ────────────────────────────────
    info!("Normalization loop started");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received");
                break;
            }
            msg = consumer.recv() => {
                match msg {
                    Err(e) => {
                        error!("Kafka consumer error: {e}");
                    }
                    Ok(m) => {
                        let payload = match m.payload() {
                            Some(p) => p,
                            None    => {
                                warn!("Empty Kafka message, skipping");
                                let _ = consumer.commit_message(&m, CommitMode::Async);
                                continue;
                            }
                        };

                        // Deserialize RawEvent
                        let raw: RawEvent = match serde_json::from_slice(payload) {
                            Ok(r)  => r,
                            Err(e) => {
                                warn!("Failed to deserialize RawEvent: {e}");
                                let _ = consumer.commit_message(&m, CommitMode::Async);
                                continue;
                            }
                        };

                        // Look up normalizer
                        let normalizer = match registry.get(&raw.source_type) {
                            Some(n) => n.clone(),
                            None => {
                                warn!(source_type = %raw.source_type, "No normalizer found, forwarding as-is");
                                let _ = consumer.commit_message(&m, CommitMode::Async);
                                continue;
                            }
                        };

                        // Normalize
                        let mut ace_event = match normalizer.normalize(&raw) {
                            Ok(e)  => e,
                            Err(e) => {
                                warn!(
                                    source_type = %raw.source_type,
                                    error = %e,
                                    "Normalization failed"
                                );
                                let _ = consumer.commit_message(&m, CommitMode::Async);
                                continue;
                            }
                        };

                        // Enrich
                        enricher.run(&mut ace_event);

                        // Produce normalized event
                        if let Err(e) = kafka::send_normalized(&producer, &norm_topic, &ace_event).await {
                            error!(
                                event_id = %ace_event.event_id,
                                "Failed to produce normalized event: {e}"
                            );
                        }

                        // Commit offset
                        let _ = consumer.commit_message(&m, CommitMode::Async);
                    }
                }
            }
        }
    }

    info!("ACE Normalize stopped");
    Ok(())
}
