/// ace-correlate — Consumes normalized events from `ace.events.normalized`,
/// applies correlation rules, and produces enriched events to
/// `ace.events.enriched` and alerts to `ace.alerts`.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use rdkafka::consumer::{CommitMode, Consumer};
use rdkafka::message::Message;
use tracing::{error, info, warn};

mod config;
mod engine;
mod error;
mod kafka;
mod rules;
mod schema;
mod session;
mod window;

use config::Config;
use engine::CorrelationEngine;
use rules::RuleRegistry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::load()?;

    // ── Logging ────────────────────────────────────────────────
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
        "ACE Correlate starting"
    );

    // ── Kafka ──────────────────────────────────────────────────
    let consumer = kafka::create_consumer(&cfg)?;
    let producer = Arc::new(kafka::create_producer(&cfg)?);

    let enriched_topic = cfg.kafka.enriched_topic.clone();
    let alerts_topic   = cfg.kafka.alerts_topic.clone();

    // ── Rule registry and engine ───────────────────────────────
    let registry = RuleRegistry::build(&cfg.engine.rules_dir);
    let engine   = Arc::new(CorrelationEngine::new(registry, cfg.engine.clone()));

    // ── Health server ──────────────────────────────────────────
    let health_port = cfg.health_port;
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/readyz",  get(|| async { "ok" }));
        let addr     = SocketAddr::from(([0, 0, 0, 0], health_port));
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        info!("Health server on {addr}");
        axum::serve(listener, app).await.unwrap();
    });

    // ── Periodic GC task ───────────────────────────────────────
    {
        let engine_gc   = Arc::clone(&engine);
        let gc_interval = cfg.engine.window_gc_interval_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(gc_interval));
            loop {
                interval.tick().await;
                engine_gc.gc_windows();
            }
        });
    }

    // ── Main correlation loop ──────────────────────────────────
    info!("Correlation loop started");
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

                        // Deserialize AceEvent.
                        let mut event: schema::AceEvent = match serde_json::from_slice(payload) {
                            Ok(e)  => e,
                            Err(e) => {
                                warn!("Failed to deserialize AceEvent: {e}");
                                let _ = consumer.commit_message(&m, CommitMode::Async);
                                continue;
                            }
                        };

                        // Run correlation engine — returns alerts, mutates event.session_id.
                        let alerts = engine.process(&mut event);

                        // Produce enriched event (always, even without alerts).
                        if let Err(e) =
                            kafka::send_enriched(&producer, &enriched_topic, &event).await
                        {
                            error!(
                                event_id = %event.event_id,
                                "Failed to produce enriched event: {e}"
                            );
                        }

                        // Produce any generated alerts.
                        for alert in &alerts {
                            if let Err(e) =
                                kafka::send_alert(&producer, &alerts_topic, alert).await
                            {
                                error!(
                                    rule = %alert.rule_name,
                                    "Failed to produce alert: {e}"
                                );
                            }
                        }

                        let _ = consumer.commit_message(&m, CommitMode::Async);
                    }
                }
            }
        }
    }

    info!("ACE Correlate stopped");
    Ok(())
}
