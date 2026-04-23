/// ace-ingest — Universal log ingestion gateway.
///
/// Phase 1 protocol handlers: Syslog, Modbus/TCP, CloudTrail, WEF, K8s Audit.
/// Target: 500,000 events/second per pod with horizontal scaling.
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

mod config;
mod error;
mod health;
mod kafka;
mod protocols;

use config::Config;
use health::HealthState;
use kafka::{AceProducer, KafkaMetrics};
use protocols::ProtocolHandler;

// Kafka send queue size (events in flight before back-pressure kicks in).
const EVENT_CHANNEL_SIZE: usize = 1_000_000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Tracing / observability ────────────────────────────────
    let cfg = Config::load()?;

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new(&cfg.observability.log_level)
                }),
        )
        .init();

    info!(
        version   = env!("CARGO_PKG_VERSION"),
        collector = %cfg.collector_id,
        tenant    = %cfg.tenant_id,
        "ACE Ingest starting"
    );

    // ── Kafka ─────────────────────────────────────────────────
    let producer      = kafka::create_producer(&cfg.kafka)?;
    let kafka_metrics = Arc::new(KafkaMetrics::default());
    let ace_producer  = Arc::new(AceProducer::new(producer, kafka_metrics.clone()));

    // ── Shutdown signal ────────────────────────────────────────
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // ── Event channel (protocol handlers → Kafka dispatcher) ──
    let (event_tx, mut event_rx) = mpsc::channel::<protocols::RawEvent>(EVENT_CHANNEL_SIZE);

    // ── Protocol handlers ──────────────────────────────────────
    let mut handler_names: Vec<&'static str> = Vec::new();

    let handlers: Vec<Box<dyn ProtocolHandler>> = build_handlers(&cfg);
    for handler in handlers {
        handler_names.push(handler.name());
        let rx  = shutdown_tx.subscribe();
        let tx  = event_tx.clone();
        tokio::spawn(async move {
            handler.run(tx, rx).await;
        });
    }

    info!(handlers = ?handler_names, "Protocol handlers started");

    // ── Kafka dispatch loop ────────────────────────────────────
    let raw_topic      = cfg.kafka.raw_topic.clone();
    let producer_clone = ace_producer.clone();

    let kafka_dispatch = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let key = event.event_id.clone();
            if let Err(e) = producer_clone.send(&raw_topic, &key, &event).await {
                error!(error = %e, "Kafka dispatch failed");
            }
        }
    });

    // ── Health server ──────────────────────────────────────────
    let health_state = HealthState {
        metrics: kafka_metrics.clone(),
        version: env!("CARGO_PKG_VERSION"),
    };
    let health_port = cfg.health_port;
    tokio::spawn(async move {
        if let Err(e) = health::serve(health_port, health_state).await {
            error!("Health server exited: {e}");
        }
    });

    // ── Wait for SIGTERM / Ctrl-C ──────────────────────────────
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down");
        }
    }

    // Broadcast shutdown to all handlers.
    let _ = shutdown_tx.send(());
    // Drop the channel sender so the dispatch loop drains and exits.
    drop(event_tx);
    let _ = kafka_dispatch.await;

    info!("ACE Ingest stopped");
    Ok(())
}

/// Instantiate all enabled protocol handlers from config.
fn build_handlers(cfg: &Config) -> Vec<Box<dyn ProtocolHandler>> {
    let mut handlers: Vec<Box<dyn ProtocolHandler>> = Vec::new();

    // ── Syslog ─────────────────────────────────────────────────
    if cfg.protocols.syslog.enabled {
        handlers.push(Box::new(protocols::syslog::SyslogHandler::new(
            cfg.protocols.syslog.clone(),
            cfg.tenant_id.clone(),
            cfg.collector_id.clone(),
        )));
    }

    // ── Modbus/TCP ─────────────────────────────────────────────
    if cfg.protocols.modbus.enabled {
        handlers.push(Box::new(protocols::modbus::ModbusHandler::new(
            cfg.protocols.modbus.clone(),
            cfg.tenant_id.clone(),
            cfg.collector_id.clone(),
        )));
    }

    // ── AWS CloudTrail ─────────────────────────────────────────
    if cfg.protocols.cloudtrail.enabled {
        handlers.push(Box::new(protocols::cloudtrail::CloudTrailHandler::new(
            cfg.protocols.cloudtrail.clone(),
            cfg.tenant_id.clone(),
            cfg.collector_id.clone(),
        )));
    }

    // ── Windows Event Forwarding ───────────────────────────────
    if cfg.protocols.wef.enabled {
        handlers.push(Box::new(protocols::wef::WefHandler::new(
            cfg.protocols.wef.clone(),
            cfg.tenant_id.clone(),
            cfg.collector_id.clone(),
        )));
    }

    // ── Kubernetes Audit ───────────────────────────────────────
    if cfg.protocols.k8s_audit.enabled {
        handlers.push(Box::new(protocols::k8s_audit::K8sAuditHandler::new(
            cfg.protocols.k8s_audit.clone(),
            cfg.tenant_id.clone(),
            cfg.collector_id.clone(),
        )));
    }

    handlers
}
