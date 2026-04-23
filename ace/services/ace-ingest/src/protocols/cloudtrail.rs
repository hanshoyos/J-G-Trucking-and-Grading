/// AWS CloudTrail ingestion handler.
///
/// Polls an SQS queue for S3-event notifications that CloudTrail publishes
/// when it delivers new log files.  Each notification points to an S3 object
/// containing a JSON batch of CloudTrail records.  We download, decompress
/// (CloudTrail gzips files), and emit one RawEvent per CloudTrail record.
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_sqs::Client as SqsClient;
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::config::CloudTrailConfig;
use crate::error::IngestError;
use crate::protocols::{ProtocolHandler, RawEvent, SourceDomain};

// ─────────────────────────────────────────────────────────────
//  SQS message envelope (S3 event notification)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct S3EventNotification {
    #[serde(rename = "Records")]
    records: Vec<S3EventRecord>,
}

#[derive(Debug, Deserialize)]
struct S3EventRecord {
    s3: S3Info,
}

#[derive(Debug, Deserialize)]
struct S3Info {
    bucket: S3Bucket,
    object: S3Object,
}

#[derive(Debug, Deserialize)]
struct S3Bucket {
    name: String,
}

#[derive(Debug, Deserialize)]
struct S3Object {
    key: String,
}

// ─────────────────────────────────────────────────────────────
//  CloudTrail log envelope
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CloudTrailLog {
    #[serde(rename = "Records")]
    records: Vec<Value>,
}

// ─────────────────────────────────────────────────────────────
//  Handler
// ─────────────────────────────────────────────────────────────

pub struct CloudTrailHandler {
    cfg:          CloudTrailConfig,
    tenant_id:    String,
    collector_id: String,
}

impl CloudTrailHandler {
    pub fn new(cfg: CloudTrailConfig, tenant_id: String, collector_id: String) -> Self {
        Self { cfg, tenant_id, collector_id }
    }

    async fn poll_once(
        &self,
        sqs:    &SqsClient,
        s3:     &S3Client,
        queue:  &str,
        sender: &tokio::sync::mpsc::Sender<RawEvent>,
    ) -> Result<(), IngestError> {
        // Receive up to 10 messages at a time.
        let receive_output = sqs
            .receive_message()
            .queue_url(queue)
            .max_number_of_messages(10)
            .wait_time_seconds(20) // long-poll
            .send()
            .await
            .map_err(|e| IngestError::AwsSqs(e.to_string()))?;

        let messages = receive_output.messages.unwrap_or_default();
        debug!("cloudtrail: received {} SQS messages", messages.len());

        for msg in messages {
            let body = match &msg.body {
                Some(b) => b.as_str(),
                None => continue,
            };

            // Parse S3 event notification.
            let notification: S3EventNotification = match serde_json::from_str(body) {
                Ok(n) => n,
                Err(e) => {
                    warn!("cloudtrail: failed to parse SQS notification: {e}");
                    continue;
                }
            };

            for record in notification.records {
                let bucket = &record.s3.bucket.name;
                let key    = &record.s3.object.key;

                // Download from S3.
                let s3_obj = s3
                    .get_object()
                    .bucket(bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(|e| IngestError::AwsS3(e.to_string()))?;

                let compressed = s3_obj
                    .body
                    .collect()
                    .await
                    .map_err(|e| IngestError::AwsS3(e.to_string()))?
                    .into_bytes();

                // CloudTrail files are gzip-compressed.
                let json_bytes = Self::decompress_gzip(&compressed)?;
                let ct_log: CloudTrailLog = serde_json::from_slice(&json_bytes)
                    .map_err(|e| IngestError::Parse {
                        protocol: "cloudtrail",
                        message:  e.to_string(),
                    })?;

                info!(
                    "cloudtrail: {} records from s3://{bucket}/{key}",
                    ct_log.records.len()
                );

                for ct_record in ct_log.records {
                    let payload = serde_json::to_vec(&ct_record)?;
                    let event   = RawEvent::new(
                        self.tenant_id.clone(),
                        SourceDomain::Cloud,
                        "cloudtrail",
                        self.collector_id.clone(),
                        payload,
                        None,
                    );
                    if sender.send(event).await.is_err() {
                        return Ok(()); // channel closed → shutdown
                    }
                }
            }

            // Delete processed message.
            if let Some(receipt) = &msg.receipt_handle {
                let _ = sqs
                    .delete_message()
                    .queue_url(queue)
                    .receipt_handle(receipt)
                    .send()
                    .await;
            }
        }

        Ok(())
    }

    fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, IngestError> {
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).map_err(|e| IngestError::Io(e))?;
        Ok(out)
    }
}

#[async_trait]
impl ProtocolHandler for CloudTrailHandler {
    fn name(&self) -> &'static str {
        "cloudtrail"
    }

    async fn run(
        self: Box<Self>,
        sender: tokio::sync::mpsc::Sender<RawEvent>,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) {
        let queue_url = match &self.cfg.sqs_queue_url {
            Some(u) => u.clone(),
            None => {
                warn!("cloudtrail: no sqs_queue_url configured, handler inactive");
                return;
            }
        };

        info!(
            "cloudtrail: polling SQS queue {} every {:?}",
            queue_url, self.cfg.poll_interval
        );

        // Build AWS SDK clients from environment (IAM role / env vars).
        let aws_cfg = aws_config::load_from_env().await;
        let sqs = SqsClient::new(&aws_cfg);
        let s3  = S3Client::new(&aws_cfg);

        let mut interval = tokio::time::interval(self.cfg.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.poll_once(&sqs, &s3, &queue_url, &sender).await {
                        error!("cloudtrail poll error: {e}");
                    }
                }
                _ = shutdown.recv() => {
                    info!("cloudtrail handler shutting down");
                    break;
                }
            }
        }
    }
}
