// Package discovery implements passive asset discovery by consuming
// ace.events.normalized Kafka events and upserting assets into the store.
package discovery

import (
	"context"
	"encoding/json"
	"time"

	confluentkafka "github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"go.uber.org/zap"

	"github.com/ace-platform/ace-asset-inventory/internal/purdue"
	"github.com/ace-platform/ace-asset-inventory/internal/store"
	"github.com/google/uuid"
)

// aceEvent is the minimal subset of the AceEvent JSON we need for asset discovery.
type aceEvent struct {
	TenantID     string     `json:"tenant_id"`
	SourceDomain string     `json:"source_domain"` // "IT", "OT", "CLOUD", "HYBRID"
	SourceType   string     `json:"source_type"`
	Normalized   normalized `json:"normalized"`
}

type normalized struct {
	SrcIP          string `json:"src_ip"`
	DstIP          string `json:"dst_ip"`
	User           string `json:"user"`
	PlcAddress     string `json:"plc_address"`
	FunctionCode   *uint  `json:"function_code"`
	PurdueLevel    *uint  `json:"purdue_level"`
	CloudProvider  string `json:"cloud_provider"`
	CloudAccountID string `json:"cloud_account_id"`
	CloudRegion    string `json:"cloud_region"`
	ResourceARN    string `json:"resource_arn"`
}

// Discoverer consumes from Kafka and updates the asset store.
type Discoverer struct {
	consumer *confluentkafka.Consumer
	db       *store.Store
	clf      *purdue.Classifier
	log      *zap.Logger
}

// New creates a Discoverer. Returns nil without error when brokers is empty
// (passive discovery disabled).
func New(
	brokers, topic, groupID string,
	db *store.Store,
	clf *purdue.Classifier,
	log *zap.Logger,
) (*Discoverer, error) {
	if brokers == "" {
		log.Warn("passive discovery disabled — no Kafka brokers configured")
		return nil, nil
	}

	c, err := confluentkafka.NewConsumer(&confluentkafka.ConfigMap{
		"bootstrap.servers":  brokers,
		"group.id":           groupID,
		"auto.offset.reset":  "latest", // only discover assets from new events
		"enable.auto.commit": true,
	})
	if err != nil {
		return nil, err
	}
	if err := c.Subscribe(topic, nil); err != nil {
		return nil, err
	}

	return &Discoverer{consumer: c, db: db, clf: clf, log: log}, nil
}

// Run starts consuming events until ctx is cancelled.
func (d *Discoverer) Run(ctx context.Context) {
	d.log.Info("passive asset discovery started")
	for {
		select {
		case <-ctx.Done():
			d.log.Info("passive discovery stopping")
			_ = d.consumer.Close()
			return
		default:
		}

		msg, err := d.consumer.ReadMessage(200 * time.Millisecond)
		if err != nil {
			// Timeout is normal when the topic is quiet.
			if err.(confluentkafka.Error).Code() != confluentkafka.ErrTimedOut {
				d.log.Error("kafka read error", zap.Error(err))
			}
			continue
		}

		var event aceEvent
		if err := json.Unmarshal(msg.Value, &event); err != nil {
			continue
		}
		d.processEvent(ctx, &event)
	}
}

func (d *Discoverer) processEvent(ctx context.Context, event *aceEvent) {
	now := time.Now().UTC()

	domain := store.AssetDomain(event.SourceDomain)
	if domain != store.DomainIT && domain != store.DomainOT && domain != store.DomainCloud {
		domain = store.DomainIT
	}

	// Discover cloud asset from resource_arn
	if event.Normalized.ResourceARN != "" {
		a := &store.Asset{
			AssetID:        deterministicID(event.TenantID, event.Normalized.ResourceARN),
			TenantID:       event.TenantID,
			HostnameOrIP:   event.Normalized.ResourceARN,
			IPAddresses:    nil,
			Domain:         store.DomainCloud,
			PurdueLevel:    -1,
			CloudProvider:  event.Normalized.CloudProvider,
			CloudRegion:    event.Normalized.CloudRegion,
			CloudAccountID: event.Normalized.CloudAccountID,
			ResourceARN:    event.Normalized.ResourceARN,
			AssetType:      "cloud_resource",
			FirstSeen:      now,
			LastSeen:       now,
			IsActive:       true,
		}
		if err := d.db.UpsertAsset(ctx, a); err != nil {
			d.log.Error("upsert cloud asset", zap.Error(err))
		}
	}

	// Discover OT asset from plc_address / modbus source
	if event.Normalized.PlcAddress != "" {
		purdueLevel := d.clf.Classify("plc", event.Normalized.PlcAddress)
		a := &store.Asset{
			AssetID:      deterministicID(event.TenantID, event.Normalized.PlcAddress),
			TenantID:     event.TenantID,
			HostnameOrIP: event.Normalized.PlcAddress,
			IPAddresses:  []string{event.Normalized.PlcAddress},
			Domain:       store.DomainOT,
			PurdueLevel:  purdueLevel,
			AssetType:    "plc",
			FirstSeen:    now,
			LastSeen:     now,
			IsActive:     true,
		}
		if err := d.db.UpsertAsset(ctx, a); err != nil {
			d.log.Error("upsert OT asset", zap.Error(err))
		}
	}

	// Discover IT asset from src_ip
	if event.Normalized.SrcIP != "" && event.Normalized.SrcIP != "-" {
		purdueLevel := -1
		if domain == store.DomainOT {
			purdueLevel = d.clf.Classify("", event.Normalized.SrcIP)
		}
		a := &store.Asset{
			AssetID:      deterministicID(event.TenantID, event.Normalized.SrcIP),
			TenantID:     event.TenantID,
			HostnameOrIP: event.Normalized.SrcIP,
			IPAddresses:  []string{event.Normalized.SrcIP},
			Domain:       domain,
			PurdueLevel:  purdueLevel,
			FirstSeen:    now,
			LastSeen:     now,
			IsActive:     true,
		}
		if err := d.db.UpsertAsset(ctx, a); err != nil {
			d.log.Error("upsert src_ip asset", zap.Error(err))
		}
	}
}

// deterministicID generates a stable UUID v5-like ID from tenant + key.
func deterministicID(tenantID, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte(tenantID+":"+key)).String()
}
