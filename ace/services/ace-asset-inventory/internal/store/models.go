package store

import "time"

// AssetDomain classifies an asset by its operational domain.
type AssetDomain string

const (
	DomainIT    AssetDomain = "IT"
	DomainOT    AssetDomain = "OT"
	DomainCloud AssetDomain = "CLOUD"
)

// Asset is the canonical record for a network asset in the ACE platform.
type Asset struct {
	AssetID        string      `json:"asset_id"`          // UUIDv7
	TenantID       string      `json:"tenant_id"`
	HostnameOrIP   string      `json:"hostname_or_ip"`    // primary lookup key
	IPAddresses    []string    `json:"ip_addresses"`
	Hostnames      []string    `json:"hostnames"`
	MACs           []string    `json:"macs"`
	OSInfo         string      `json:"os_info"`
	AssetType      string      `json:"asset_type"`        // server, workstation, plc, hmi, ...
	Domain         AssetDomain `json:"domain"`
	PurdueLevel    int         `json:"purdue_level"`      // -1 = non-OT, 0–5 = Purdue level
	CloudProvider  string      `json:"cloud_provider"`
	CloudRegion    string      `json:"cloud_region"`
	CloudAccountID string      `json:"cloud_account_id"`
	ResourceARN    string      `json:"resource_arn"`
	Tags           []string    `json:"tags"`
	RiskScore      float64     `json:"risk_score"`
	FirstSeen      time.Time   `json:"first_seen"`
	LastSeen       time.Time   `json:"last_seen"`
	LastUpdated    time.Time   `json:"last_updated"`
	IsActive       bool        `json:"is_active"`
}
