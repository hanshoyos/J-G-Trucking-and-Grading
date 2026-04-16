// Package feeds defines the Feed interface and shared IOC type used by all
// threat intelligence feed adapters.
package feeds

import (
	"context"
	"time"
)

// IOCType classifies an indicator of compromise.
type IOCType string

const (
	IOCTypeIP        IOCType = "ip"
	IOCTypeDomain    IOCType = "domain"
	IOCTypeURL       IOCType = "url"
	IOCTypeHashMD5   IOCType = "hash_md5"
	IOCTypeSHA256    IOCType = "hash_sha256"
	IOCTypeCVE       IOCType = "cve"
	IOCTypeEmail     IOCType = "email"
)

// Severity of an IOC.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// IOC is a single indicator of compromise from any feed source.
type IOC struct {
	Type        IOCType   `json:"type"`
	Value       string    `json:"value"`
	Source      string    `json:"source"`      // feed name
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Confidence  float64   `json:"confidence"` // 0.0–1.0
	// CVE-specific
	VendorProject string `json:"vendor_project,omitempty"`
	Product       string `json:"product,omitempty"`
}

// Feed is the interface every threat-intel adapter must implement.
type Feed interface {
	Name() string
	FetchIOCs(ctx context.Context) ([]IOC, error)
}

// FeedStatus captures the last sync result for a feed.
type FeedStatus struct {
	Name      string    `json:"name"`
	LastSync  time.Time `json:"last_sync"`
	IOCsAdded int       `json:"iocs_added"`
	Error     string    `json:"error,omitempty"`
}
