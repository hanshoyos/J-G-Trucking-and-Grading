// Package purdue implements Purdue Model level classification for OT/ICS assets.
//
// Purdue Reference Model levels:
//   0 — Physical process (sensors, actuators, field devices)
//   1 — Control devices (PLCs, RTUs, PACs)
//   2 — Control systems (HMIs, SCADA workstations, engineering stations)
//   3 — Operations zone (Historian, MES, batch management servers)
//   4 — Business zone (ERP, site-level enterprise)
//   5 — Enterprise / DMZ (corporate IT, VPN, web servers)
//  -1 — Not an OT asset (IT or Cloud domain)
package purdue

import (
	"net"
	"strings"
)

// Classifier assigns Purdue Model levels to OT assets.
type Classifier struct {
	// Each element is a parsed CIDR for level 0–3 OT subnets.
	levelSubnets map[int][]*net.IPNet
}

// Config holds optional static subnet-to-level overrides.
type Config struct {
	Level0Subnets []string
	Level1Subnets []string
	Level2Subnets []string
	Level3Subnets []string
}

// NewClassifier creates a Classifier with optional subnet overrides.
func NewClassifier(cfg Config) *Classifier {
	c := &Classifier{levelSubnets: make(map[int][]*net.IPNet)}
	c.addSubnets(0, cfg.Level0Subnets)
	c.addSubnets(1, cfg.Level1Subnets)
	c.addSubnets(2, cfg.Level2Subnets)
	c.addSubnets(3, cfg.Level3Subnets)
	return c
}

func (c *Classifier) addSubnets(level int, cidrs []string) {
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			c.levelSubnets[level] = append(c.levelSubnets[level], ipnet)
		}
	}
}

// ClassifyByType infers the Purdue level from a human-readable asset type string.
// Returns -1 if the asset type is not OT-related.
func ClassifyByType(assetType string) int {
	lower := strings.ToLower(assetType)
	switch {
	// Level 0 — field devices
	case contains(lower, "sensor", "actuator", "valve", "transmitter", "field device"):
		return 0
	// Level 1 — control devices
	case contains(lower, "plc", "rtu", "pac", "programmable logic", "remote terminal"):
		return 1
	// Level 2 — control systems
	case contains(lower, "hmi", "scada", "dcs", "historian workstation", "engineering station"):
		return 2
	// Level 3 — operations zone
	case contains(lower, "historian", "mes", "batch server", "data server", "pi server"):
		return 3
	// Level 4 — business zone (usually IT)
	case contains(lower, "erp", "business server"):
		return 4
	// IT assets
	case contains(lower, "server", "workstation", "laptop", "desktop", "vm", "k8s", "pod",
		"container", "cloud"):
		return -1
	default:
		return -1
	}
}

// ClassifyByIP checks whether an IP falls in one of the configured OT subnets.
// Returns -1 if no subnet match.
func (c *Classifier) ClassifyByIP(ip string) int {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return -1
	}
	for level := 0; level <= 3; level++ {
		for _, subnet := range c.levelSubnets[level] {
			if subnet.Contains(parsed) {
				return level
			}
		}
	}
	return -1
}

// Classify determines the Purdue level for an asset, combining type-based
// and IP-based classification.  IP-based overrides type-based when a subnet
// match is found.
func (c *Classifier) Classify(assetType, ip string) int {
	// IP-based is most specific — check first.
	if ip != "" {
		if level := c.ClassifyByIP(ip); level >= 0 {
			return level
		}
	}
	// Fall back to type-based.
	return ClassifyByType(assetType)
}

func contains(s string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}
