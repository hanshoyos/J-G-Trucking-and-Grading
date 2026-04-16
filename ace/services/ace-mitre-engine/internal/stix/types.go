package stix

import "time"

// STIXBundle represents a STIX 2.1 bundle containing heterogeneous objects.
type STIXBundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []interface{} `json:"objects"`
}

// AttackPattern represents a STIX 2.1 attack-pattern object corresponding
// to a MITRE ATT&CK technique or sub-technique.
type AttackPattern struct {
	Type              string           `json:"type"` // "attack-pattern"
	ID                string           `json:"id"`
	SpecVersion       string           `json:"spec_version"`
	Name              string           `json:"name"`
	Description       string           `json:"description"`
	ExternalReferences []ExternalRef   `json:"external_references"`
	KillChainPhases   []KillChainPhase `json:"kill_chain_phases"`
	XMitreDetection   string           `json:"x_mitre_detection"`
	XMitrePlatforms   []string         `json:"x_mitre_platforms"`
	XMitreDataSources []string         `json:"x_mitre_data_sources"`
	XMitreIsSubtechnique bool          `json:"x_mitre_is_subtechnique"`
	XMitreDeprecated  bool             `json:"x_mitre_deprecated"`
	Modified          time.Time        `json:"modified"`
	Created           time.Time        `json:"created"`
}

// ExternalRef holds an external reference attached to a STIX object.
type ExternalRef struct {
	SourceName  string `json:"source_name"`
	ExternalID  string `json:"external_id"` // e.g. "T1078"
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// KillChainPhase represents a phase in a kill-chain (ATT&CK tactic).
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// MitreSourceName is the source_name used in external_references for MITRE ATT&CK entries.
const MitreSourceName = "mitre-attack"

// EnterpriseURL is the URL for the MITRE ATT&CK Enterprise STIX bundle.
const EnterpriseURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

// ICSAttackURL is the URL for the MITRE ATT&CK ICS STIX bundle.
const ICSAttackURL = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
