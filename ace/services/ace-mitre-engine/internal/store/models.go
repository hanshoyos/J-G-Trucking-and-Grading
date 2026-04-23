package store

import "time"

// Technique represents a MITRE ATT&CK technique or sub-technique as stored
// in the mitre_techniques PostgreSQL table.
type Technique struct {
	TechniqueID    string    `json:"technique_id"`     // "T1078"
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Tactic         string    `json:"tactic"`           // primary tactic phase name
	Framework      string    `json:"framework"`        // "enterprise" | "ics"
	IsSubtechnique bool      `json:"is_subtechnique"`
	ParentID       string    `json:"parent_id"`        // "T1078" when this is T1078.001
	Platforms      []string  `json:"platforms"`
	DataSources    []string  `json:"data_sources"`
	URL            string    `json:"url"`
	FirstSeen      *time.Time `json:"first_seen,omitempty"`
	LastSeen       *time.Time `json:"last_seen,omitempty"`
	SeenCount      int       `json:"seen_count"`
	UpdatedAt      time.Time `json:"updated_at"`
}
