package stix

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ParseBundle parses a raw STIX 2.1 JSON bundle and returns all attack-pattern objects.
// Objects that are not attack-patterns or that are deprecated are included unless they
// set XMitreDeprecated=true (callers may filter those out as needed).
func ParseBundle(data []byte) ([]AttackPattern, error) {
	// We unmarshal into a raw bundle first where objects are json.RawMessage
	// so we can peek at the "type" field before full unmarshaling.
	var rawBundle struct {
		Type    string            `json:"type"`
		ID      string            `json:"id"`
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(data, &rawBundle); err != nil {
		return nil, fmt.Errorf("stix: unmarshal bundle: %w", err)
	}

	var patterns []AttackPattern
	for _, rawObj := range rawBundle.Objects {
		// Peek at the type field.
		var typePeek struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rawObj, &typePeek); err != nil {
			continue
		}
		if typePeek.Type != "attack-pattern" {
			continue
		}
		var ap AttackPattern
		if err := json.Unmarshal(rawObj, &ap); err != nil {
			continue
		}
		patterns = append(patterns, ap)
	}
	return patterns, nil
}

// FetchAndParse retrieves a STIX bundle from the given URL (with a 60-second
// timeout) and returns the parsed attack-pattern objects.
func FetchAndParse(ctx context.Context, url string) ([]AttackPattern, error) {
	client := &http.Client{Timeout: 60 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("stix: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stix: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stix: fetch %s: unexpected status %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("stix: read body: %w", err)
	}

	return ParseBundle(data)
}

// TechniqueID extracts the canonical ATT&CK technique ID (e.g. "T1078") from
// the ExternalReferences slice. Returns "" if no MITRE reference is found.
func (ap *AttackPattern) TechniqueID() string {
	for _, ref := range ap.ExternalReferences {
		if ref.SourceName == MitreSourceName && ref.ExternalID != "" {
			return ref.ExternalID
		}
	}
	return ""
}

// PrimaryTactic returns the first tactic associated with the technique, or "".
func (ap *AttackPattern) PrimaryTactic() string {
	for _, kcp := range ap.KillChainPhases {
		if kcp.KillChainName == "mitre-attack" || kcp.KillChainName == "mitre-ics-attack" {
			return kcp.PhaseName
		}
	}
	return ""
}
