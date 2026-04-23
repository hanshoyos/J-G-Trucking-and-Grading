package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TAXIIFeed is a STIX/TAXII 2.1 client that fetches indicator objects
// from a configurable collection endpoint.
type TAXIIFeed struct {
	serverURL  string
	collection string
	username   string
	password   string
	client     *http.Client
}

// NewTAXIIFeed constructs a TAXII feed. serverURL and collection must be non-empty
// for the feed to do anything useful.
func NewTAXIIFeed(serverURL, collection, username, password string) *TAXIIFeed {
	return &TAXIIFeed{
		serverURL:  serverURL,
		collection: collection,
		username:   username,
		password:   password,
		client:     &http.Client{Timeout: 60 * time.Second},
	}
}

func (f *TAXIIFeed) Name() string { return "taxii" }

// TAXII 2.1 envelope response.
type taxiiEnvelope struct {
	More    bool              `json:"more"`
	Objects []json.RawMessage `json:"objects"`
}

// STIX 2.1 indicator (minimal fields we care about).
type stixIndicator struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Pattern   string `json:"pattern"`
	Labels    []string `json:"labels"`
	Created   time.Time `json:"created"`
	Modified  time.Time `json:"modified"`
	ValidFrom time.Time `json:"valid_from"`
}

// FetchIOCs retrieves indicator objects from the configured TAXII collection.
func (f *TAXIIFeed) FetchIOCs(ctx context.Context) ([]IOC, error) {
	if f.serverURL == "" || f.collection == "" {
		return nil, nil // not configured — skip silently
	}

	url := fmt.Sprintf("%s/collections/%s/objects/?match[type]=indicator",
		f.serverURL, f.collection)

	var allIOCs []IOC
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("taxii: build request: %w", err)
		}
		req.Header.Set("Accept", "application/taxii+json;version=2.1")
		if f.username != "" {
			req.SetBasicAuth(f.username, f.password)
		}

		resp, err := f.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("taxii: fetch: %w", err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("taxii: status %d", resp.StatusCode)
		}

		var envelope taxiiEnvelope
		if err := json.Unmarshal(data, &envelope); err != nil {
			return nil, fmt.Errorf("taxii: parse envelope: %w", err)
		}

		now := time.Now().UTC()
		for _, raw := range envelope.Objects {
			var ind stixIndicator
			if err := json.Unmarshal(raw, &ind); err != nil || ind.Type != "indicator" {
				continue
			}
			iocType, value := extractFromPattern(ind.Pattern)
			if iocType == "" {
				continue
			}
			allIOCs = append(allIOCs, IOC{
				Type:       iocType,
				Value:      value,
				Source:     f.Name(),
				Severity:   SeverityMedium,
				Tags:       ind.Labels,
				FirstSeen:  ind.ValidFrom,
				LastSeen:   now,
				Confidence: 0.75,
			})
		}

		if !envelope.More {
			break
		}
		// In a full implementation, follow pagination headers.
		// For Phase 2, stop after first page.
		break
	}
	return allIOCs, nil
}

// extractFromPattern extracts an IOC type and value from a simple STIX pattern like:
//   [ipv4-addr:value = '1.2.3.4']
//   [domain-name:value = 'evil.example.com']
//   [file:hashes.SHA-256 = 'abc...']
func extractFromPattern(pattern string) (IOCType, string) {
	for _, candidate := range []struct {
		prefix  string
		iocType IOCType
	}{
		{"[ipv4-addr:value = '", IOCTypeIP},
		{"[ipv6-addr:value = '", IOCTypeIP},
		{"[domain-name:value = '", IOCTypeDomain},
		{"[url:value = '", IOCTypeURL},
		{"[file:hashes.'SHA-256' = '", IOCTypeSHA256},
		{"[file:hashes.MD5 = '", IOCTypeHashMD5},
	} {
		start := len(candidate.prefix)
		if len(pattern) <= start {
			continue
		}
		if pattern[:start] == candidate.prefix {
			end := len(pattern) - 2 // strip ']' and "'"
			if end > start {
				return candidate.iocType, pattern[start:end]
			}
		}
	}
	return "", ""
}
