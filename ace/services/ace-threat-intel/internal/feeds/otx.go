package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const otxBaseURL = "https://otx.alienvault.com/api/v1"

type otxPulseList struct {
	Count   int        `json:"count"`
	Results []otxPulse `json:"results"`
	Next    string     `json:"next"`
}

type otxPulse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Tags        []string       `json:"tags"`
	Indicators  []otxIndicator `json:"indicators"`
	Modified    time.Time      `json:"modified"`
	Created     time.Time      `json:"created"`
}

type otxIndicator struct {
	Indicator   string `json:"indicator"`
	Type        string `json:"type"`  // "IPv4", "domain", "URL", "FileHash-MD5", "FileHash-SHA256"
	Description string `json:"description"`
}

// OTXFeed fetches threat indicators from AlienVault OTX subscribed pulses.
type OTXFeed struct {
	apiKey string
	client *http.Client
}

// NewOTXFeed constructs an OTX feed. If apiKey is empty the feed is a no-op.
func NewOTXFeed(apiKey string) *OTXFeed {
	return &OTXFeed{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *OTXFeed) Name() string { return "otx" }

// FetchIOCs downloads subscribed pulse indicators from OTX.
func (f *OTXFeed) FetchIOCs(ctx context.Context) ([]IOC, error) {
	if f.apiKey == "" {
		return nil, nil // no key configured — silently skip
	}

	url := otxBaseURL + "/pulses/subscribed?limit=50"
	var allIOCs []IOC

	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("otx: build request: %w", err)
		}
		req.Header.Set("X-OTX-API-KEY", f.apiKey)

		resp, err := f.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("otx: fetch: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("otx: unexpected status %d", resp.StatusCode)
		}

		var list otxPulseList
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("otx: parse: %w", err)
		}

		now := time.Now().UTC()
		for _, pulse := range list.Results {
			for _, ind := range pulse.Indicators {
				iocType := mapOTXType(ind.Type)
				if iocType == "" {
					continue
				}
				allIOCs = append(allIOCs, IOC{
					Type:        iocType,
					Value:       ind.Indicator,
					Source:      f.Name(),
					Severity:    SeverityMedium,
					Description: coalesce(ind.Description, pulse.Name),
					Tags:        pulse.Tags,
					FirstSeen:   pulse.Created,
					LastSeen:    now,
					Confidence:  0.7,
				})
			}
		}

		url = list.Next
		if len(list.Results) == 0 {
			break
		}
	}
	return allIOCs, nil
}

func mapOTXType(t string) IOCType {
	switch t {
	case "IPv4", "IPv6":
		return IOCTypeIP
	case "domain", "hostname":
		return IOCTypeDomain
	case "URL":
		return IOCTypeURL
	case "FileHash-MD5":
		return IOCTypeHashMD5
	case "FileHash-SHA256":
		return IOCTypeSHA256
	default:
		return ""
	}
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
