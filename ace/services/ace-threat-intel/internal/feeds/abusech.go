package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	urlhausRecentURL    = "https://urlhaus.abuse.ch/downloads/json_recent/"
	malwareBazaarAPIURL = "https://mb-api.abuse.ch/api/v1/"
)

// ── URLhaus ───────────────────────────────────────────────────

type urlhausEntry struct {
	ID          string `json:"id"`
	DateAdded   string `json:"dateadded"`
	URL         string `json:"url"`
	URLStatus   string `json:"url_status"` // "online" | "offline"
	Threat      string `json:"threat"`
	Tags        string `json:"tags"`
}

// URLhausFeed fetches recent malicious URLs from URLhaus.
type URLhausFeed struct {
	client *http.Client
}

func NewURLhausFeed() *URLhausFeed {
	return &URLhausFeed{client: &http.Client{Timeout: 30 * time.Second}}
}

func (f *URLhausFeed) Name() string { return "abusech_urlhaus" }

func (f *URLhausFeed) FetchIOCs(ctx context.Context) ([]IOC, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlhausRecentURL, nil)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: build request: %w", err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: fetch: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: read: %w", err)
	}

	var entries []urlhausEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("urlhaus: parse: %w", err)
	}

	now := time.Now().UTC()
	iocs := make([]IOC, 0, len(entries))
	for _, e := range entries {
		if e.URLStatus != "online" {
			continue
		}
		added := now
		if t, err := time.Parse("2006-01-02 15:04:05", e.DateAdded); err == nil {
			added = t.UTC()
		}
		iocs = append(iocs, IOC{
			Type:        IOCTypeURL,
			Value:       e.URL,
			Source:      f.Name(),
			Severity:    SeverityHigh,
			Description: coalesce(e.Threat, "URLhaus malicious URL"),
			FirstSeen:   added,
			LastSeen:    now,
			Confidence:  0.85,
		})
	}
	return iocs, nil
}

// ── MalwareBazaar ─────────────────────────────────────────────

type mbResponse struct {
	QueryStatus string    `json:"query_status"`
	Data        []mbSample `json:"data"`
}

type mbSample struct {
	SHA256Hash  string   `json:"sha256_hash"`
	MD5Hash     string   `json:"md5_hash"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	Tags        []string `json:"tags"`
	Signature   string   `json:"signature"`
	FileType    string   `json:"file_type"`
}

// MalwareBazaarFeed fetches recent malware samples from MalwareBazaar.
type MalwareBazaarFeed struct {
	client *http.Client
}

func NewMalwareBazaarFeed() *MalwareBazaarFeed {
	return &MalwareBazaarFeed{client: &http.Client{Timeout: 30 * time.Second}}
}

func (f *MalwareBazaarFeed) Name() string { return "abusech_malware" }

func (f *MalwareBazaarFeed) FetchIOCs(ctx context.Context) ([]IOC, error) {
	body := []byte("query=get_recent&selector=time")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, malwareBazaarAPIURL,
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("malwarebazaar: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("malwarebazaar: fetch: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("malwarebazaar: read: %w", err)
	}

	var mbResp mbResponse
	if err := json.Unmarshal(data, &mbResp); err != nil {
		return nil, fmt.Errorf("malwarebazaar: parse: %w", err)
	}

	now := time.Now().UTC()
	iocs := make([]IOC, 0, len(mbResp.Data)*2)
	for _, s := range mbResp.Data {
		firstSeen := now
		if t, err := time.Parse("2006-01-02 15:04:05", s.FirstSeen); err == nil {
			firstSeen = t.UTC()
		}
		desc := coalesce(s.Signature, "MalwareBazaar sample")

		if s.SHA256Hash != "" {
			iocs = append(iocs, IOC{
				Type:        IOCTypeSHA256,
				Value:       s.SHA256Hash,
				Source:      f.Name(),
				Severity:    SeverityHigh,
				Description: desc,
				Tags:        s.Tags,
				FirstSeen:   firstSeen,
				LastSeen:    now,
				Confidence:  0.90,
			})
		}
		if s.MD5Hash != "" {
			iocs = append(iocs, IOC{
				Type:        IOCTypeHashMD5,
				Value:       s.MD5Hash,
				Source:      f.Name(),
				Severity:    SeverityHigh,
				Description: desc,
				Tags:        s.Tags,
				FirstSeen:   firstSeen,
				LastSeen:    now,
				Confidence:  0.85,
			})
		}
	}
	return iocs, nil
}
