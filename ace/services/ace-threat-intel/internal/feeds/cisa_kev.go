package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const cisaKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// cisaKEVPayload matches the CISA KEV catalog JSON schema.
type cisaKEVPayload struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []cisaVuln      `json:"vulnerabilities"`
}

type cisaVuln struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse"`
}

// CISAKEVFeed fetches the CISA Known Exploited Vulnerabilities catalog.
type CISAKEVFeed struct {
	client *http.Client
}

// NewCISAKEVFeed constructs a CISA KEV feed with a sensible default HTTP client.
func NewCISAKEVFeed() *CISAKEVFeed {
	return &CISAKEVFeed{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *CISAKEVFeed) Name() string { return "cisa_kev" }

// FetchIOCs downloads and parses the CISA KEV catalog, returning one IOC per CVE.
func (f *CISAKEVFeed) FetchIOCs(ctx context.Context) ([]IOC, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cisaKEVURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cisa_kev: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cisa_kev: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cisa_kev: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cisa_kev: read body: %w", err)
	}

	var payload cisaKEVPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("cisa_kev: parse: %w", err)
	}

	now := time.Now().UTC()
	iocs := make([]IOC, 0, len(payload.Vulnerabilities))
	for _, v := range payload.Vulnerabilities {
		added := now
		if t, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
			added = t
		}

		sev := SeverityHigh
		if v.KnownRansomware == "Known" {
			sev = SeverityCritical
		}

		desc := v.VulnerabilityName
		if v.ShortDescription != "" {
			desc = v.ShortDescription
		}

		iocs = append(iocs, IOC{
			Type:          IOCTypeCVE,
			Value:         v.CVEID,
			Source:        f.Name(),
			Severity:      sev,
			Description:   desc,
			Tags:          []string{"kev", "cisa", v.VendorProject},
			FirstSeen:     added,
			LastSeen:      now,
			Confidence:    1.0,
			VendorProject: v.VendorProject,
			Product:       v.Product,
		})
	}
	return iocs, nil
}
