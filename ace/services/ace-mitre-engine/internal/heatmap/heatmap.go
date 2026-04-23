// Package heatmap generates MITRE ATT&CK Navigator-compatible layer JSON
// from a technique coverage map produced by the store.
package heatmap

import "math"

// Layer is a MITRE ATT&CK Navigator layer.
type Layer struct {
	Name        string      `json:"name"`
	Versions    Versions    `json:"versions"`
	Domain      string      `json:"domain"`
	Description string      `json:"description"`
	Techniques  []Technique `json:"techniques"`
	Gradient    Gradient    `json:"gradient"`
	ShowTacticRowBackground bool `json:"showTacticRowBackground"`
	TacticRowBackground     string `json:"tacticRowBackground"`
}

// Versions records the Navigator / ATT&CK version compatibility.
type Versions struct {
	Layer  string `json:"layer"`
	ATTaCK string `json:"attack"`
}

// Technique entry in the navigator layer.
type Technique struct {
	TechniqueID  string  `json:"techniqueID"`
	Score        float64 `json:"score"`
	Color        string  `json:"color,omitempty"`
	Comment      string  `json:"comment,omitempty"`
	Enabled      bool    `json:"enabled"`
	ShowSubtechniques bool `json:"showSubtechniques"`
}

// Gradient defines a colour scale for scores 0→maxScore.
type Gradient struct {
	Colors   []string `json:"colors"`
	MinValue float64  `json:"minValue"`
	MaxValue float64  `json:"maxValue"`
}

// Generate builds a Navigator layer from a coverage map (technique_id → seen_count).
// domain should be "enterprise-attack" or "ics-attack".
func Generate(coverage map[string]int, domain string) Layer {
	maxScore := maxCount(coverage)
	if maxScore < 1 {
		maxScore = 1
	}

	techniques := make([]Technique, 0, len(coverage))
	for id, count := range coverage {
		score := math.Round(float64(count)/float64(maxScore)*100) / 100 * 100
		techniques = append(techniques, Technique{
			TechniqueID:       id,
			Score:             score,
			Enabled:           true,
			ShowSubtechniques: true,
			Comment:           commentForCount(count),
		})
	}

	return Layer{
		Name:        "ACE Platform Coverage",
		Versions:    Versions{Layer: "4.5", ATTaCK: "16"},
		Domain:      domain,
		Description: "Techniques observed by the ACE Platform correlation engine",
		Techniques:  techniques,
		Gradient: Gradient{
			Colors:   []string{"#ffffff", "#ff6666"},
			MinValue: 0,
			MaxValue: 100,
		},
		ShowTacticRowBackground: true,
		TacticRowBackground:     "#dddddd",
	}
}

func maxCount(m map[string]int) int {
	max := 0
	for _, v := range m {
		if v > max {
			max = v
		}
	}
	return max
}

func commentForCount(count int) string {
	switch {
	case count >= 100:
		return "Frequently observed"
	case count >= 10:
		return "Regularly observed"
	case count >= 3:
		return "Occasionally observed"
	default:
		return "Rarely observed"
	}
}
