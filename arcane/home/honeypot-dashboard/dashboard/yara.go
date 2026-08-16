package main

import (
	"encoding/json"
	"strings"
)

type yaraSample struct {
	SHA256    string   `json:"sha256"`
	ScannedAt string   `json:"scanned_at"`
	Error     string   `json:"error"`
	Source    string   `json:"source"`
	Size      int64    `json:"size"`
	Matches   []string `json:"matches"`
	// ReportUpdatedAt is analysis/yara/scanner.py's own results.json
	// updated_at, riding along on every sample document -- see
	// es-results-importer's "yara" source (importer.py) for why: it reads
	// one aggregate file covering every scanned sample and explodes it
	// into one ES document per sample, and this loader only ever fetches
	// the yara-analysis-v1 mirror's "yara" sub-object (searchNamespace's
	// one-field contract, same as every other ES-backed loader here), so
	// this is the only way "when was this last scanned" survives the trip.
	ReportUpdatedAt string `json:"report_updated_at"`
}

type yaraStatus struct {
	Enabled                  bool
	Updated                  string
	Samples, Matched, Errors int
}

// loadYaraSamplesES reads the yara-analysis-v1 ES mirror exclusively
// (#1103 Category 4) -- see loadGhidraResults' doc comment in ghidra.go for
// the reasoning. analysis/yara/scanner.py is deliberately "networkless"
// (its own module docstring) and must stay that way: scanning
// attacker-supplied samples with a scanner that cannot reach the network at
// all is a real security boundary, so mirroring into ES is
// es-results-importer's job, never the scanner's own.
func loadYaraSamplesES(es *esClient) (map[string]yaraSample, bool) {
	if es == nil {
		return nil, false
	}
	raws, err := es.searchNamespace("yara-analysis-v1", "yara")
	if err != nil {
		return nil, false
	}
	samples := make(map[string]yaraSample, len(raws))
	for _, raw := range raws {
		var row yaraSample
		if json.Unmarshal(raw, &row) != nil || !hashName.MatchString(row.SHA256) {
			continue
		}
		samples[strings.ToLower(row.SHA256)] = row
	}
	return samples, true
}

func yaraSummary(es *esClient) yaraStatus {
	samples, ok := loadYaraSamplesES(es)
	status := yaraStatus{Enabled: ok, Samples: len(samples)}
	for _, sample := range samples {
		if sample.ScannedAt > status.Updated {
			status.Updated = sample.ScannedAt
		}
		if sample.ReportUpdatedAt > status.Updated {
			status.Updated = sample.ReportUpdatedAt
		}
		if len(sample.Matches) > 0 {
			status.Matched++
		}
		if sample.Error != "" {
			status.Errors++
		}
	}
	return status
}

func (s *store) yaraFor(hash string) yaraSample {
	if s.es == nil {
		return yaraSample{}
	}
	samples, _ := loadYaraSamplesES(s.es)
	return samples[strings.ToLower(hash)]
}

func (s *store) yaraForSHA(hash string) yaraSample {
	return s.yaraFor(hash)
}
