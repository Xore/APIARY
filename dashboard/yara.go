package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
)

type yaraSample struct {
	SHA256    string   `json:"sha256"`
	ScannedAt string   `json:"scanned_at"`
	Error     string   `json:"error"`
	Source    string   `json:"source"`
	Size      int64    `json:"size"`
	Matches   []string `json:"matches"`
}

type yaraReport struct {
	UpdatedAt   string                `json:"updated_at"`
	Scanner     string                `json:"scanner"`
	RulesSHA256 string                `json:"rules_sha256"`
	Samples     map[string]yaraSample `json:"samples"`
	Errors      []string              `json:"errors"`
}

type yaraStatus struct {
	Enabled                  bool
	Updated                  string
	Samples, Matched, Errors int
}

func loadYARA(path string) yaraReport {
	if path == "" {
		return yaraReport{}
	}
	file, err := os.Open(path)
	if err != nil {
		return yaraReport{}
	}
	defer file.Close()
	var report yaraReport
	_ = json.NewDecoder(io.LimitReader(file, 32<<20)).Decode(&report)
	return report
}

func yaraSummary(path string) yaraStatus {
	report := loadYARA(path)
	status := yaraStatus{Enabled: path != "", Updated: report.UpdatedAt, Samples: len(report.Samples), Errors: len(report.Errors)}
	for _, sample := range report.Samples {
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
	if s.yaraFile == "" {
		return yaraSample{}
	}
	return loadYARA(s.yaraFile).Samples[strings.ToLower(hash)]
}

func (s *store) yaraForSHA(hash string) yaraSample {
	if s.yaraFile == "" {
		return yaraSample{}
	}
	for _, sample := range loadYARA(s.yaraFile).Samples {
		if strings.EqualFold(sample.SHA256, hash) {
			return sample
		}
	}
	return yaraSample{}
}
