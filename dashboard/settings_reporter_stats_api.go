package main

// settings_reporter_stats_api.go — #666: the Honeypot operations pane's
// brief Reports sent glance (attempted/suppressed/dry-run/sent/failed),
// mirroring reporter/metrics.go's own counters. Per #638, ES is the only
// path here: es-results-importer mirrors reporter's metrics.json into
// reporter-metrics-v1 (docker-compose.dashboard.yml), this reads that index
// only -- the dashboard never mounts the reporter's own data volume.
// Same admin guard as the rest of the settings surface
// (settings_admin_api.go's adminSettingsIdentity).
//
//	GET /api/settings/reporter-stats

import (
	"encoding/json"
	"net/http"
)

type reporterStats struct {
	Attempted           int64  `json:"attempted"`
	SuppressedCooldown  int64  `json:"suppressed_cooldown"`
	SuppressedGreynoise int64  `json:"suppressed_greynoise"`
	DryRun              int64  `json:"dry_run"`
	Sent                int64  `json:"sent"`
	Failed              int64  `json:"failed"`
	UpdatedAt           string `json:"updated_at"`
}

func (s *store) serveSettingsReporterStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if s.es == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "reason": "Elasticsearch integration disabled"})
		return
	}
	hits, err := s.es.docSearchAll("reporter-metrics-v1", 1)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "reason": err.Error()})
		return
	}
	if len(hits) == 0 {
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "reason": "no reporter metrics indexed yet"})
		return
	}
	var doc struct {
		ReporterMetrics reporterStats `json:"reporter_metrics"`
	}
	if err := json.Unmarshal(hits[0].Source, &doc); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "reason": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"available": true, "stats": doc.ReporterMetrics})
}
