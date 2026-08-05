package main

// settings_es_storage_api.go — the Elasticsearch pane's brief storage-stats
// glance (#647): cluster status, index count, document count, and store
// size, alongside the existing free-text history search already in that
// pane. Same admin guard as the rest of the settings surface
// (settings_admin_api.go's adminSettingsIdentity).
//
//	GET /api/settings/es-storage-stats

import (
	"encoding/json"
	"net/http"
)

func (s *store) serveSettingsESStorageStats(w http.ResponseWriter, r *http.Request) {
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
	stats, err := s.es.storageStats()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "reason": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"available": true, "stats": stats})
}
