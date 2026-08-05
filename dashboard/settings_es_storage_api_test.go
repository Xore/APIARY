package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func fakeESStorageStatsServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/_cluster/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "green", "number_of_data_nodes": 1})
		case "/_stats/store,docs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"indices": map[string]any{"honeypot-v2-2026.08.06": map[string]any{}, "suricata-v2-alert-2026.08.06": map[string]any{}},
				"_all": map[string]any{"total": map[string]any{
					"docs":  map[string]any{"count": 12345},
					"store": map[string]any{"size_in_bytes": 987654321},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestServeSettingsESStorageStatsRejectsNonAdminAndAnonymous(t *testing.T) {
	nonAdmin := newSettingsAPITestStore(t, "user")
	response := httptest.NewRecorder()
	nonAdmin.serveSettingsESStorageStats(response, settingsRequest(t, http.MethodGet, "/api/settings/es-storage-stats", true, ""))
	if response.Code != http.StatusForbidden {
		t.Fatalf("user role: status = %d, want 403", response.Code)
	}

	admin := newSettingsAPITestStore(t, "admin")
	response = httptest.NewRecorder()
	admin.serveSettingsESStorageStats(response, httptest.NewRequest(http.MethodGet, "/api/settings/es-storage-stats", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: status = %d, want 401", response.Code)
	}
}

func TestServeSettingsESStorageStatsRejectsNonGET(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	s.serveSettingsESStorageStats(response, settingsRequest(t, http.MethodPost, "/api/settings/es-storage-stats", true, ""))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status = %d, want 405", response.Code)
	}
}

func TestServeSettingsESStorageStatsReturnsSummary(t *testing.T) {
	es := fakeESStorageStatsServer(t)
	defer es.Close()
	s := newSettingsAPITestStore(t, "admin")
	s.es = newESClient(es.URL, "")

	response := httptest.NewRecorder()
	s.serveSettingsESStorageStats(response, settingsRequest(t, http.MethodGet, "/api/settings/es-storage-stats", false, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed struct {
		Available bool           `json:"available"`
		Stats     esStorageStats `json:"stats"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v (body %s)", err, response.Body.String())
	}
	if !parsed.Available {
		t.Fatal("expected available=true")
	}
	if parsed.Stats.ClusterStatus != "green" || parsed.Stats.DataNodes != 1 {
		t.Fatalf("cluster fields = %+v", parsed.Stats)
	}
	if parsed.Stats.IndexCount != 2 {
		t.Fatalf("index_count = %d, want 2", parsed.Stats.IndexCount)
	}
	if parsed.Stats.DocCount != 12345 {
		t.Fatalf("doc_count = %d, want 12345", parsed.Stats.DocCount)
	}
	if parsed.Stats.StoreSizeBytes != 987654321 {
		t.Fatalf("store_size_bytes = %d, want 987654321", parsed.Stats.StoreSizeBytes)
	}
}

func TestServeSettingsESStorageStatsHandlesDisabledES(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	// s.es stays nil -- Elasticsearch integration disabled, same convention
	// serveSettingsServices' "adapter unavailable" branch uses.
	response := httptest.NewRecorder()
	s.serveSettingsESStorageStats(response, settingsRequest(t, http.MethodGet, "/api/settings/es-storage-stats", false, ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	var parsed struct{ Available bool }
	_ = json.Unmarshal(response.Body.Bytes(), &parsed)
	if parsed.Available {
		t.Fatal("expected available=false when s.es is nil")
	}
}

func TestServeSettingsESStorageStatsHandlesUpstreamError(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	s.es = newESClient("http://127.0.0.1:1", "") // nothing listening
	response := httptest.NewRecorder()
	s.serveSettingsESStorageStats(response, settingsRequest(t, http.MethodGet, "/api/settings/es-storage-stats", false, ""))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.Code)
	}
	var parsed struct{ Available bool }
	_ = json.Unmarshal(response.Body.Bytes(), &parsed)
	if parsed.Available {
		t.Fatal("expected available=false on upstream failure")
	}
}
