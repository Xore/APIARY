package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func servicesRequest(t *testing.T, s *store, method, target string, sameOrigin bool) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := settingsRequest(t, method, target, sameOrigin, "")
	if target == "/api/settings/services" {
		s.serveSettingsServices(response, request)
	} else {
		s.serveSettingsServiceItem(response, request)
	}
	return response
}

func TestServicesEndpointsRejectNonAdminAndAnonymous(t *testing.T) {
	targets := []struct{ method, target string }{
		{http.MethodGet, "/api/settings/services"},
		{http.MethodPost, "/api/settings/services/hp-cowrie/restart"},
		{http.MethodGet, "/api/settings/services/hp-cowrie/logs"},
	}
	nonAdmin := newSettingsAPITestStore(t, "user")
	for _, target := range targets {
		response := servicesRequest(t, nonAdmin, target.method, target.target, true)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s with user role: status = %d, want 403", target.method, target.target, response.Code)
		}
	}
	admin := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	admin.serveSettingsServices(response, httptest.NewRequest(http.MethodGet, "/api/settings/services", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous services read: status = %d, want 401", response.Code)
	}
}

func TestServeSettingsServicesReturnsAdapterData(t *testing.T) {
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"services": []serviceStatus{
			{Name: "hp-cowrie", State: "running"},
		}})
	}))
	s := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	s.serveSettingsServices(response, settingsRequest(t, http.MethodGet, "/api/settings/services", false, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed struct {
		Available bool            `json:"available"`
		Services  []serviceStatus `json:"services"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Available || len(parsed.Services) != 1 || parsed.Services[0].Name != "hp-cowrie" {
		t.Fatalf("unexpected response: %#v", parsed)
	}
}

func TestServeSettingsServicesReportsUnavailable(t *testing.T) {
	t.Setenv("SERVICES_ADAPTER_SOCKET", "")
	s := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	s.serveSettingsServices(response, settingsRequest(t, http.MethodGet, "/api/settings/services", false, ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	var parsed struct {
		Available bool `json:"available"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Available {
		t.Fatal("must report available=false when the adapter isn't configured")
	}
}

func TestServeSettingsServiceActionRequiresSameOrigin(t *testing.T) {
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "action": "restart", "name": "hp-cowrie"})
	}))
	s := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	request := settingsRequest(t, http.MethodPost, "/api/settings/services/hp-cowrie/restart", false, "")
	s.serveSettingsServiceItem(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin action: status = %d, want 403", response.Code)
	}
}

func TestServeSettingsServiceActionSucceedsAndAudits(t *testing.T) {
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "action": "restart", "name": "hp-cowrie"})
	}))
	s := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	request := settingsRequest(t, http.MethodPost, "/api/settings/services/hp-cowrie/restart", true, "")
	s.serveSettingsServiceItem(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	events := s.settings.audit.read(10)
	if len(events) == 0 || events[0].Action != "services.restart" || events[0].Result != "success" {
		t.Fatalf("action must be audited: %#v", events)
	}
	if !containsString(events[0].Fields, "hp-cowrie") {
		t.Fatalf("audit fields must record the target container: %#v", events[0].Fields)
	}
}

func TestServeSettingsServiceActionReportsAdapterFailure(t *testing.T) {
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "container not in allowlist"})
	}))
	s := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	request := settingsRequest(t, http.MethodPost, "/api/settings/services/hp-elasticsearch/restart", true, "")
	s.serveSettingsServiceItem(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	events := s.settings.audit.read(10)
	if len(events) == 0 || events[0].Result != "error" {
		t.Fatalf("a rejected action must be audited as an error: %#v", events)
	}
}

func TestServeSettingsServiceItemRejectsMalformedPath(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	request := settingsRequest(t, http.MethodPost, "/api/settings/services/hp-cowrie", true, "")
	s.serveSettingsServiceItem(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("path with no action segment: status = %d, want 404", response.Code)
	}
}

func TestServeSettingsServiceLogsClampsAndReturnsText(t *testing.T) {
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "hp-cowrie", "lines": 500, "log": "hello\n"})
	}))
	s := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	request := settingsRequest(t, http.MethodGet, "/api/settings/services/hp-cowrie/logs?lines=99999999", false, "")
	s.serveSettingsServiceItem(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed struct {
		Log string `json:"log"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Log != "hello\n" {
		t.Fatalf("unexpected log body: %#v", parsed)
	}
}

// A GET on the logs route must never require the same-origin/write guard --
// it's read-only, exactly like every other GET in this settings API.
func TestServeSettingsServiceLogsDoesNotRequireSameOrigin(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "hp-cowrie", "lines": 200, "log": ""})
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	t.Setenv("SERVICES_ADAPTER_SOCKET", socket)

	s := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	request := settingsRequest(t, http.MethodGet, "/api/settings/services/hp-cowrie/logs", false, "")
	s.serveSettingsServiceItem(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}
