package main

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// startFakeServicesAdapter serves handler over a real AF_UNIX socket and
// points SERVICES_ADAPTER_SOCKET at it, so these tests exercise the exact
// transport services_control.go uses in production (same dial, same
// schema-validation path) rather than mocking the client itself.
func startFakeServicesAdapter(t *testing.T, handler http.Handler) {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	t.Setenv("SERVICES_ADAPTER_SOCKET", socket)
}

func TestServicesAdapterSocketRejectsUnsafePaths(t *testing.T) {
	cases := []struct {
		name  string
		value string
		valid bool
	}{
		{"unset", "", false},
		{"relative", "run/control.sock", false},
		// filepath.Clean fully resolves a rooted ".." sequence before the
		// containment check ever runs (matching workbench_model_status.go's
		// identical validation) -- this exercises that behavior rather than
		// asserting a rejection that can't actually occur post-Clean.
		{"traversal resolved by Clean", "/run/services-adapter/../../etc/shadow", true},
		{"relative traversal stays relative", "../etc/shadow", false},
		{"valid absolute", "/run/services-adapter/control.sock", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SERVICES_ADAPTER_SOCKET", c.value)
			_, ok := servicesAdapterSocket()
			if ok != c.valid {
				t.Fatalf("servicesAdapterSocket(%q) ok = %v, want %v", c.value, ok, c.valid)
			}
		})
	}
}

func TestValidServiceStatusRequiresKnownStateAndName(t *testing.T) {
	if validServiceStatus(serviceStatus{Name: "", State: "running"}) {
		t.Fatal("empty name must be rejected")
	}
	if validServiceStatus(serviceStatus{Name: "hp-cowrie", State: "bogus"}) {
		t.Fatal("unknown state must be rejected")
	}
	if !validServiceStatus(serviceStatus{Name: "hp-cowrie", State: "running"}) {
		t.Fatal("a known state and non-empty name must be valid")
	}
}

func TestLoadServicesStatusUnavailableWhenSocketUnset(t *testing.T) {
	t.Setenv("SERVICES_ADAPTER_SOCKET", "")
	services, ok, reason := loadServicesStatus()
	if ok || services != nil || reason == "" {
		t.Fatalf("unset socket must report unavailable, got ok=%v services=%v reason=%q", ok, services, reason)
	}
}

func TestLoadServicesStatusParsesAdapterResponse(t *testing.T) {
	restartCount := 2
	exitCode := 0
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"services": []serviceStatus{
			{Name: "hp-cowrie", State: "running", Health: "healthy", ExitCode: &exitCode, StartedAt: "2026-08-01T00:00:00Z", RestartCount: &restartCount},
		}})
	}))
	services, ok, reason := loadServicesStatus()
	if !ok {
		t.Fatalf("expected success, got reason %q", reason)
	}
	if len(services) != 1 || services[0].Name != "hp-cowrie" || services[0].State != "running" {
		t.Fatalf("unexpected services: %#v", services)
	}
}

func TestLoadServicesStatusRejectsInvalidSchema(t *testing.T) {
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"services": []map[string]any{
			{"name": "hp-cowrie", "state": "not-a-real-state"},
		}})
	}))
	_, ok, reason := loadServicesStatus()
	if ok {
		t.Fatal("an unrecognized state must not be trusted")
	}
	if reason == "" {
		t.Fatal("a rejection must explain itself")
	}
}

func TestLoadServicesStatusRejectsNonJSONResponse(t *testing.T) {
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("not json"))
	}))
	_, ok, _ := loadServicesStatus()
	if ok {
		t.Fatal("a non-JSON response must not be trusted")
	}
}

func TestPerformServiceActionRejectsBadActionWithoutDialing(t *testing.T) {
	// No fake adapter started at all: if this dialed out, it would fail with
	// a connection error, not a clean 400 -- proving validation happens first.
	t.Setenv("SERVICES_ADAPTER_SOCKET", "/run/does-not-exist/control.sock")
	succeeded, status, _ := performServiceAction("hp-cowrie", "delete")
	if succeeded || status != http.StatusBadRequest {
		t.Fatalf("bad action: succeeded=%v status=%d, want false/400", succeeded, status)
	}
}

func TestPerformServiceActionSucceeds(t *testing.T) {
	var gotMethod, gotPath string
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "action": "restart", "name": "hp-cowrie"})
	}))
	succeeded, status, reason := performServiceAction("hp-cowrie", "restart")
	if !succeeded || status != http.StatusOK {
		t.Fatalf("succeeded=%v status=%d reason=%q, want true/200", succeeded, status, reason)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/services/hp-cowrie/restart" {
		t.Fatalf("adapter saw %s %s, want POST /v1/services/hp-cowrie/restart", gotMethod, gotPath)
	}
}

func TestPerformServiceActionForwardsAdapterRejection(t *testing.T) {
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "container not in allowlist"})
	}))
	succeeded, status, reason := performServiceAction("hp-elasticsearch", "restart")
	if succeeded || status != http.StatusForbidden || reason == "" {
		t.Fatalf("succeeded=%v status=%d reason=%q, want false/403/non-empty", succeeded, status, reason)
	}
}

func TestPerformServiceActionEscapesNameInRequestPath(t *testing.T) {
	// A literal "/" in name must reach the adapter as an escaped %2F on the
	// wire -- checked via RequestURI (the raw request-target), since Go's
	// http.Request.URL.Path is decoded back to slashes for routing purposes
	// on the server side and would give a false negative here.
	var gotRequestURI string
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "container not in allowlist"})
	}))
	performServiceAction("../../etc/passwd", "restart")
	if !strings.Contains(gotRequestURI, "%2F") {
		t.Fatalf("name containing '/' must be percent-escaped on the wire, got %q", gotRequestURI)
	}
}

func TestFetchServiceLogsClampsLinesAndReturnsContent(t *testing.T) {
	var gotLines string
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLines = r.URL.Query().Get("lines")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "hp-cowrie", "lines": 1000, "log": "line one\nline two\n"})
	}))
	log, status, reason := fetchServiceLogs("hp-cowrie", 999999)
	if status != http.StatusOK {
		t.Fatalf("status = %d, reason = %q", status, reason)
	}
	if log != "line one\nline two\n" {
		t.Fatalf("unexpected log content: %q", log)
	}
	if lines, _ := strconv.Atoi(gotLines); lines > maxServiceLogLines {
		t.Fatalf("adapter received unclamped lines=%s, want <= %d", gotLines, maxServiceLogLines)
	}
}

func TestFetchServiceLogsRejectsEmptyName(t *testing.T) {
	_, status, reason := fetchServiceLogs("", 200)
	if status != http.StatusBadRequest || reason == "" {
		t.Fatalf("empty name: status=%d reason=%q, want 400/non-empty", status, reason)
	}
}

func TestFetchServiceLogsEscapesNameInRequestPath(t *testing.T) {
	var gotRequestURI string
	startFakeServicesAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		w.WriteHeader(http.StatusNotFound)
	}))
	fetchServiceLogs("../../etc/passwd", 200)
	if !strings.Contains(gotRequestURI, "%2F") {
		t.Fatalf("name containing '/' must be percent-escaped on the wire, got %q", gotRequestURI)
	}
}
