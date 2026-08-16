package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #1103 Category 2: buildViaMap moved from reading the local portbridge
// connlog to querying portbridge-v2-* directly. These are buildViaMap's own
// dedicated unit tests -- previously it was only ever exercised indirectly
// through tunnel_peer_test.go/p0f_fingerprint_test.go's higher-level
// rebuild() tests.

// portbridgeSearchStub wraps docs under _source.portbridge, in the exact
// order given -- callers control ordering directly rather than this stub
// simulating a real timestamp sort, since buildViaMap's correctness depends
// on processing oldest-first (see its own doc comment).
func portbridgeSearchStub(t *testing.T, docs []map[string]any, gotPaths *[]string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "_pit") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"id": "test-pit-id"})
			return
		}
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "_pit") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"succeeded": true})
			return
		}

		body, _ := io.ReadAll(r.Body)
		*gotPaths = append(*gotPaths, string(body))

		type hit struct {
			Source struct {
				Portbridge map[string]any `json:"portbridge"`
			} `json:"_source"`
		}
		hits := make([]hit, 0, len(docs))
		for _, d := range docs {
			var h hit
			h.Source.Portbridge = d
			hits = append(hits, h)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	}
}

func TestBuildViaMapQueriesPortbridgeIndexAscending(t *testing.T) {
	var gotPaths []string
	docs := []map[string]any{
		{"sensor": "portbridge", "src_ip": "203.0.113.9", "os": "Linux 3.11 and newer", "via_port": 41001.0, "port": 445.0},
	}
	var gotPITPath string
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "_pit") {
			gotPITPath = r.URL.Path
		}
		portbridgeSearchStub(t, docs, &gotPaths)(w, r)
	}))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	m, osByIP := s.buildViaMap()

	if !strings.HasPrefix(gotPITPath, "/portbridge-") {
		t.Fatalf("PIT opened against %q, want it scoped to portbridge-v2-*", gotPITPath)
	}
	if len(gotPaths) != 1 || !strings.Contains(gotPaths[0], `"asc"`) {
		t.Fatalf("request body %q does not sort ascending (oldest first)", gotPaths)
	}
	if len(m[41001]) != 1 || m[41001][0].ip != "203.0.113.9" {
		t.Fatalf("via_port map missing the seeded entry: %+v", m)
	}
	if osByIP["203.0.113.9"] != "Linux 3.11 and newer" {
		t.Fatalf("osByIP missing the seeded p0f guess: %+v", osByIP)
	}
}

// viaLookup takes the newest match, so append order (oldest-processed-first)
// is what makes plain last-write-wins correct -- prove the ES path actually
// preserves whatever order the query returns, the same way the old
// portbridge.json.1-then-portbridge.json file order did.
func TestBuildViaMapPreservesOrderForNewestWinsLookup(t *testing.T) {
	docs := []map[string]any{
		{"sensor": "portbridge", "src_ip": "198.51.100.1", "via_port": 41001.0, "port": ""}, // older
		{"sensor": "portbridge", "src_ip": "198.51.100.2", "via_port": 41001.0, "port": ""}, // newer, same via_port
	}
	var gotPaths []string
	es := httptest.NewServer(portbridgeSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	m, _ := s.buildViaMap()

	if got := viaLookup(m, 41001, ""); got != "198.51.100.2" {
		t.Fatalf("viaLookup = %q, want the second (newest-processed) entry to win", got)
	}
}

func TestBuildViaMapReturnsEmptyWhenESUnconfigured(t *testing.T) {
	s := &store{}
	m, osByIP := s.buildViaMap()
	if len(m) != 0 || len(osByIP) != 0 {
		t.Fatalf("expected both maps empty with no ES configured, got m=%+v osByIP=%+v", m, osByIP)
	}
}

func TestBuildViaMapReturnsEmptyOnUnreachableES(t *testing.T) {
	s := &store{es: newESClient("http://127.0.0.1:1", "")} // nothing listening
	m, osByIP := s.buildViaMap()
	if len(m) != 0 || len(osByIP) != 0 {
		t.Fatalf("expected both maps empty when Elasticsearch is unreachable, got m=%+v osByIP=%+v", m, osByIP)
	}
}

func TestBuildViaMapReturnsEmptyWhenPointInTimeOpenFails(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	m, osByIP := s.buildViaMap()
	if len(m) != 0 || len(osByIP) != 0 {
		t.Fatalf("expected both maps empty when opening a point-in-time fails, got m=%+v osByIP=%+v", m, osByIP)
	}
}

// A record with no via_port (portbridge's own transport-metadata-only
// lines, or a malformed one) must not pollute the map with a bogus zero-key
// entry.
func TestBuildViaMapSkipsRecordsWithoutViaPort(t *testing.T) {
	docs := []map[string]any{
		{"sensor": "portbridge", "src_ip": "203.0.113.5", "os": "Windows"}, // no via_port at all
	}
	var gotPaths []string
	es := httptest.NewServer(portbridgeSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	m, osByIP := s.buildViaMap()
	if len(m) != 0 {
		t.Fatalf("expected no via_port entries, got %+v", m)
	}
	// The p0f OS guess is independent of via_port and must still land.
	if osByIP["203.0.113.5"] != "Windows" {
		t.Fatalf("osByIP missing the seeded p0f guess: %+v", osByIP)
	}
}
