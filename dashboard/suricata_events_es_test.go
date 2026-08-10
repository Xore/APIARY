package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #1103 Category 2: suricata moved from a local-only sensor to an
// ES-sourced one, with its own adapter (loadSuricataEventsES) against
// suricata-* rather than loadSensorEventsES's honeypot-v2-*. These mirror
// loadSensorEventsES's own test coverage (events_es_test.go) for the parts
// that differ: the index pattern, the category server-side filter, and the
// _source.suricata.eve unwrapping.

// suricataEveSearchStub is honeypotSearchStub's own pattern, wrapping docs
// under _source.suricata.eve instead of _source.honeypot.
func suricataEveSearchStub(t *testing.T, docs []map[string]any, gotPaths *[]string) http.HandlerFunc {
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

		var req struct {
			Size        int   `json:"size"`
			SearchAfter []any `json:"search_after"`
		}
		json.Unmarshal(body, &req)

		start := 0
		if len(req.SearchAfter) > 0 {
			if idx, ok := req.SearchAfter[0].(float64); ok {
				start = int(idx) + 1
			}
		}
		end := start + req.Size
		if end > len(docs) {
			end = len(docs)
		}

		type hit struct {
			Sort   []any `json:"sort"`
			Source struct {
				Suricata struct {
					Eve map[string]any `json:"eve"`
				} `json:"suricata"`
			} `json:"_source"`
		}
		hits := make([]hit, 0, end-start)
		for i := start; i < end; i++ {
			var h hit
			h.Source.Suricata.Eve = docs[i]
			h.Sort = []any{i, fmt.Sprintf("id-%d", i)}
			hits = append(hits, h)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	}
}

func TestLoadSuricataEventsESQueriesTheRightIndexAndFiltersByCategory(t *testing.T) {
	var gotPaths []string
	docs := []map[string]any{
		{"event_type": "alert", "src_ip": "198.51.100.7", "dest_port": 22.0, "proto": "TCP",
			"alert": map[string]any{"signature": "GPL TELNET Bad Login", "category": "Potentially Bad Traffic", "severity": 2.0}},
	}
	es := httptest.NewServer(suricataEveSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{}
	events, ok := s.loadSuricataEventsES(newESClient(es.URL, ""))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(gotPaths) != 1 {
		t.Fatalf("expected exactly one page for a single-doc result, got %d requests", len(gotPaths))
	}
	if !strings.Contains(gotPaths[0], `"event.category"`) || !strings.Contains(gotPaths[0], `"alert"`) || !strings.Contains(gotPaths[0], `"anomaly"`) {
		t.Fatalf("request body %q does not filter server-side by event.category in (alert, anomaly): %s", gotPaths[0], gotPaths[0])
	}
	if len(events) != 1 || events[0].ev.sensor != "suricata" || events[0].ev.alert != "GPL TELNET Bad Login" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

// The PIT this opens must be scoped to suricata-*, not honeypot-v2-* --
// otherwise it would return every other sensor's documents too (they'd
// just fail the suricata-shaped _source.suricata.eve unwrap silently).
func TestLoadSuricataEventsESOpensPointInTimeAgainstSuricataIndex(t *testing.T) {
	var gotPITPath string
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "_pit") {
			gotPITPath = r.URL.Path
			json.NewEncoder(w).Encode(map[string]string{"id": "test-pit-id"})
			return
		}
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "_pit") {
			json.NewEncoder(w).Encode(map[string]bool{"succeeded": true})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": []any{}}})
	}))
	defer es.Close()

	s := &store{}
	if _, ok := s.loadSuricataEventsES(newESClient(es.URL, "")); !ok {
		t.Fatal("expected ok=true")
	}
	if !strings.HasPrefix(gotPITPath, "/suricata-") {
		t.Fatalf("PIT opened against %q, want it scoped to suricata-*", gotPITPath)
	}
}

func TestLoadSuricataEventsESPaginatesPastTheSizeCap(t *testing.T) {
	total := esEventsPageSize + 250
	docs := make([]map[string]any, total)
	for i := range docs {
		docs[i] = map[string]any{
			"event_type": "alert", "src_ip": fmt.Sprintf("203.0.113.%d", i%255), "dest_port": 22.0, "proto": "TCP",
			"alert": map[string]any{"signature": "test", "category": "Test", "severity": 3.0},
		}
	}
	var gotPaths []string
	es := httptest.NewServer(suricataEveSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{}
	events, ok := s.loadSuricataEventsES(newESClient(es.URL, ""))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(gotPaths) != 2 {
		t.Fatalf("expected exactly two pages for %d docs, got %d requests", total, len(gotPaths))
	}
	if len(events) != total {
		t.Fatalf("got %d events, want all %d (pagination dropped events)", len(events), total)
	}
}

func TestLoadSuricataEventsESReturnsFalseOnUnreachableES(t *testing.T) {
	s := &store{}
	es := newESClient("http://127.0.0.1:1", "") // nothing listening
	if _, ok := s.loadSuricataEventsES(es); ok {
		t.Fatal("expected ok=false when Elasticsearch is unreachable")
	}
}

func TestLoadSuricataEventsESReturnsFalseWhenClientIsNil(t *testing.T) {
	s := &store{}
	if _, ok := s.loadSuricataEventsES(nil); ok {
		t.Fatal("expected ok=false with a nil esClient")
	}
}

func TestLoadSuricataEventsESReturnsFalseWhenPointInTimeOpenFails(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer es.Close()

	s := &store{}
	if _, ok := s.loadSuricataEventsES(newESClient(es.URL, "")); ok {
		t.Fatal("expected ok=false when opening a point-in-time fails")
	}
}

// A non-alert/anomaly event_type (flow/dns/netflow/stats) must still be
// skipped even if it somehow reaches classify() -- defense in depth on top
// of the server-side category filter, matching classify()'s own existing
// local-file behavior for the exact same input shape.
func TestLoadSuricataEventsESSkipsNonAlertEventTypes(t *testing.T) {
	var gotPaths []string
	docs := []map[string]any{
		{"event_type": "flow", "src_ip": "203.0.113.1", "dest_port": 445.0, "proto": "TCP"},
	}
	es := httptest.NewServer(suricataEveSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{}
	events, ok := s.loadSuricataEventsES(newESClient(es.URL, ""))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0 -- a flow record must never surface as a displayable event: %+v", len(events), events)
	}
}
