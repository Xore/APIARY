package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #403: multipot moved from a file-based sensor to an ES-sourced one as
// part of #238 (see events_es.go's esOnlySensors doc comment). These verify
// loadSensorEventsES's own query/parse behavior and that rebuild() actually
// wires an ES-sourced sensor's events into the same s.events pipeline a
// file-based sensor's events go through -- not just that the query
// succeeds in isolation.

func honeypotSearchStub(t *testing.T, docs []map[string]any, gotPath *string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		*gotPath = r.URL.RequestURI()
		type hit struct {
			Source struct {
				Honeypot map[string]any `json:"honeypot"`
			} `json:"_source"`
		}
		hits := make([]hit, 0, len(docs))
		for _, d := range docs {
			var h hit
			h.Source.Honeypot = d
			hits = append(hits, h)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{"hits": hits},
		})
	}
}

func TestLoadSensorEventsESQueriesTheRightIndexAndSensor(t *testing.T) {
	var gotPath string
	docs := []map[string]any{
		{"sensor": "multipot", "proto": "pop3", "src_ip": "203.0.113.7", "timestamp": "2026-08-01T00:00:00Z"},
	}
	es := httptest.NewServer(honeypotSearchStub(t, docs, &gotPath))
	defer es.Close()

	s := &store{}
	events, ok := s.loadSensorEventsES(newESClient(es.URL, ""), "multipot")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !strings.Contains(gotPath, "/honeypot-v2-*/_search") {
		t.Fatalf("queried path %q does not target honeypot-v2-*", gotPath)
	}
	if !strings.Contains(gotPath, "event.sensor") {
		t.Fatalf("queried path %q does not filter by event.sensor", gotPath)
	}
	if len(events) != 1 || events[0].ev.ip != "203.0.113.7" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestLoadSensorEventsESReturnsFalseOnUnreachableES(t *testing.T) {
	s := &store{}
	es := newESClient("http://127.0.0.1:1", "") // nothing listening
	if _, ok := s.loadSensorEventsES(es, "multipot"); ok {
		t.Fatal("expected ok=false when Elasticsearch is unreachable")
	}
}

func TestLoadSensorEventsESReturnsFalseWhenClientIsNil(t *testing.T) {
	s := &store{}
	if _, ok := s.loadSensorEventsES(nil, "multipot"); ok {
		t.Fatal("expected ok=false with a nil esClient")
	}
}

// End to end: rebuild() must merge an ES-sourced sensor's events into
// s.events alongside file-based sensors, indistinguishable downstream (the
// whole point of #403 -- an ES-only sensor gets the exact same overview/
// filter/dedup/geo treatment as a file-based one).
func TestRebuildMergesESSourcedSensorEvents(t *testing.T) {
	var gotPath string
	docs := []map[string]any{
		{"sensor": "multipot", "proto": "rdp", "src_ip": "203.0.113.55", "timestamp": "2026-08-01T00:00:00Z"},
	}
	es := httptest.NewServer(honeypotSearchStub(t, docs, &gotPath))
	defer es.Close()

	root := t.TempDir()
	writeFileLines(t, root+"/cowrie/cowrie.json", cowrieLine("a", "2026-01-01T00:00:00Z"))

	s := &store{dir: root, es: newESClient(es.URL, "")}
	s.rebuild()

	found := false
	for _, ev := range s.getEvents() {
		if ev.Sensor == "multipot" && ev.SrcIP == "203.0.113.55" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ES-sourced multipot event missing from s.events: %+v", s.getEvents())
	}
}

// multipot's own log directory must never be read once it's ES-sourced --
// this is the actual #238 data-flow requirement, not just "ES also works."
func TestRebuildNeverReadsESOnlySensorsLogDirectory(t *testing.T) {
	root := t.TempDir()
	writeFileLines(t, root+"/multipot/multipot.json",
		`{"sensor":"multipot","proto":"ftp","src_ip":"203.0.113.9","timestamp":"2026-01-01T00:00:00Z"}`)

	s := &store{dir: root} // s.es is nil: loadSensorEventsES must no-op, not fall back to the file
	s.rebuild()

	if _, cached := s.logCache[root+"/multipot/multipot.json"]; cached {
		t.Fatal("multipot's log file must never be read into the file-based cache -- it's an ES-only sensor")
	}
	for _, ev := range s.getEvents() {
		if ev.Sensor == "multipot" {
			t.Fatalf("multipot event present without ES configured -- must have been read from its log file: %+v", ev)
		}
	}
}
