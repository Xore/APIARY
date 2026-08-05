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

// #403: multipot moved from a file-based sensor to an ES-sourced one as
// part of #238 (see events_es.go's esOnlySensors doc comment). These verify
// loadSensorEventsES's own query/parse behavior and that rebuild() actually
// wires an ES-sourced sensor's events into the same s.events pipeline a
// file-based sensor's events go through -- not just that the query
// succeeds in isolation.

// honeypotSearchStub serves up to esEventsPageSize docs per request and
// honors search_after (#583) by paging through docs in order -- gotPaths
// records each request's raw JSON body (the filter/sort/search_after now
// live there, not the URL query string) so tests can assert on them.
func honeypotSearchStub(t *testing.T, docs []map[string]any, gotPaths *[]string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*gotPaths = append(*gotPaths, string(body))

		var req struct {
			Size        int   `json:"size"`
			SearchAfter []any `json:"search_after"`
		}
		json.Unmarshal(body, &req)

		start := 0
		if len(req.SearchAfter) > 0 {
			// search_after[0] is this stub's own "@timestamp" sort value,
			// which it sets to the doc's index in docs (see below) --
			// standing in for a real page cursor without needing genuine
			// timestamp math in the stub.
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
				Honeypot map[string]any `json:"honeypot"`
			} `json:"_source"`
		}
		hits := make([]hit, 0, end-start)
		for i := start; i < end; i++ {
			var h hit
			h.Source.Honeypot = docs[i]
			h.Sort = []any{i, fmt.Sprintf("id-%d", i)} // [timestamp-stand-in, tie-breaker]
			hits = append(hits, h)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{"hits": hits},
		})
	}
}

func TestLoadSensorEventsESQueriesTheRightIndexAndSensor(t *testing.T) {
	var gotPaths []string
	docs := []map[string]any{
		{"sensor": "multipot", "proto": "pop3", "src_ip": "203.0.113.7", "timestamp": "2026-08-01T00:00:00Z"},
	}
	es := httptest.NewServer(honeypotSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{}
	events, ok := s.loadSensorEventsES(newESClient(es.URL, ""), "multipot")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(gotPaths) != 1 {
		t.Fatalf("expected exactly one page for a single-doc result, got %d requests", len(gotPaths))
	}
	if !strings.Contains(gotPaths[0], `"event.sensor":"multipot"`) {
		t.Fatalf("request body %q does not filter by event.sensor", gotPaths[0])
	}
	if !strings.Contains(gotPaths[0], `"@timestamp"`) {
		t.Fatalf("request body %q does not sort by @timestamp", gotPaths[0])
	}
	if len(events) != 1 || events[0].ev.ip != "203.0.113.7" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

// TestLoadSensorEventsESPaginatesPastTheSizeCap is a regression test for
// #583: a plain size=10000 GET query silently dropped every event past the
// first page during a burst. A sensor with more than esEventsPageSize
// events across a rebuild cycle must not lose the oldest ones anymore.
func TestLoadSensorEventsESPaginatesPastTheSizeCap(t *testing.T) {
	total := esEventsPageSize + 250 // forces exactly two pages
	docs := make([]map[string]any, total)
	for i := range docs {
		docs[i] = map[string]any{
			"sensor": "multipot", "proto": "ftp",
			"src_ip": fmt.Sprintf("203.0.113.%d", i%255), "timestamp": "2026-08-01T00:00:00Z",
		}
	}
	var gotPaths []string
	es := httptest.NewServer(honeypotSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{}
	events, ok := s.loadSensorEventsES(newESClient(es.URL, ""), "multipot")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(gotPaths) != 2 {
		t.Fatalf("expected exactly two pages for %d docs, got %d requests", total, len(gotPaths))
	}
	if !strings.Contains(gotPaths[1], `"search_after"`) {
		t.Fatalf("second page request did not carry search_after: %q", gotPaths[1])
	}
	if len(events) != total {
		t.Fatalf("got %d events, want all %d (pagination dropped events)", len(events), total)
	}
}

// TestLoadSensorEventsESStopsAtMaxPages confirms the pagination loop is
// bounded, not unbounded -- a hard cap on worst-case rebuild latency during
// a pathological burst, per #583's own stated design.
func TestLoadSensorEventsESStopsAtMaxPages(t *testing.T) {
	total := esEventsPageSize*esEventsMaxPages + 1000 // one page more than the cap allows
	docs := make([]map[string]any, total)
	for i := range docs {
		docs[i] = map[string]any{"sensor": "multipot", "proto": "ftp", "src_ip": "203.0.113.1", "timestamp": "2026-08-01T00:00:00Z"}
	}
	var gotPaths []string
	es := httptest.NewServer(honeypotSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{}
	events, ok := s.loadSensorEventsES(newESClient(es.URL, ""), "multipot")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(gotPaths) != esEventsMaxPages {
		t.Fatalf("expected exactly esEventsMaxPages (%d) requests, got %d", esEventsMaxPages, len(gotPaths))
	}
	if len(events) != esEventsPageSize*esEventsMaxPages {
		t.Fatalf("got %d events, want exactly the max-pages cap (%d)", len(events), esEventsPageSize*esEventsMaxPages)
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
	var gotPaths []string
	docs := []map[string]any{
		{"sensor": "multipot", "proto": "rdp", "src_ip": "203.0.113.55", "timestamp": "2026-08-01T00:00:00Z"},
	}
	es := httptest.NewServer(honeypotSearchStub(t, docs, &gotPaths))
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
