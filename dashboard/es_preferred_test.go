package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// esSensorAndOverviewStub answers both request shapes a rebuild() cycle
// makes once s.es is configured: the ES-preferred per-sensor GET (matched
// on event.sensor:<name> in the query string, honeypotSearchStub's own
// convention) and the #39 overview aggregation POST (an empty response is
// fine -- these tests aren't about the aggregate fields).
func esSensorAndOverviewStub(t *testing.T, docsBySensor map[string][]map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(esOverviewAggResponse{})
			return
		}
		q := r.URL.Query().Get("q")
		var docs []map[string]any
		for sensor, d := range docsBySensor {
			if q == `event.sensor:"`+sensor+`"` {
				docs = d
			}
		}
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
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	}
}

// TestRebuildPrefersESOverLocalFileForFormerlyFileOnlySensors (#34/#403):
// cowrie was never in esOnlySensors before this change -- it must now be
// read from Elasticsearch when available, not from its local log file, even
// though the local file is still present and would classify successfully on
// its own.
func TestRebuildPrefersESOverLocalFileForFormerlyFileOnlySensors(t *testing.T) {
	root := t.TempDir()
	writeLog(t, root, "cowrie/cowrie.json", map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "eventid": "cowrie.login.failed",
		"src_ip": "198.51.100.1", "username": "local-only", "password": "x", "session": "local-session",
	})

	esSrv := httptest.NewServer(esSensorAndOverviewStub(t, map[string][]map[string]any{
		"cowrie": {{
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "eventid": "cowrie.login.failed",
			"src_ip": "203.0.113.9", "username": "es-sourced", "password": "y", "session": "es-session",
		}},
	}))
	defer esSrv.Close()

	s := &store{dir: root, es: newESClient(esSrv.URL, "")}
	s.rebuild()

	var sawES, sawLocal bool
	for _, ev := range s.getEvents() {
		switch ev.User {
		case "es-sourced":
			sawES = true
		case "local-only":
			sawLocal = true
		}
	}
	if !sawES {
		t.Fatalf("expected the ES-sourced cowrie event to reach the snapshot: %+v", s.getEvents())
	}
	if sawLocal {
		t.Fatalf("local file must not also be read once ES succeeds for this sensor: %+v", s.getEvents())
	}
}

// TestRebuildFallsBackToLocalFileWhenESUnavailable (#34/#403): a sensor with
// no ES client configured at all -- or one Elasticsearch can't currently
// answer for -- must still show its local events rather than going blank.
func TestRebuildFallsBackToLocalFileWhenESUnavailable(t *testing.T) {
	root := t.TempDir()
	writeLog(t, root, "cowrie/cowrie.json", map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "eventid": "cowrie.login.failed",
		"src_ip": "198.51.100.1", "username": "local-only", "password": "x", "session": "local-session",
	})

	s := &store{dir: root} // no ES client at all
	s.rebuild()

	found := false
	for _, ev := range s.getEvents() {
		if ev.User == "local-only" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the local cowrie event as a fallback with no ES configured: %+v", s.getEvents())
	}
}

// TestRebuildSkipsTheEnrichedDirectoryAsItsOwnSensor (#38/#34):
// ip-enrichment-worker's own output directory carries the exact same
// underlying events as cowrie/dionaea/conpot/dns-honeypot/
// cisco-asa-honeypot's real directories already do (just with src_ip
// corrected) -- it must never be read as a sixth, bogus "enriched" sensor.
func TestRebuildSkipsTheEnrichedDirectoryAsItsOwnSensor(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "enriched", "cowrie.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	line, _ := json.Marshal(map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "eventid": "cowrie.login.failed",
		"src_ip": "203.0.113.9", "username": "should-not-appear", "password": "x", "session": "s",
	})
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{dir: root}
	s.rebuild()

	for _, ev := range s.getEvents() {
		if ev.Sensor == "enriched" || ev.User == "should-not-appear" {
			t.Fatalf("the enriched/ staging directory must not be read as its own sensor: %+v", ev)
		}
	}
}
