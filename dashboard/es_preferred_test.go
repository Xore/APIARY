package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// esSensorAndOverviewStub answers both request shapes a rebuild() cycle
// makes once s.es is configured: loadSensorEventsES's per-sensor POST
// (#583: a term-query-on-event.sensor body, same as honeypotSearchStub's
// convention in events_es_test.go) and the #39 overview aggregation POST
// (an empty response is fine -- these tests aren't about the aggregate
// fields). Both now POST to the same /honeypot-v2-*/_search path, so the
// body's shape -- not the path or method -- is what distinguishes them.
func esSensorAndOverviewStub(t *testing.T, docsBySensor map[string][]map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		// #1097: loadSensorEventsES opens/closes a point-in-time around its
		// search now (see events_es.go) -- answer those two requests before
		// falling into the sensor/overview body-parsing logic below, which
		// only knows how to answer a _search body.
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

		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		sensor, isSensorQuery := sensorFromSearchBody(body)
		if !isSensorQuery {
			json.NewEncoder(w).Encode(esOverviewAggResponse{})
			return
		}
		docs := docsBySensor[sensor]
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

// TestRebuildNeverReadsLocalFileWithoutESConfigured (#1103): a sensor with
// no ES client configured at all -- or one Elasticsearch can't currently
// answer for -- must show no events for that sensor, not fall back to its
// local log file. cowrie/dionaea/conpot/dnp3/http-honeypot/api-honeypot/
// tanner/endlessh read Elasticsearch exclusively now; only suricata and
// portbridge (their own index families, not honeypot-v2-*) still read
// local files at all -- see TestRebuildNeverMasksSuricataOrPortbridgeWithAnEmptyESResult
// below for that pair's own (unrelated, still-correct) coverage.
func TestRebuildNeverReadsLocalFileWithoutESConfigured(t *testing.T) {
	root := t.TempDir()
	writeLog(t, root, "cowrie/cowrie.json", map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "eventid": "cowrie.login.failed",
		"src_ip": "198.51.100.1", "username": "local-only", "password": "x", "session": "local-session",
	})

	s := &store{dir: root} // no ES client at all
	s.rebuild()

	for _, ev := range s.getEvents() {
		if ev.User == "local-only" {
			t.Fatalf("cowrie event was read from the local file with no ES configured, must be empty: %+v", s.getEvents())
		}
	}
}

// TestRebuildNeverMasksSuricataOrPortbridgeWithAnEmptyESResult (#41): both
// ship to their own index families (suricata-*, portbridge-v2-*), never
// honeypot-v2-* under event.sensor:"suricata"/"portbridge" the way every
// other sensor does -- loadSensorEventsES querying honeypot-v2-* for either
// "successfully" returns zero hits every time (reproduced here the same
// way: an ES stub with nothing registered for these two names, exactly what
// a real cluster returns), which #34 was silently treating as "ES has this
// sensor covered" and skipping the local read that actually has the data.
// This is the exact regression a live production check found after #34/#39
// shipped: no suricata alerts anywhere in the dashboard.
func TestRebuildNeverMasksSuricataOrPortbridgeWithAnEmptyESResult(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	writeLog(t, root, "suricata/eve.json", map[string]any{
		"timestamp": now, "event_type": "alert", "src_ip": "198.51.100.7", "dest_port": 22.0, "proto": "TCP",
		"alert": map[string]any{"signature": "SYNTHETIC TEST ALERT", "category": "Test", "severity": 3.0},
	})

	// Registered for cowrie only, matching production where honeypot-v2-*
	// genuinely has no event.sensor:"suricata"/"portbridge" documents at
	// all -- the stub answers those with a valid, empty hit list, not an
	// error, which is exactly what makes this bug silent.
	esSrv := httptest.NewServer(esSensorAndOverviewStub(t, map[string][]map[string]any{}))
	defer esSrv.Close()
	s := &store{dir: root, es: newESClient(esSrv.URL, "")}
	s.rebuild()

	found := false
	for _, ev := range s.getEvents() {
		if ev.Alert == "SYNTHETIC TEST ALERT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("suricata alert from the local file must not be masked by ES's empty (but valid) result: %+v", s.getEvents())
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
