package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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
//
// A thin wrapper over esFullStub for callers that only care about
// honeypot-v2-*-backed sensors -- see that function's own doc comment for
// suricata-*/portbridge-v2-* support (#1103 Category 2).
func esSensorAndOverviewStub(t *testing.T, docsBySensor map[string][]map[string]any) http.HandlerFunc {
	t.Helper()
	return esFullStub(t, esFullStubDocs{HoneypotBySensor: docsBySensor})
}

// esFullStubDocs seeds esFullStub's three index families independently --
// zero-value fields simply return no hits for that family's queries.
type esFullStubDocs struct {
	HoneypotBySensor map[string][]map[string]any // honeypot-v2-*, per event.sensor -- raw "honeypot" objects
	SuricataEve      []map[string]any            // suricata-*, loadSuricataEventsES -- raw "suricata.eve" objects
	Portbridge       []map[string]any            // portbridge-v2-*, buildViaMap -- raw "portbridge" objects, in the order buildViaMap should process them (oldest first)
	Overview         esOverviewAggResponse       // the #39 plain overview aggregation
	SuricataOverview esSuricataOverviewResponse  // fetchESOverview's separate suricata-v2-* query -- NOT the same as SuricataEve/loadSuricataEventsES, see es_aggregate.go's own comment on why that's a second query
}

// esFullStub answers every Elasticsearch request shape a rebuild() cycle
// can make (#1103): loadSensorEventsES's per-sensor honeypot-v2-* search,
// loadSuricataEventsES's suricata-* search, buildViaMap's portbridge-v2-*
// search, the #39 overview aggregation, and fetchESOverview's separate
// suricata-v2-* overview query. A single PIT-scoped bare POST /_search is
// used by all three of the first three (the PIT itself, not the path or
// body shape, pins which index family a given search targets) -- this
// stub tracks each open PIT's family by which index pattern its own
// POST /<pattern>/_pit request named, then routes the follow-up /_search
// accordingly.
func esFullStub(t *testing.T, docs esFullStubDocs) http.HandlerFunc {
	t.Helper()
	pitFamily := map[string]string{} // pit id -> "honeypot" | "suricata" | "portbridge"
	var pitSeq int
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// fetchESOverview's own separate suricata-v2-* aggregation -- a
		// direct index-scoped POST, never PIT-based, so it's distinguished
		// by path alone before any of the PIT handling below.
		if strings.Contains(r.URL.Path, "suricata-v2-") && !strings.Contains(r.URL.Path, "_pit") {
			json.NewEncoder(w).Encode(docs.SuricataOverview)
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "_pit") {
			family := "honeypot"
			if strings.HasPrefix(r.URL.Path, "/suricata-") {
				family = "suricata"
			} else if strings.HasPrefix(r.URL.Path, "/portbridge-") {
				family = "portbridge"
			}
			pitSeq++
			id := family + "-pit-" + strconv.Itoa(pitSeq)
			pitFamily[id] = family
			json.NewEncoder(w).Encode(map[string]string{"id": id})
			return
		}
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "_pit") {
			json.NewEncoder(w).Encode(map[string]bool{"succeeded": true})
			return
		}

		body, _ := io.ReadAll(r.Body)
		var parsed struct {
			PIT struct {
				ID string `json:"id"`
			} `json:"pit"`
		}
		json.Unmarshal(body, &parsed)
		switch pitFamily[parsed.PIT.ID] {
		case "suricata":
			type hit struct {
				Source struct {
					Suricata struct {
						Eve map[string]any `json:"eve"`
					} `json:"suricata"`
				} `json:"_source"`
			}
			hits := make([]hit, 0, len(docs.SuricataEve))
			for _, d := range docs.SuricataEve {
				var h hit
				h.Source.Suricata.Eve = d
				hits = append(hits, h)
			}
			json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
			return
		case "portbridge":
			type hit struct {
				Source struct {
					Portbridge map[string]any `json:"portbridge"`
				} `json:"_source"`
			}
			hits := make([]hit, 0, len(docs.Portbridge))
			for _, d := range docs.Portbridge {
				var h hit
				h.Source.Portbridge = d
				hits = append(hits, h)
			}
			json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
			return
		}

		// honeypot family (the default -- also covers the plain #39
		// overview query, which carries no PIT at all).
		sensor, isSensorQuery := sensorFromSearchBody(body)
		if !isSensorQuery {
			json.NewEncoder(w).Encode(docs.Overview)
			return
		}
		hitsSrc := docs.HoneypotBySensor[sensor]
		type hit struct {
			Source struct {
				Honeypot map[string]any `json:"honeypot"`
			} `json:"_source"`
		}
		hits := make([]hit, 0, len(hitsSrc))
		for _, d := range hitsSrc {
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

// TestRebuildRoutesSuricataThroughItsOwnAdapterNotTheGenericOne (#41,
// updated for #1103 Category 2): suricata ships to its own index family
// (suricata-*), never honeypot-v2-* under event.sensor:"suricata" the way
// every other sensor does -- loadSensorEventsES querying honeypot-v2-* for
// "suricata" "successfully" returns zero hits every time (reproduced here
// the same way: an ES stub with nothing registered for that name in
// HoneypotBySensor, exactly what a real cluster returns), which #34
// originally treated as "ES has this sensor covered" and skipped the local
// read that actually had the data -- the regression a live production
// check found after #34/#39 shipped, no suricata alerts anywhere in the
// dashboard. #1103 replaced the local-read fallback with a real, separate
// suricata-* adapter (loadSuricataEventsES); what this test proves now is
// that rebuild() actually calls it -- an empty honeypot-v2-* result for
// "suricata" must not suppress the real alert loadSuricataEventsES itself
// returns.
func TestRebuildRoutesSuricataThroughItsOwnAdapterNotTheGenericOne(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	writeFileLines(t, filepath.Join(root, "suricata", "eve.json"), "{}")

	esSrv := httptest.NewServer(esFullStub(t, esFullStubDocs{
		// Empty for "suricata" -- matches production's real honeypot-v2-*,
		// which never has suricata documents at all.
		HoneypotBySensor: map[string][]map[string]any{},
		SuricataEve: []map[string]any{
			{"timestamp": now, "event_type": "alert", "src_ip": "198.51.100.7", "dest_port": 22.0, "proto": "TCP",
				"alert": map[string]any{"signature": "SYNTHETIC TEST ALERT", "category": "Test", "severity": 3.0}},
		},
	}))
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
		t.Fatalf("suricata alert from its own adapter must not be masked by honeypot-v2-*'s empty (but valid) result: %+v", s.getEvents())
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
