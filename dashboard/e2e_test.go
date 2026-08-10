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

func TestSyntheticSensorsReachDashboardSnapshot(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// cowrie/dionaea/conpot/tanner read from Elasticsearch exclusively now
	// (#1103); suricata stays local (excluded from the ES attempt
	// entirely -- own index family, see aggregate.go's own comment).
	// rebuild() still discovers WHICH sensors to query in ES by walking
	// the local directory tree, so an empty placeholder file is needed
	// for each ES-only sensor too, even though its content is never read.
	esFixtures := map[string]map[string]any{
		"cowrie":  {"timestamp": now, "eventid": "cowrie.login.failed", "src_ip": "8.8.8.8", "username": "root", "password": "test", "session": "synthetic-cowrie"},
		"dionaea": {"timestamp": now, "origin": "dionaea.connection.tcp.connect", "data": map[string]any{"connection": map[string]any{"protocol": "smb", "remote_ip": "8.8.4.4", "local_port": 445.0}}},
		"conpot":  {"timestamp": now, "data_type": "modbus", "src_ip": "1.1.1.1", "dst_port": 502.0, "request": "read coils"},
		"tanner":  {"timestamp": now, "peer": map[string]any{"ip": "9.9.9.9"}, "paths": []any{map[string]any{"path": "/login.php"}}, "attack_types": []any{"sqli"}},
	}
	docsBySensor := map[string][]map[string]any{}
	for sensor, event := range esFixtures {
		docsBySensor[sensor] = []map[string]any{event}
		placeholder := filepath.Join(root, sensor, sensor+".json")
		if err := os.MkdirAll(filepath.Dir(placeholder), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(placeholder, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	localFixtures := map[string]map[string]any{
		"suricata/eve.json": {"timestamp": now, "event_type": "alert", "src_ip": "4.2.2.2", "dest_port": 22.0, "proto": "TCP", "alert": map[string]any{"signature": "SYNTHETIC TEST ALERT", "category": "Test", "severity": 3.0}},
	}
	for name, event := range localFixtures {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		line, _ := json.Marshal(event)
		if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// #39: per-sensor counts on the snapshot are ES-native now (see
	// es_aggregate.go) -- this fixture data still proves classify()/
	// rebuild() correctly parse and route every one of these raw shapes
	// into storedEvent (checked below via s.getEvents()); which sensors
	// show up in the Sensors leaderboard is Elasticsearch's own job,
	// covered by TestFetchESOverviewParsesCountsAndTerms.
	//
	// suricata is seeded through the separate suricata-v2-* query
	// (esSuricataOverviewResponse), not the main sensors bucket list --
	// #1100's fix made that match how production actually works: Suricata
	// ships to its own index family, never honeypot-v2-* under
	// event.sensor:"suricata" the way every other sensor here does (see
	// es_aggregate.go's own comment on suricataOverviewQuery).
	var resp esOverviewAggResponse
	for _, sensor := range []string{"cowrie", "dionaea", "conpot", "tanner"} {
		resp.Aggregations.Sensors.Buckets = append(resp.Aggregations.Sensors.Buckets, esSensorBucket{Key: sensor, DocCount: 1})
	}
	var suricata esSuricataOverviewResponse
	suricata.Hits.Total.Value = 1
	suricata.Aggregations.LastSeen.ValueAsString = now

	// A bespoke combined handler, not esSensorAndOverviewStub as-is: that
	// helper's own overview fallback always answers an empty
	// esOverviewAggResponse{} (fine for tests that aren't about the
	// aggregate fields), but this test needs the populated `resp` +
	// suricata-specific response too.
	esSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "suricata") {
			json.NewEncoder(w).Encode(suricata)
			return
		}
		if strings.Contains(r.URL.Path, "_pit") {
			if r.Method == http.MethodDelete {
				json.NewEncoder(w).Encode(map[string]bool{"succeeded": true})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"id": "test-pit-id"})
			return
		}
		body, _ := io.ReadAll(r.Body)
		sensor, isSensorQuery := sensorFromSearchBody(body)
		if !isSensorQuery {
			json.NewEncoder(w).Encode(resp)
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
	}))
	defer esSrv.Close()
	s := &store{dir: root, es: newESClient(esSrv.URL, "")}
	s.rebuild()

	seenEvent := map[string]bool{}
	for _, ev := range s.getEvents() {
		seenEvent[ev.Sensor] = true
	}
	for _, sensor := range []string{"cowrie", "dionaea", "conpot", "tanner", "suricata"} {
		if !seenEvent[sensor] {
			t.Fatalf("synthetic %s event was not parsed into an event: %+v", sensor, s.getEvents())
		}
	}

	seen := map[string]bool{}
	for _, row := range s.get().Sensors {
		seen[row.Name] = row.Count > 0
	}
	for _, sensor := range []string{"cowrie", "dionaea", "conpot", "tanner", "suricata"} {
		if !seen[sensor] {
			t.Fatalf("ES-reported %s sensor did not reach the snapshot: %+v", sensor, s.get().Sensors)
		}
	}
}
