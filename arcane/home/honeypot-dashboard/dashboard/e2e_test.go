package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSyntheticSensorsReachDashboardSnapshot(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Every sensor reads Elasticsearch exclusively now (#1103, including
	// suricata as of Category 2 -- loadSuricataEventsES, its own suricata-*
	// adapter). rebuild() still discovers WHICH sensors to query by walking
	// the local directory tree, so an empty placeholder file is needed for
	// each one, even though its content is never read.
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
	if err := os.MkdirAll(filepath.Join(root, "suricata"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "suricata", "eve.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// #39: per-sensor counts on the snapshot are ES-native now (see
	// es_aggregate.go) -- this fixture data still proves classify()/
	// rebuild() correctly parse and route every one of these raw shapes
	// into storedEvent (checked below via s.getEvents()); which sensors
	// show up in the Sensors leaderboard is Elasticsearch's own job,
	// covered by TestFetchESOverviewParsesCountsAndTerms.
	//
	// suricata's OVERVIEW numbers come through the same multi-index
	// aggregation as every other sensor now (#1136: honeypot-v2-*,
	// suricata-v2-* queried together), just its own bucket in the same
	// sensors list -- not a separate query anymore. Its *events* (checked
	// below via s.getEvents()) still come through loadSuricataEventsES
	// instead, a separate mechanism from the aggregation.
	var resp esOverviewAggResponse
	for _, sensor := range []string{"cowrie", "dionaea", "conpot", "tanner"} {
		resp.Aggregations.Sensors.Buckets = append(resp.Aggregations.Sensors.Buckets, esSensorBucket{Key: sensor, DocCount: 1})
	}
	resp.Aggregations.Sensors.Buckets = append(resp.Aggregations.Sensors.Buckets, esSensorBucket{Key: "suricata", DocCount: 1, LastSeen: struct {
		ValueAsString string `json:"value_as_string"`
	}{ValueAsString: now}})

	esSrv := httptest.NewServer(esFullStub(t, esFullStubDocs{
		HoneypotBySensor: docsBySensor,
		SuricataEve: []map[string]any{
			{"timestamp": now, "event_type": "alert", "src_ip": "4.2.2.2", "dest_port": 22.0, "proto": "TCP",
				"alert": map[string]any{"signature": "SYNTHETIC TEST ALERT", "category": "Test", "severity": 3.0}},
		},
		Overview: resp,
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
