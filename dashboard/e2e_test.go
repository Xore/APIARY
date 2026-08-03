package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSyntheticSensorsReachDashboardSnapshot(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	fixtures := map[string]map[string]any{
		"cowrie/cowrie.json":     {"timestamp": now, "eventid": "cowrie.login.failed", "src_ip": "8.8.8.8", "username": "root", "password": "test", "session": "synthetic-cowrie"},
		"dionaea/incidents.json": {"timestamp": now, "origin": "dionaea.connection.tcp.connect", "data": map[string]any{"connection": map[string]any{"protocol": "smb", "remote_ip": "8.8.4.4", "local_port": 445.0}}},
		"conpot/events.json":     {"timestamp": now, "data_type": "modbus", "src_ip": "1.1.1.1", "dst_port": 502.0, "request": "read coils"},
		"tanner/report.json":     {"timestamp": now, "peer": map[string]any{"ip": "9.9.9.9"}, "paths": []any{map[string]any{"path": "/login.php"}}, "attack_types": []any{"sqli"}},
		"suricata/eve.json":      {"timestamp": now, "event_type": "alert", "src_ip": "4.2.2.2", "dest_port": 22.0, "proto": "TCP", "alert": map[string]any{"signature": "SYNTHETIC TEST ALERT", "category": "Test", "severity": 3.0}},
	}
	for name, event := range fixtures {
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
	var resp esOverviewAggResponse
	for _, sensor := range []string{"cowrie", "dionaea", "conpot", "tanner", "suricata"} {
		resp.Aggregations.Sensors.Buckets = append(resp.Aggregations.Sensors.Buckets, esSensorBucket{Key: sensor, DocCount: 1})
	}
	esSrv := httptest.NewServer(esOverviewStub(t, resp))
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
