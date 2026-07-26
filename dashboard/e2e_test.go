package main

import (
	"encoding/json"
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
	s := &store{dir: root}
	s.rebuild()
	seen := map[string]bool{}
	for _, row := range s.get().Sensors {
		seen[row.Name] = row.Count > 0
	}
	for _, sensor := range []string{"cowrie", "dionaea", "conpot", "tanner", "suricata"} {
		if !seen[sensor] {
			t.Fatalf("synthetic %s event did not reach the snapshot: %+v", sensor, s.get().Sensors)
		}
	}
}
