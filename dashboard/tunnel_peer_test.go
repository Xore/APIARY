package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeLog puts one JSON record per line into <root>/<rel>, creating the sensor
// subdirectory the way the real log tree is laid out.
func writeLog(t *testing.T, root, rel string, records ...map[string]any) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	var body []byte
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		body = append(append(body, line...), '\n')
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Sensors behind portbridge see the WireGuard peer, not the attacker. The
// via_port join recovers the real address; when it cannot, the event must be
// left with no source rather than credited to the tunnel. 10.8.0.1 is our own
// VPS, so attributing traffic to it puts our infrastructure at the top of
// /ips, inflates the unique-attacker count, and would eventually be handed to
// external abuse reporting. See issue #54.
func TestTunnelPeerIsRecoveredOrLeftUnattributed(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Only the first connection has a portbridge record to join against.
	writeLog(t, root, "portbridge/portbridge.json", map[string]any{
		"time": now, "sensor": "portbridge", "event": "connect", "proto": "tcp",
		"port": 445.0, "src_ip": "203.0.113.9", "src_port": 51000.0, "via_port": 41001.0,
	})
	writeLog(t, root, "dionaea/incidents.json",
		map[string]any{
			"timestamp": now, "origin": "dionaea.connection.tcp.connect",
			"data": map[string]any{"connection": map[string]any{
				"protocol": "smb", "remote_ip": tunnelPeerIP, "remote_port": 41001.0, "local_port": 445.0,
			}},
		},
		// No matching via_port: a UDP-fronted or already-rotated connection.
		map[string]any{
			"timestamp": now, "origin": "dionaea.connection.tcp.reject",
			"data": map[string]any{"connection": map[string]any{
				"protocol": "smb", "remote_ip": tunnelPeerIP, "remote_port": 49999.0, "local_port": 445.0,
			}},
		},
	)

	s := &store{dir: root}
	s.rebuild()
	snap := s.get()

	for _, row := range snap.TopIPs {
		if row.Key == tunnelPeerIP {
			t.Fatalf("the tunnel peer is ranked as an attacker on the overview: %+v", snap.TopIPs)
		}
	}
	if snap.UniqueIPs != 1 {
		t.Fatalf("UniqueIPs=%d, want only the one recovered attacker", snap.UniqueIPs)
	}
	if snap.Unattributed != 1 {
		t.Fatalf("Unattributed=%d, want the unrecoverable event reported as a gap", snap.Unattributed)
	}

	// The unattributed event is still an attack: dropping it would understate
	// the volume and hide the recovery gap instead of measuring it.
	if snap.Total != 2 {
		t.Fatalf("Total=%d, want both events retained", snap.Total)
	}

	var recovered, blank int
	for _, event := range s.getEvents() {
		switch event.SrcIP {
		case "203.0.113.9":
			recovered++
		case "":
			blank++
		default:
			t.Fatalf("unexpected source %q on a tunnelled event", event.SrcIP)
		}
	}
	if recovered != 1 || blank != 1 {
		t.Fatalf("recovered=%d unattributed=%d, want one of each", recovered, blank)
	}

	for _, row := range s.buildIPsData(filter{}).Rows {
		if row.IP == tunnelPeerIP {
			t.Fatalf("/ips still lists the tunnel peer: %+v", row)
		}
	}

	// #75 asks for the gap to be judged on a before-and-after number. The
	// read-only diagnostics workflow can reach /metrics on the home runner but
	// not /source-health, so the count has to be exported to be answerable.
	recorder := httptest.NewRecorder()
	s.serveMetrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(recorder.Body.String(), "honeypot_unattributed_events 1\n") {
		t.Fatalf("/metrics does not report the recovery gap:\n%s", recorder.Body.String())
	}
}

// The VPS rotates the portbridge conn log by copytruncate. If the join only
// read the live file, every rotation would blank the map and re-open the gap
// #54 measured — the events would still be there, just unattributable again.
// UDP is the case that depends on this most: it has no PROXY-protocol
// alternative, so the conn log is its only route to a real source. See #75.
func TestViaMapSpansTheRotatedConnLog(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// The SNMP connection was recorded before the last rotation; only the
	// newer FTP one is still in the live file.
	writeLog(t, root, "portbridge/portbridge.json.1", map[string]any{
		"time": now, "sensor": "portbridge", "event": "connect", "proto": "udp",
		"port": 161.0, "src_ip": "198.51.100.7", "src_port": 33001.0, "via_port": 41002.0,
	})
	writeLog(t, root, "portbridge/portbridge.json", map[string]any{
		"time": now, "sensor": "portbridge", "event": "connect", "proto": "tcp",
		"port": 21.0, "src_ip": "203.0.113.9", "src_port": 51000.0, "via_port": 41003.0,
	})
	writeLog(t, root, "conpot/conpot.json", map[string]any{
		"timestamp": now, "sensorid": "snmp", "data_type": "snmp",
		"src_ip": tunnelPeerIP, "src_port": 41002.0, "dst_port": 161.0,
		"event_type": "snmp_get",
	})

	s := &store{dir: root}
	s.rebuild()

	if snap := s.get(); snap.Unattributed != 0 {
		t.Fatalf("Unattributed=%d, want the rotated-out connection still joined", snap.Unattributed)
	}
	events := s.getEvents()
	if len(events) != 1 {
		t.Fatalf("got %d events, want only the conpot probe (portbridge records are transport metadata)", len(events))
	}
	if events[0].SrcIP != "198.51.100.7" {
		t.Fatalf("SrcIP=%q, want the attacker recorded in the rotated conn log", events[0].SrcIP)
	}
}

// The via_port join is the only thing standing between a real attacker IP and
// being discarded, so a miss must be caused by a genuinely absent record — not
// by a listen-port mismatch that viaLookup should have tolerated.
func TestViaLookupMatchesOnListenPort(t *testing.T) {
	m := map[int][]viaEntry{
		41001: {{ip: "203.0.113.1", port: "445"}, {ip: "203.0.113.2", port: "22"}},
		41002: {{ip: "203.0.113.3", port: ""}},
	}
	for _, tc := range []struct {
		name    string
		srcPort int
		port    string
		want    string
	}{
		{"newest entry for the matching listen port", 41001, "22", "203.0.113.2"},
		{"older entry when the newer one is a different port", 41001, "445", "203.0.113.1"},
		{"an event with no port takes the newest entry", 41001, "", "203.0.113.2"},
		{"an entry with no port matches anything", 41002, "445", "203.0.113.3"},
		{"an unknown via_port yields nothing", 40000, "445", ""},
		{"a via_port with no matching listen port yields nothing", 41001, "3306", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := viaLookup(m, tc.srcPort, tc.port); got != tc.want {
				t.Fatalf("viaLookup(%d, %q) = %q, want %q", tc.srcPort, tc.port, got, tc.want)
			}
		})
	}
}
