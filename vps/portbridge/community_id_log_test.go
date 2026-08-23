package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// logOneAndDecode writes a single connection record and returns it decoded, so
// the assertions below are against the JSON that actually reaches
// portbridge.json rather than against the helper functions in isolation.
func logOneAndDecode(t *testing.T, r rule, src, dst, via net.Addr) map[string]any {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "portbridge.json")
	cl := newConnLogger(logPath)
	if cl == nil {
		t.Fatal("newConnLogger returned nil")
	}
	t.Cleanup(func() { cl.f.Close() })

	cl.log(r, src, dst, via)

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("conn log line is not valid JSON: %v (%q)", err, raw)
	}
	return rec
}

// The TCP path is the one that matters most: ~70 of portbridge's rules are TCP,
// and an accepted connection knows its own receiving address, so both IDs
// should be present with no configuration at all.
func TestLogEmitsBothCommunityIDsForTCP(t *testing.T) {
	r := rule{proto: "tcp", listenPort: "23", target: "10.8.0.2:19023"}
	src := &net.TCPAddr{IP: net.ParseIP("123.188.73.228"), Port: 42482}
	dst := &net.TCPAddr{IP: net.ParseIP("87.106.162.235"), Port: 23}
	via := &net.TCPAddr{IP: net.ParseIP("10.8.0.1"), Port: 51000}

	rec := logOneAndDecode(t, r, src, dst, via)

	// This is the exact value Suricata recorded for this real flow.
	if got := rec["community_id"]; got != "1:X5VoMLhACgm02hIBoeKOK6Pu2PY=" {
		t.Errorf("community_id = %v, want the Suricata-observed value", got)
	}
	relayed, ok := rec["community_id_relayed"].(string)
	if !ok || relayed == "" {
		t.Errorf("community_id_relayed missing: %v", rec["community_id_relayed"])
	}
	if relayed == rec["community_id"] {
		t.Error("relayed ID must hash the tunnel-side tuple, not repeat the public one")
	}
	// The pre-existing fields must survive unchanged.
	if rec["src_ip"] != "123.188.73.228" || rec["via_port"] != float64(51000) {
		t.Errorf("existing fields disturbed: %v", rec)
	}
}

// UDP listeners bind wildcard, so without PUBLIC_IP there is no honest way to
// name the destination. Omitting beats emitting an ID that would never join.
func TestLogOmitsPublicCommunityIDForUDPWithoutPublicIP(t *testing.T) {
	r := rule{proto: "udp", listenPort: "161", target: "10.8.0.2:19161"}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5353}
	via := &net.UDPAddr{IP: net.IPv4zero, Port: 34000}

	rec := logOneAndDecode(t, r, src, nil, via)

	if _, present := rec["community_id"]; present {
		t.Errorf("expected no community_id without PUBLIC_IP, got %v", rec["community_id"])
	}
	// The wildcard upstream bind is equally unknowable, so the relayed ID is
	// absent too — but the record itself must still be written.
	if rec["src_ip"] != "203.0.113.9" {
		t.Errorf("UDP record should still log normally: %v", rec)
	}
}

// With PUBLIC_IP configured, UDP becomes joinable — and must agree with what
// Suricata computes for the same datagram.
func TestLogUsesPublicIPForUDP(t *testing.T) {
	t.Setenv("PUBLIC_IP", "87.106.162.235")

	r := rule{proto: "udp", listenPort: "161", target: "10.8.0.2:19161"}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5353}

	rec := logOneAndDecode(t, r, src, nil, nil)

	want := communityIDFromParts("udp", "203.0.113.9", 5353, "87.106.162.235", 161)
	if want == "" {
		t.Fatal("test vector produced no ID")
	}
	if rec["community_id"] != want {
		t.Errorf("community_id = %v, want %v", rec["community_id"], want)
	}
}

// A real TCP destination must win over PUBLIC_IP: the socket knows which of our
// addresses was reached, and a misconfigured PUBLIC_IP should never override
// ground truth.
func TestLogPrefersSocketDestinationOverPublicIP(t *testing.T) {
	t.Setenv("PUBLIC_IP", "198.51.100.200")

	r := rule{proto: "tcp", listenPort: "23", target: "10.8.0.2:19023"}
	src := &net.TCPAddr{IP: net.ParseIP("123.188.73.228"), Port: 42482}
	dst := &net.TCPAddr{IP: net.ParseIP("87.106.162.235"), Port: 23}

	rec := logOneAndDecode(t, r, src, dst, nil)

	if got := rec["community_id"]; got != "1:X5VoMLhACgm02hIBoeKOK6Pu2PY=" {
		t.Errorf("community_id = %v, want the value for the real destination", got)
	}
}
