package main

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// esSensorPlaceholder writes a placeholder local file so rebuild()'s
// directory walk still discovers `sensor` as needing an ES query (#1103:
// discovery still comes from the local directory tree even though the
// sensor's own event content is read from Elasticsearch exclusively now).
func esSensorPlaceholder(t *testing.T, root, sensor string) {
	t.Helper()
	writeFileLines(t, filepath.Join(root, sensor, sensor+".json"), "{}")
}

// #241: portbridge queries p0f per connection and folds the OS guess into
// its own conn log (vps/portbridge/p0f.go) rather than shipping a second,
// independently-rotated log for the dashboard to correlate by IP -- so this
// rides the exact same buildViaMap join TestTunnelPeerIsRecoveredOrLeftUnattributed
// already exercises for src_ip recovery, just reading a different field off
// the same record.
func TestP0fOSGuessFillsFingerprintWhenNoneCaptured(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	writeLog(t, root, "portbridge/portbridge.json", map[string]any{
		"time": now, "sensor": "portbridge", "event": "connect", "proto": "tcp",
		"port": 21.0, "src_ip": "203.0.113.9", "src_port": 51000.0, "os": "Linux 3.11 and newer",
	})
	// dionaea's own events come from Elasticsearch exclusively now (#1103).
	// log_json shape, at the top level (dtagdevsec image) -- carries no
	// fingerprint of its own, unlike cowrie's client.kex/HASSH.
	esSensorPlaceholder(t, root, "dionaea")
	esSrv := httptest.NewServer(esSensorAndOverviewStub(t, map[string][]map[string]any{
		"dionaea": {{
			"timestamp": now, "src_ip": "203.0.113.9", "dst_port": 21.0,
			"connection": map[string]any{"protocol": "ftp", "transport": "tcp", "type": "accept"},
		}},
	}))
	defer esSrv.Close()

	s := &store{dir: root, es: newESClient(esSrv.URL, "")}
	s.rebuild()

	events := s.getEvents()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1 (portbridge records are transport metadata)", len(events))
	}
	if events[0].Fingerprint != "Linux 3.11 and newer" || events[0].FingerKind != "p0f OS" {
		t.Fatalf("Fingerprint=%q FingerKind=%q, want the p0f OS guess attached", events[0].Fingerprint, events[0].FingerKind)
	}
}

// A protocol-level fingerprint (HASSH here) is a direct observation of this
// specific session; p0f's OS guess is a fallback for when nothing better
// exists, not a replacement for one that does.
func TestP0fOSGuessNeverOverwritesExistingFingerprint(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	writeLog(t, root, "portbridge/portbridge.json", map[string]any{
		"time": now, "sensor": "portbridge", "event": "connect", "proto": "tcp",
		"port": 22.0, "src_ip": "203.0.113.9", "src_port": 51000.0, "os": "Linux 3.11 and newer",
	})
	esSensorPlaceholder(t, root, "cowrie")
	esSrv := httptest.NewServer(esSensorAndOverviewStub(t, map[string][]map[string]any{
		"cowrie": {{
			"timestamp": now, "eventid": "cowrie.client.kex", "src_ip": "203.0.113.9",
			"hassh": "aabbccddeeff00112233445566778899",
		}},
	}))
	defer esSrv.Close()

	s := &store{dir: root, es: newESClient(esSrv.URL, "")}
	s.rebuild()

	events := s.getEvents()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].FingerKind != "HASSH" {
		t.Fatalf("FingerKind=%q, want HASSH left untouched by the p0f fallback", events[0].FingerKind)
	}
	if events[0].Fingerprint != "aabbccddeeff00112233445566778899" {
		t.Fatalf("Fingerprint=%q, want the HASSH value preserved", events[0].Fingerprint)
	}
}

// No "os" field at all (p0f undeployed, or never matched this IP) must
// leave Fingerprint empty, not panic or fall back to some zero-value string.
func TestNoP0fRecordLeavesFingerprintEmpty(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	writeLog(t, root, "portbridge/portbridge.json", map[string]any{
		"time": now, "sensor": "portbridge", "event": "connect", "proto": "tcp",
		"port": 21.0, "src_ip": "203.0.113.9", "src_port": 51000.0,
	})
	esSensorPlaceholder(t, root, "dionaea")
	esSrv := httptest.NewServer(esSensorAndOverviewStub(t, map[string][]map[string]any{
		"dionaea": {{
			"timestamp": now, "src_ip": "203.0.113.9", "dst_port": 21.0,
			"connection": map[string]any{"protocol": "ftp", "transport": "tcp", "type": "accept"},
		}},
	}))
	defer esSrv.Close()

	s := &store{dir: root, es: newESClient(esSrv.URL, "")}
	s.rebuild()

	events := s.getEvents()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Fingerprint != "" || events[0].FingerKind != "" {
		t.Fatalf("Fingerprint=%q FingerKind=%q, want both empty with no p0f data available", events[0].Fingerprint, events[0].FingerKind)
	}
}
