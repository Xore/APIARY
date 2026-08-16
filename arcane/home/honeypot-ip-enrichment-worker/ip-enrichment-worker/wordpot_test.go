package main

import (
	"encoding/json"
	"testing"
)

// Fixture shapes confirmed by actually running the patched wordpot binary
// locally (patched by wordpot/wordpot_patch.py) and inspecting its real
// log output: {"message","level","time"}, "message" carries a leading
// "ip:port" prefix from the patched port-preserving REMOTE_ADDR.
const wordpotLoginAttemptLine = `{"message": "10.8.0.1:47760 tried to login with username admin and password hunter2", "level": "INFO", "time": "2026-08-15T12:05:05"}`

func TestEnrichWordpotLineRewritesTunnelPeerIPWhenResolved(t *testing.T) {
	vm := viaMap{47760: "203.0.113.9"}

	out, resolved := enrichWordpotLine([]byte(wordpotLoginAttemptLine), vm, viaMap{}, "wordpot")
	if !resolved {
		t.Fatal("expected resolved=true on a hit")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["message"] != "203.0.113.9:47760 tried to login with username admin and password hunter2" {
		t.Errorf("message = %v, want rewritten ip", e["message"])
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
	if e["src_port"] != float64(47760) {
		t.Errorf("src_port = %v, want 47760", e["src_port"])
	}
	if e["sensor"] != "wordpot" {
		t.Errorf("sensor = %v, want wordpot", e["sensor"])
	}
	if e["protocol"] != "HTTP" {
		t.Errorf("protocol = %v, want HTTP", e["protocol"])
	}
	if e["path"] != "/wp-login.php" {
		t.Errorf("path = %v, want /wp-login.php", e["path"])
	}
	if e["username"] != "admin" {
		t.Errorf("username = %v, want admin", e["username"])
	}
	if e["password"] != "hunter2" {
		t.Errorf("password = %v, want hunter2", e["password"])
	}
}

func TestEnrichWordpotLinePluginProbeExtractsPluginAndPath(t *testing.T) {
	line := `{"message": "203.0.113.9:47786 probed for plugin \"akismet\" with path: /readme.txt", "level": "INFO", "time": "2026-08-15T12:05:05"}`
	out, resolved := enrichWordpotLine([]byte(line), viaMap{}, viaMap{}, "wordpot")
	if !resolved {
		t.Fatal("expected resolved=true: ip already real (non-tunnel-peer)")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["plugin"] != "akismet" {
		t.Errorf("plugin = %v, want akismet", e["plugin"])
	}
	if e["path"] != "/wp-content/plugins/akismet/readme.txt" {
		t.Errorf("path = %v, want /wp-content/plugins/akismet/readme.txt", e["path"])
	}
}

func TestEnrichWordpotLineUnresolvedMissKeepsLineRetryable(t *testing.T) {
	out, resolved := enrichWordpotLine([]byte(wordpotLoginAttemptLine), viaMap{}, viaMap{}, "wordpot")
	if resolved {
		t.Fatal("expected resolved=false when the port isn't in vm yet")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["message"] != "10.8.0.1:47760 tried to login with username admin and password hunter2" {
		t.Errorf("message = %v, want unchanged tunnel peer", e["message"])
	}
}

func TestEnrichWordpotLineStartupLinePassesThrough(t *testing.T) {
	line := []byte(`{"message": "Honeypot started on 0.0.0.0:80", "level": "INFO", "time": "2026-08-15T12:04:59"}`)
	out, resolved := enrichWordpotLine(line, viaMap{}, viaMap{}, "wordpot")
	if !resolved {
		t.Fatal("expected resolved=true for a non-request startup log line")
	}
	if string(out) != string(line) {
		t.Errorf("out = %q, want unchanged %q", out, line)
	}
}

func TestEnrichWordpotLineUnparseableLinePassesThrough(t *testing.T) {
	line := []byte(`not json`)
	out, resolved := enrichWordpotLine(line, viaMap{}, viaMap{}, "wordpot")
	if !resolved {
		t.Fatal("expected resolved=true for unparseable input")
	}
	if string(out) != string(line) {
		t.Errorf("out = %q, want unchanged %q", out, line)
	}
}
