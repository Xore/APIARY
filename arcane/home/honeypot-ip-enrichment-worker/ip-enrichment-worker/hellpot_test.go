package main

import (
	"encoding/json"
	"testing"
)

// Fixture shape confirmed by actually running the patched hellpot binary
// locally (patched by hellpot/router_patch.py) and inspecting its real log
// output: REMOTE_ADDR is a single "ip:port" string, no nested object, no
// "sensor" field. A pre-patch fixture (REMOTE_ADDR without a port, or a
// client-spoofed X-Real-IP value) would pass against a naive
// implementation but not reflect what the real, patched binary emits.
const hellpotRealShapeLine = `{"level":"info","USERAGENT":"curl/8.18.0","REMOTE_ADDR":"10.8.0.1:52764","URL":"/wp-login.php","time":"2026-08-15T07:50:22Z","message":"NEW"}`

func TestEnrichHellpotLineRewritesTunnelPeerIPWhenResolved(t *testing.T) {
	vm := viaMap{52764: "203.0.113.9"}

	out, resolved := enrichHellpotLine([]byte(hellpotRealShapeLine), vm, viaMap{}, "hellpot")
	if !resolved {
		t.Fatal("expected resolved=true on a hit")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["REMOTE_ADDR"] != "203.0.113.9:52764" {
		t.Errorf("REMOTE_ADDR = %v, want 203.0.113.9:52764", e["REMOTE_ADDR"])
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
	if e["src_port"] != float64(52764) {
		t.Errorf("src_port = %v, want 52764", e["src_port"])
	}
	if e["sensor"] != "hellpot" {
		t.Errorf("sensor = %v, want hellpot", e["sensor"])
	}
	if e["protocol"] != "HTTP" {
		t.Errorf("protocol = %v, want HTTP", e["protocol"])
	}
	if e["path"] != "/wp-login.php" {
		t.Errorf("path = %v, want /wp-login.php", e["path"])
	}
	if e["user_agent"] != "curl/8.18.0" {
		t.Errorf("user_agent = %v, want curl/8.18.0", e["user_agent"])
	}
}

func TestEnrichHellpotLineUnresolvedMissKeepsLineRetryable(t *testing.T) {
	out, resolved := enrichHellpotLine([]byte(hellpotRealShapeLine), viaMap{}, viaMap{}, "hellpot")
	if resolved {
		t.Fatal("expected resolved=false when the port isn't in vm yet")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["REMOTE_ADDR"] != "10.8.0.1:52764" {
		t.Errorf("REMOTE_ADDR = %v, want unchanged tunnel peer", e["REMOTE_ADDR"])
	}
}

func TestEnrichHellpotLineAlreadyResolvedIsUntouched(t *testing.T) {
	line := []byte(`{"level":"info","USERAGENT":"curl/8.18.0","REMOTE_ADDR":"203.0.113.9:1234","URL":"/","message":"NEW"}`)

	out, resolved := enrichHellpotLine(line, viaMap{}, viaMap{}, "hellpot")
	if !resolved {
		t.Fatal("expected resolved=true: REMOTE_ADDR is already the real IP")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
}

func TestEnrichHellpotLineNonRequestLinePassesThrough(t *testing.T) {
	line := []byte(`{"level":"info","message":"Listening and serving HTTP...","caller":"0.0.0.0:8080"}`)
	out, resolved := enrichHellpotLine(line, viaMap{}, viaMap{}, "hellpot")
	if !resolved {
		t.Fatal("expected resolved=true for a non-request startup log line")
	}
	if string(out) != string(line) {
		t.Errorf("out = %q, want unchanged %q", out, line)
	}
}

func TestEnrichHellpotLineUnparseableLinePassesThrough(t *testing.T) {
	line := []byte(`not json`)
	out, resolved := enrichHellpotLine(line, viaMap{}, viaMap{}, "hellpot")
	if !resolved {
		t.Fatal("expected resolved=true for unparseable input")
	}
	if string(out) != string(line) {
		t.Errorf("out = %q, want unchanged %q", out, line)
	}
}
