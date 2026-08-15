package main

import (
	"encoding/json"
	"testing"
)

// Fixture shape confirmed by actually running the pinned galah commit
// end to end (against a fake Ollama backend standing in for
// galah-llm-broker) and inspecting real event_log.json output --
// srcIP/srcPort are already flat, httpRequest is nested with
// bodySha256/request/userAgent inside it, and srcHost/tags reflect
// galah's own (pre-join, unreliable) enrichment. tunnelPeerIP substituted
// in place of the real run's 127.0.0.1 to exercise the join path.
const galahRealShapeLine = `{"level":"info","msg":"successfulResponse","port":"18889","httpRequest":{"body":"somebody=1","bodySha256":"3ab1934661e28794cb670d590a1d6cfd9b8d2870ed4ae92c4b4e114048651fce","headers":{"User-Agent":"test-agent-galah"},"method":"POST","protocolVersion":"HTTP/1.1","request":"/wp-login.php?a=1","sessionID":"abc","userAgent":"test-agent-galah"},"eventTime":"2026-08-15T13:26:35Z","tags":null,"httpResponse":{"headers":{"Content-Type":"text/html"},"body":"<html></html>"},"responseMetadata":{"generationSource":"llm","info":{"model":"qwen3.5:4b","provider":"ollama"}},"srcIP":"10.8.0.1","srcHost":"localhost","srcPort":"49762","sensorName":"host01"}`

func TestEnrichGalahLineRewritesTunnelPeerIPWhenResolved(t *testing.T) {
	vm := viaMap{49762: "203.0.113.9"}

	out, resolved := enrichGalahLine([]byte(galahRealShapeLine), vm, viaMap{}, "galah")
	if !resolved {
		t.Fatal("expected resolved=true on a hit")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["srcIP"] != "203.0.113.9" {
		t.Errorf("srcIP = %v, want 203.0.113.9", e["srcIP"])
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
	if e["src_port"] != float64(49762) {
		t.Errorf("src_port = %v, want 49762", e["src_port"])
	}
	if e["sensor"] != "galah" {
		t.Errorf("sensor = %v, want galah", e["sensor"])
	}
	if e["protocol"] != "HTTP" {
		t.Errorf("protocol = %v, want HTTP", e["protocol"])
	}
	if e["dst_port"] != "18889" {
		t.Errorf("dst_port = %v, want 18889", e["dst_port"])
	}
	if e["path"] != "/wp-login.php?a=1" {
		t.Errorf("path = %v, want /wp-login.php?a=1", e["path"])
	}
	if e["user_agent"] != "test-agent-galah" {
		t.Errorf("user_agent = %v, want test-agent-galah", e["user_agent"])
	}
	if e["body_sha256"] != "3ab1934661e28794cb670d590a1d6cfd9b8d2870ed4ae92c4b4e114048651fce" {
		t.Errorf("body_sha256 = %v, want the real sha", e["body_sha256"])
	}
	// srcHost is galah's own pre-join enrichment against the tunnel peer --
	// deliberately left untouched, not promoted, not deleted.
	if e["srcHost"] != "localhost" {
		t.Errorf("srcHost = %v, want untouched localhost", e["srcHost"])
	}
}

func TestEnrichGalahLineUnresolvedMissKeepsLineRetryable(t *testing.T) {
	out, resolved := enrichGalahLine([]byte(galahRealShapeLine), viaMap{}, viaMap{}, "galah")
	if resolved {
		t.Fatal("expected resolved=false on a via_port miss")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["src_ip"] != tunnelPeerIP {
		t.Errorf("src_ip = %v, want tunnel peer %v pending resolution", e["src_ip"], tunnelPeerIP)
	}
}

func TestEnrichGalahLineAlreadyResolvedIsUntouched(t *testing.T) {
	line := `{"msg":"successfulResponse","port":"18889","srcIP":"203.0.113.9","srcPort":"49762","httpRequest":{"request":"/x","userAgent":"ua"}}`
	out, resolved := enrichGalahLine([]byte(line), viaMap{}, viaMap{}, "galah")
	if !resolved {
		t.Fatal("expected resolved=true when srcIP is already the real IP")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
	if e["sensor"] != "galah" {
		t.Errorf("sensor = %v, want galah", e["sensor"])
	}
}

func TestEnrichGalahLineNonEventLinePassesThrough(t *testing.T) {
	line := `{"level":"info","msg":"starting galah on port 18889"}`
	out, resolved := enrichGalahLine([]byte(line), viaMap{49762: "203.0.113.9"}, viaMap{}, "galah")
	if !resolved {
		t.Fatal("expected resolved=true for a non-event line (nothing to retry)")
	}
	if string(out) != line {
		t.Errorf("non-event line was modified: got %q", out)
	}
}

func TestEnrichGalahLineUnparseableLinePassesThrough(t *testing.T) {
	line := `not json`
	out, resolved := enrichGalahLine([]byte(line), viaMap{}, viaMap{}, "galah")
	if !resolved {
		t.Fatal("expected resolved=true for an unparseable line")
	}
	if string(out) != line {
		t.Errorf("unparseable line was modified: got %q", out)
	}
}
