package main

import (
	"encoding/json"
	"testing"
)

// Fixture shape confirmed by actually running the patched sentrypeer
// binary locally (patched by sentrypeer/nul_byte_crash_patch.py) and
// sending it a real SIP REGISTER, then inspecting its real JSON log
// output: source_ip is a single "ip:port" string, sip_method/
// sip_user_agent are already flat top-level fields, no nested object, no
// "sensor" field.
const sentrypeerRealShapeLine = `{"app_name":"sentrypeer","app_version":"4.0.6","called_number":"test","collected_method":"passive","created_by_node_id":"c7c009d8-f121-49ab-9bf8-fe30eae903fc","destination_ip":"0.0.0.0:5060","event_timestamp":"2026-08-15 12:24:14.12157143","event_uuid":"d3d7904a-75b8-4d4a-ac5a-badba2b1ed48","sip_message":"REGISTER sip:127.0.0.1 SIP/2.0\r\n","sip_method":"REGISTER","sip_user_agent":"friendly-scanner","source_ip":"10.8.0.1:59637","transport_type":"UDP"}`

func TestEnrichSentrypeerLineRewritesTunnelPeerIPWhenResolved(t *testing.T) {
	vm := viaMap{59637: "203.0.113.9"}

	out, resolved := enrichSentrypeerLine([]byte(sentrypeerRealShapeLine), vm, viaMap{}, "sentrypeer")
	if !resolved {
		t.Fatal("expected resolved=true on a hit")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["source_ip"] != "203.0.113.9:59637" {
		t.Errorf("source_ip = %v, want 203.0.113.9:59637", e["source_ip"])
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
	if e["src_port"] != float64(59637) {
		t.Errorf("src_port = %v, want 59637", e["src_port"])
	}
	if e["sensor"] != "sentrypeer" {
		t.Errorf("sensor = %v, want sentrypeer", e["sensor"])
	}
	if e["protocol"] != "SIP" {
		t.Errorf("protocol = %v, want SIP", e["protocol"])
	}
	if e["sip_method"] != "REGISTER" {
		t.Errorf("sip_method = %v, want REGISTER", e["sip_method"])
	}
	if e["user_agent"] != "friendly-scanner" {
		t.Errorf("user_agent = %v, want friendly-scanner", e["user_agent"])
	}
}

func TestEnrichSentrypeerLineUnresolvedMissKeepsLineRetryable(t *testing.T) {
	out, resolved := enrichSentrypeerLine([]byte(sentrypeerRealShapeLine), viaMap{}, viaMap{}, "sentrypeer")
	if resolved {
		t.Fatal("expected resolved=false when the port isn't in vm yet")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["source_ip"] != "10.8.0.1:59637" {
		t.Errorf("source_ip = %v, want unchanged tunnel peer", e["source_ip"])
	}
}

func TestEnrichSentrypeerLineAlreadyResolvedIsUntouched(t *testing.T) {
	line := []byte(`{"sip_method":"REGISTER","sip_user_agent":"friendly-scanner","source_ip":"203.0.113.9:1234"}`)

	out, resolved := enrichSentrypeerLine(line, viaMap{}, viaMap{}, "sentrypeer")
	if !resolved {
		t.Fatal("expected resolved=true: source_ip is already the real IP")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
}

func TestEnrichSentrypeerLineNonEventLinePassesThrough(t *testing.T) {
	line := []byte(`{"level":"info","message":"Listening for incoming UDP connections..."}`)
	out, resolved := enrichSentrypeerLine(line, viaMap{}, viaMap{}, "sentrypeer")
	if !resolved {
		t.Fatal("expected resolved=true for a non-event startup log line")
	}
	if string(out) != string(line) {
		t.Errorf("out = %q, want unchanged %q", out, line)
	}
}

func TestEnrichSentrypeerLineUnparseableLinePassesThrough(t *testing.T) {
	line := []byte(`not json`)
	out, resolved := enrichSentrypeerLine(line, viaMap{}, viaMap{}, "sentrypeer")
	if !resolved {
		t.Fatal("expected resolved=true for unparseable input")
	}
	if string(out) != string(line) {
		t.Errorf("out = %q, want unchanged %q", out, line)
	}
}
