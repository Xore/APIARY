package main

import (
	"encoding/json"
	"testing"
)

func TestEnrichLineRewritesTunnelPeerIPWhenResolved(t *testing.T) {
	vm := viaMap{45282: "203.0.113.9"}
	line := []byte(`{"src_ip":"10.8.0.1","src_port":45282,"sensor":"cowrie"}`)

	out, resolved := enrichLine(line, vm)
	if !resolved {
		t.Fatal("expected resolved=true on a hit")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Fatalf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
	if e["sensor"] != "cowrie" {
		t.Fatalf("other fields lost: %+v", e)
	}
}

func TestEnrichLineLeavesUnresolvedForRetry(t *testing.T) {
	vm := viaMap{} // no matching via_port yet
	line := []byte(`{"src_ip":"10.8.0.1","src_port":45282}`)

	out, resolved := enrichLine(line, vm)
	if resolved {
		t.Fatal("expected resolved=false on a miss -- caller must retry, not give up immediately")
	}
	if string(out) != string(line) {
		t.Fatalf("unresolved line was mutated: %s", out)
	}
}

func TestEnrichLinePassesThroughAlreadyCorrectIP(t *testing.T) {
	vm := viaMap{45282: "203.0.113.9"}
	line := []byte(`{"src_ip":"198.51.100.1","src_port":45282}`)

	out, resolved := enrichLine(line, vm)
	if !resolved {
		t.Fatal("a real, non-tunnel-peer IP must never wait on a retry")
	}
	if string(out) != string(line) {
		t.Fatalf("already-correct line was rewritten: %s", out)
	}
}

func TestEnrichLinePassesThroughUnparseableInput(t *testing.T) {
	line := []byte(`not json`)
	out, resolved := enrichLine(line, viaMap{})
	if !resolved || string(out) != string(line) {
		t.Fatalf("unparseable line must pass through unchanged and resolved, got resolved=%v out=%s", resolved, out)
	}
}

func TestEnrichLineNoSrcPortPassesThrough(t *testing.T) {
	line := []byte(`{"src_ip":"10.8.0.1"}`)
	out, resolved := enrichLine(line, viaMap{45282: "203.0.113.9"})
	if !resolved || string(out) != string(line) {
		t.Fatalf("a tunnel-peer line with no src_port has nothing left to retry, got resolved=%v out=%s", resolved, out)
	}
}

func TestExtractSrcPortFallsBackToNestedConnectionShape(t *testing.T) {
	var e map[string]any
	json.Unmarshal([]byte(`{"connection":{"remote_port":45678}}`), &e)
	if got := extractSrcPort(e); got != 45678 {
		t.Fatalf("extractSrcPort = %d, want 45678", got)
	}
}

func TestExtractSrcPortPrefersTopLevel(t *testing.T) {
	var e map[string]any
	json.Unmarshal([]byte(`{"src_port":111,"connection":{"remote_port":222}}`), &e)
	if got := extractSrcPort(e); got != 111 {
		t.Fatalf("extractSrcPort = %d, want top-level 111", got)
	}
}
