package main

import (
	"encoding/json"
	"testing"
)

func TestEnrichLineRewritesTunnelPeerIPWhenResolved(t *testing.T) {
	vm := viaMap{45282: "203.0.113.9"}
	line := []byte(`{"src_ip":"10.8.0.1","src_port":45282,"sensor":"cowrie"}`)

	out, resolved := enrichLine(line, vm, viaMap{}, "")
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

	out, resolved := enrichLine(line, vm, viaMap{}, "")
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

	out, resolved := enrichLine(line, vm, viaMap{}, "")
	if !resolved {
		t.Fatal("a real, non-tunnel-peer IP must never wait on a retry")
	}
	if string(out) != string(line) {
		t.Fatalf("already-correct line was rewritten: %s", out)
	}
}

func TestEnrichLineFixesConpotS71200DestPort(t *testing.T) {
	line := []byte(`{"src_ip":"198.51.100.1","dst_port":502,"sensorid":"conpot"}`)

	out, resolved := enrichLine(line, viaMap{}, viaMap{}, "conpot-s7-1200")
	if !resolved {
		t.Fatal("a dst_port-only fix must never wait on a retry")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["dst_port"] != float64(1502) {
		t.Fatalf("dst_port = %v, want 1502", e["dst_port"])
	}
}

func TestEnrichLineFixesConpotS71500DestPort(t *testing.T) {
	line := []byte(`{"src_ip":"198.51.100.1","dst_port":102,"sensorid":"conpot"}`)

	out, _ := enrichLine(line, viaMap{}, viaMap{}, "conpot-s7-1500")
	var e map[string]any
	json.Unmarshal(out, &e)
	if e["dst_port"] != float64(2102) {
		t.Fatalf("dst_port = %v, want 2102", e["dst_port"])
	}
}

func TestEnrichLineLeavesOtherPersonasDestPortAlone(t *testing.T) {
	line := []byte(`{"src_ip":"198.51.100.1","dst_port":502}`)

	for _, persona := range []string{"", "conpot", "conpot-iec104", "cowrie"} {
		out, _ := enrichLine(line, viaMap{}, viaMap{}, persona)
		if string(out) != string(line) {
			t.Fatalf("persona %q: dst_port was rewritten unexpectedly: %s", persona, out)
		}
	}
}

func TestEnrichLineAppliesBothFixesTogether(t *testing.T) {
	vm := viaMap{45282: "203.0.113.9"}
	line := []byte(`{"src_ip":"10.8.0.1","src_port":45282,"dst_port":502}`)

	out, resolved := enrichLine(line, vm, viaMap{}, "conpot-s7-1200")
	if !resolved {
		t.Fatal("expected resolved=true on a src_ip hit")
	}
	var e map[string]any
	json.Unmarshal(out, &e)
	if e["src_ip"] != "203.0.113.9" {
		t.Fatalf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
	if e["dst_port"] != float64(1502) {
		t.Fatalf("dst_port = %v, want 1502", e["dst_port"])
	}
}

func TestEnrichLineKeepsDestPortFixOnSrcIPMiss(t *testing.T) {
	// src_ip needs a portbridge join that hasn't landed yet, but the
	// dst_port fix doesn't depend on that join and must not be dropped --
	// see enrich.go's comment on the vm-miss branch for why this matters:
	// pendingQueue.drain writes exactly this return value once the line
	// times out.
	line := []byte(`{"src_ip":"10.8.0.1","src_port":45282,"dst_port":502}`)

	out, resolved := enrichLine(line, viaMap{}, viaMap{}, "conpot-s7-1200")
	if resolved {
		t.Fatal("expected resolved=false -- src_ip still needs a retry")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["dst_port"] != float64(1502) {
		t.Fatalf("dst_port = %v, want 1502 even while src_ip is still unresolved", e["dst_port"])
	}
}

func TestEnrichLineResolvesTftpRelayedDionaeaEvent(t *testing.T) {
	tftpVM := viaMap{42285: "203.0.113.9"}
	line := []byte(`{"src_ip":"172.16.7.3","src_port":42285,"connection":{"protocol":"TftpServerHandler","transport":"udp","type":"connect"}}`)

	out, resolved := enrichLine(line, viaMap{}, tftpVM, "dionaea")
	if !resolved {
		t.Fatal("expected resolved=true on a tftp session-map hit")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Fatalf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
}

func TestEnrichLineLeavesTftpRelayedEventForRetryOnMiss(t *testing.T) {
	line := []byte(`{"src_ip":"172.16.7.3","src_port":42285,"connection":{"protocol":"TftpServerHandler"}}`)

	out, resolved := enrichLine(line, viaMap{}, viaMap{}, "dionaea")
	if resolved {
		t.Fatal("expected resolved=false -- no matching relay_port yet")
	}
	if string(out) != string(line) {
		t.Fatalf("unresolved tftp line was mutated: %s", out)
	}
}

func TestEnrichLineIgnoresNonTftpDionaeaEvents(t *testing.T) {
	// A non-TFTP dionaea event with the same relay-internal-looking src_ip
	// must not be treated as a TFTP relay record -- only the
	// TftpServerHandler connection.protocol marks that shape.
	tftpVM := viaMap{42285: "203.0.113.9"}
	line := []byte(`{"src_ip":"172.16.7.3","src_port":42285,"connection":{"protocol":"SMBDServer"}}`)

	out, resolved := enrichLine(line, viaMap{}, tftpVM, "dionaea")
	if !resolved || string(out) != string(line) {
		t.Fatalf("non-TFTP dionaea event should pass through unresolved-and-unchanged=false, got resolved=%v out=%s", resolved, out)
	}
}

func TestEnrichLineIgnoresTftpShapeFromOtherPersonas(t *testing.T) {
	tftpVM := viaMap{42285: "203.0.113.9"}
	line := []byte(`{"src_ip":"172.16.7.3","src_port":42285,"connection":{"protocol":"TftpServerHandler"}}`)

	out, resolved := enrichLine(line, viaMap{}, tftpVM, "conpot")
	if !resolved || string(out) != string(line) {
		t.Fatalf("TFTP-shaped event from a non-dionaea persona must pass through unchanged, got resolved=%v out=%s", resolved, out)
	}
}

func TestEnrichLinePassesThroughUnparseableInput(t *testing.T) {
	line := []byte(`not json`)
	out, resolved := enrichLine(line, viaMap{}, viaMap{}, "")
	if !resolved || string(out) != string(line) {
		t.Fatalf("unparseable line must pass through unchanged and resolved, got resolved=%v out=%s", resolved, out)
	}
}

func TestEnrichLineNoSrcPortPassesThrough(t *testing.T) {
	line := []byte(`{"src_ip":"10.8.0.1"}`)
	out, resolved := enrichLine(line, viaMap{45282: "203.0.113.9"}, viaMap{}, "")
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
