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

// TestEnrichDionaeaIncidentLineRewritesRealShape uses the exact
// dionaea_incident.json shape confirmed live against the homeserver
// (dionaea.modules.python.smb.exploit's DoublePulsar incident) -- no
// top-level src_ip at all, the tunnel peer buried under data.connection.
func TestEnrichDionaeaIncidentLineRewritesRealShape(t *testing.T) {
	vm := viaMap{26878: "203.0.113.9"}
	line := []byte(`{"timestamp":"2026-08-05T22:52:47.367326","name":"dionaea","origin":"dionaea.modules.python.smb.exploit","data":{"cve":"CVE-2017-0144..CVE-2017-0148","name":"DoublePulsar connection attempt","connection":{"protocol":"smbd","transport":"tcp","local_ip":"172.16.7.2","local_port":445,"remote_hostname":"","remote_ip":"10.8.0.1","remote_port":26878,"id":"29a4ff749258c8c3d7c99fd665808355f5a0b0d10a095b9610019779cdffd6a3"}}}`)

	out, resolved := enrichDionaeaIncidentLine(line, vm, viaMap{}, "dionaea-incident")
	if !resolved {
		t.Fatal("expected resolved")
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	conn := got["data"].(map[string]any)["connection"].(map[string]any)
	if conn["remote_ip"] != "203.0.113.9" {
		t.Fatalf("remote_ip = %v, want rewritten to 203.0.113.9", conn["remote_ip"])
	}
	if conn["remote_port"].(float64) != 26878 {
		t.Fatalf("remote_port was disturbed: %v", conn["remote_port"])
	}
}

// TestEnrichDionaeaIncidentLineRewritesBothChildAndParent uses the real
// dionaea.connection.link shape, which nests two separate connection-shape
// objects (child + parent) rather than one under "connection".
func TestEnrichDionaeaIncidentLineRewritesBothChildAndParent(t *testing.T) {
	vm := viaMap{57611: "203.0.113.9", 59378: "203.0.113.10"}
	line := []byte(`{"origin":"dionaea.connection.link","data":{"child":{"protocol":"SipCall","remote_ip":"10.8.0.1","remote_port":57611},"parent":{"protocol":"SipSession","remote_ip":"10.8.0.1","remote_port":59378}}}`)

	out, resolved := enrichDionaeaIncidentLine(line, vm, viaMap{}, "dionaea-incident")
	if !resolved {
		t.Fatal("expected resolved")
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	data := got["data"].(map[string]any)
	if data["child"].(map[string]any)["remote_ip"] != "203.0.113.9" {
		t.Fatalf("child.remote_ip not rewritten: %+v", data["child"])
	}
	if data["parent"].(map[string]any)["remote_ip"] != "203.0.113.10" {
		t.Fatalf("parent.remote_ip not rewritten: %+v", data["parent"])
	}
}

func TestEnrichDionaeaIncidentLineHoldsForRetryWhenPortMissing(t *testing.T) {
	line := []byte(`{"origin":"dionaea.modules.python.ftp.command","data":{"connection":{"remote_ip":"10.8.0.1","remote_port":30966}}}`)
	out, resolved := enrichDionaeaIncidentLine(line, viaMap{}, viaMap{}, "dionaea-incident")
	if resolved {
		t.Fatal("expected unresolved: port not yet in the via map")
	}
	if string(out) != string(line) {
		t.Fatalf("unresolved line must be returned unchanged, got %s", out)
	}
}

func TestEnrichDionaeaIncidentLineLeavesAlreadyRealIPsUntouched(t *testing.T) {
	vm := viaMap{44576: "should-not-be-used"}
	line := []byte(`{"origin":"dionaea.connection.tcp.accept","data":{"connection":{"remote_ip":"198.51.100.7","remote_port":44576}}}`)
	out, resolved := enrichDionaeaIncidentLine(line, vm, viaMap{}, "dionaea-incident")
	if !resolved || string(out) != string(line) {
		t.Fatalf("a non-tunnel-peer remote_ip must pass through unchanged, got resolved=%v out=%s", resolved, out)
	}
}

func TestEnrichDionaeaIncidentLinePassesThroughUnparseableInput(t *testing.T) {
	line := []byte(`not json`)
	out, resolved := enrichDionaeaIncidentLine(line, viaMap{}, viaMap{}, "")
	if !resolved || string(out) != string(line) {
		t.Fatalf("unparseable line must pass through unchanged and resolved, got resolved=%v out=%s", resolved, out)
	}
}
