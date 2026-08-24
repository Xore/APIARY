package main

import (
	"encoding/json"
	"testing"
)

// #1876: HellPot is reachable two ways and cannot tell them apart -- both
// present the tunnel peer as RemoteAddr. Only this worker can, because only
// it holds portbridge's connection log. These pin the adjudication.

func decode(t *testing.T, out []byte) map[string]any {
	t.Helper()
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return e
}

func line(remote, xff string) []byte {
	e := map[string]any{
		"level":       "info",
		"REMOTE_ADDR": remote,
		"URL":         "/wp-login.php",
		"USERAGENT":   "curl/8.18.0",
		"message":     "NEW",
	}
	if xff != "" {
		e["XFF"] = xff
	}
	raw, _ := json.Marshal(e)
	return raw
}

func TestViaPortWinsOverAContradictingHeader(t *testing.T) {
	// The portbridge path. portbridge relayed the connection and recorded
	// who made it; the header is attacker-authored on this path, so a
	// disagreement is a spoof attempt rather than a puzzle.
	vm := viaMap{52764: "203.0.113.7"}
	out, resolved := enrichHellpotLine(line("10.8.0.1:52764", "198.51.100.9"), vm, viaMap{}, "hellpot")
	if !resolved {
		t.Fatal("resolved = false, want true")
	}
	e := decode(t, out)
	if e["src_ip"] != "203.0.113.7" {
		t.Errorf("src_ip = %v, want the connection-derived address", e["src_ip"])
	}
	if e["src_ip_claimed"] != "198.51.100.9" {
		t.Errorf("src_ip_claimed = %v, want the header preserved as evidence", e["src_ip_claimed"])
	}
	if e["src_ip_conflict"] != true {
		t.Error("src_ip_conflict not set: a disagreement must be visible, not silently resolved")
	}
}

func TestAgreementIsNotFlaggedAsAConflict(t *testing.T) {
	vm := viaMap{52764: "203.0.113.7"}
	out, _ := enrichHellpotLine(line("10.8.0.1:52764", "203.0.113.7"), vm, viaMap{}, "hellpot")
	e := decode(t, out)
	if e["src_ip"] != "203.0.113.7" {
		t.Errorf("src_ip = %v", e["src_ip"])
	}
	if _, present := e["src_ip_conflict"]; present {
		t.Error("src_ip_conflict set when both joins agree")
	}
}

func TestHeaderIsUsedWhenPortbridgeNeverSawTheConnection(t *testing.T) {
	// The Traefik path. portbridge has no record, so the header is the only
	// evidence -- and the port belongs to the relay, not the client, so it
	// must not be reported as the client's.
	out, resolved := enrichHellpotLine(line("10.8.0.1:35518", "198.51.100.9"), viaMap{}, viaMap{}, "hellpot")
	if !resolved {
		t.Fatal("resolved = false, want true: the header resolved it")
	}
	e := decode(t, out)
	if e["src_ip"] != "198.51.100.9" {
		t.Errorf("src_ip = %v, want the forwarded client", e["src_ip"])
	}
	if _, present := e["src_port"]; present {
		t.Error("src_port reported on the Traefik path: that port is the relay's, not the client's")
	}
}

func TestTheLastForwardedHopWinsNotTheFirst(t *testing.T) {
	// Cloudflare appends the real client to whatever the client already
	// sent, so an attacker's own value ends up left of the truth.
	out, _ := enrichHellpotLine(
		line("10.8.0.1:35518", "1.2.3.4, 198.51.100.9"), viaMap{}, viaMap{}, "hellpot")
	e := decode(t, out)
	if e["src_ip"] != "198.51.100.9" {
		t.Errorf("src_ip = %v, want the last hop", e["src_ip"])
	}
}

func TestNeitherJoinLeavesItForRetry(t *testing.T) {
	out, resolved := enrichHellpotLine(line("10.8.0.1:35518", ""), viaMap{}, viaMap{}, "hellpot")
	if resolved {
		t.Error("resolved = true with no evidence: the caller must retry rather than accept the tunnel peer")
	}
	e := decode(t, out)
	if e["src_ip"] != "10.8.0.1" {
		t.Errorf("src_ip = %v, want the observed peer left in place", e["src_ip"])
	}
}

func TestAGarbageHeaderIsIgnoredRatherThanBelieved(t *testing.T) {
	// The header is attacker-authored. Anything that is not an address is
	// not evidence, and must not reach a field the dashboard renders as one.
	out, resolved := enrichHellpotLine(
		line("10.8.0.1:35518", "not-an-address"), viaMap{}, viaMap{}, "hellpot")
	if resolved {
		t.Error("resolved = true on an unusable header")
	}
	e := decode(t, out)
	if e["src_ip"] != "10.8.0.1" {
		t.Errorf("src_ip = %v, want the observed peer", e["src_ip"])
	}
}

func TestASourcePreservedConnectionIsLeftAlone(t *testing.T) {
	// RemoteAddr is already the attacker; no join applies and no header
	// should be able to override it.
	out, resolved := enrichHellpotLine(
		line("203.0.113.7:41000", "198.51.100.9"), viaMap{}, viaMap{}, "hellpot")
	if !resolved {
		t.Fatal("resolved = false")
	}
	e := decode(t, out)
	if e["src_ip"] != "203.0.113.7" {
		t.Errorf("src_ip = %v, want the observed address, not the header", e["src_ip"])
	}
}
