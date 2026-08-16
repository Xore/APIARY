package main

import (
	"encoding/json"
	"testing"
)

// Fixture shape confirmed by actually running the pinned beelzebub commit
// locally and inspecting its real log output -- standardOutStrategy
// (internal/builder/director.go) nests every event field under a top-level
// "event" key, alongside its own level/msg/status. A flat, unnested fixture
// would pass against a naive implementation but not against the real binary.
const beelzebubRealShapeLine = `{"level":"info","msg":"New Event","status":"Stateless","event":{"DateTime":"2026-08-15T07:01:51Z","RemoteAddr":"10.8.0.1:40414","Protocol":"HTTP","Command":"","Status":"Stateless","User":"","Password":"","HeadersMap":{"User-Agent":["curl/8.5.0"]},"HTTPMethod":"GET","RequestURI":"/wp-login.php","Description":"Wordpress 6.0","SourceIp":"10.8.0.1","SourcePort":"40414"}}`

func TestEnrichBeelzebubLineRewritesTunnelPeerIPWhenResolved(t *testing.T) {
	vm := viaMap{40414: "203.0.113.9"}

	out, resolved := enrichBeelzebubLine([]byte(beelzebubRealShapeLine), vm, viaMap{}, "beelzebub")
	if !resolved {
		t.Fatal("expected resolved=true on a hit")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	ev, ok := e["event"].(map[string]any)
	if !ok {
		t.Fatalf("output lost its nested \"event\" object: %v", e)
	}
	if ev["SourceIp"] != "203.0.113.9" {
		t.Errorf("event.SourceIp = %v, want 203.0.113.9", ev["SourceIp"])
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
	if e["sensor"] != "beelzebub" {
		t.Errorf("sensor = %v, want beelzebub", e["sensor"])
	}
	if e["protocol"] != "HTTP" {
		t.Errorf("protocol = %v, want HTTP", e["protocol"])
	}
	if e["path"] != "/wp-login.php" {
		t.Errorf("path = %v, want /wp-login.php", e["path"])
	}
}

func TestEnrichBeelzebubLineUnresolvedMissKeepsLineRetryable(t *testing.T) {
	out, resolved := enrichBeelzebubLine([]byte(beelzebubRealShapeLine), viaMap{}, viaMap{}, "beelzebub")
	if resolved {
		t.Fatal("expected resolved=false when the port isn't in vm yet")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	ev := e["event"].(map[string]any)
	if ev["SourceIp"] != tunnelPeerIP {
		t.Errorf("event.SourceIp = %v, want unchanged tunnel peer", ev["SourceIp"])
	}
}

func TestEnrichBeelzebubLineAlreadyResolvedIsUntouched(t *testing.T) {
	line := []byte(`{"level":"info","status":"Stateless","event":{"Protocol":"SSH","User":"root","SourceIp":"203.0.113.9","SourcePort":"1234"}}`)

	out, resolved := enrichBeelzebubLine(line, viaMap{}, viaMap{}, "beelzebub")
	if !resolved {
		t.Fatal("expected resolved=true: SourceIp is already the real IP")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v, want 203.0.113.9", e["src_ip"])
	}
	if e["username"] != "root" {
		t.Errorf("username = %v, want root", e["username"])
	}
}

func TestEnrichBeelzebubLineNonEventLinePassesThrough(t *testing.T) {
	line := []byte(`{"level":"info","msg":"Init service: Wordpress 6.0","port":":8880"}`)
	out, resolved := enrichBeelzebubLine(line, viaMap{}, viaMap{}, "beelzebub")
	if !resolved {
		t.Fatal("expected resolved=true for a non-event startup log line")
	}
	if string(out) != string(line) {
		t.Errorf("out = %q, want unchanged %q", out, line)
	}
}

func TestEnrichBeelzebubLineUnparseableLinePassesThrough(t *testing.T) {
	line := []byte(`not json`)
	out, resolved := enrichBeelzebubLine(line, viaMap{}, viaMap{}, "beelzebub")
	if !resolved {
		t.Fatal("expected resolved=true for unparseable input")
	}
	if string(out) != string(line) {
		t.Errorf("out = %q, want unchanged %q", out, line)
	}
}

// #1485: real line captured live against the actual running hp-beelzebub
// container (a real SSH login attempt, username "someuser" password
// "nexusai2025", against the bastion02 service on port 2200) -- not a
// hand-written fixture. Password was never mirrored to the flat "password"
// field before this fix, despite dashboard/classify.go's beelzebub block
// already reading e["password"] for its own detail line -- every real
// credential-capture event silently showed an empty password. Also proves
// canonical_user/canonical_pass (attacker-identity-worker's cross-sensor
// shared-credential signal) now gets set for beelzebub, matching every
// other credential-capturing sensor.
const beelzebubRealSSHCredLine = `{"event":{"DateTime":"2026-08-16T12:02:13Z","RemoteAddr":"10.8.0.2:55736","Protocol":"SSH","Command":"","CommandOutput":"","Status":"Stateless","Msg":"New SSH Login Attempt","ID":"eaff3139-e4fe-4f28-8fcb-82485e20d841","Environ":"","User":"someuser","Password":"nexusai2025","Client":"SSH-2.0-OpenSSH_10.3","Headers":"","HeadersMap":null,"Cookies":"","UserAgent":"","HostHTTPRequest":"","Body":"","HTTPMethod":"","RequestURI":"","Description":"SSH interactive bastion02","SourceIp":"10.8.0.2","SourcePort":"55736","TLSServerName":"","Handler":""},"level":"info","msg":"New Event","status":"Stateless"}`

func TestEnrichBeelzebubLinePromotesPasswordAndCanonicalCreds(t *testing.T) {
	out, resolved := enrichBeelzebubLine([]byte(beelzebubRealSSHCredLine), viaMap{}, viaMap{}, "beelzebub")
	if !resolved {
		t.Fatal("expected resolved=true (SourceIp is not the tunnel peer here)")
	}
	var e map[string]any
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if e["username"] != "someuser" {
		t.Errorf("username = %v, want someuser", e["username"])
	}
	if e["password"] != "nexusai2025" {
		t.Errorf("password = %v, want nexusai2025", e["password"])
	}
	if e["canonical_user"] != "someuser" {
		t.Errorf("canonical_user = %v, want someuser", e["canonical_user"])
	}
	if e["canonical_pass"] != "nexusai2025" {
		t.Errorf("canonical_pass = %v, want nexusai2025", e["canonical_pass"])
	}
}
