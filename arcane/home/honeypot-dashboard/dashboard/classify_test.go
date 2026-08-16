package main

import (
	"strings"
	"testing"
)

// TestWhenNormalizesDisplayToUTC (#198): different sensors' timestamp
// formats parse into different time.Location values -- a Z-suffixed string
// parses as UTC, suricata's eve.json "...+0200" parses into a fixed +0200
// offset, and an unlabeled string with no zone in the reference layout also
// defaults to UTC per time.Parse's own documented behavior. The unix-epoch
// path (time.Unix) returns the server process's local zone. None of that
// may leak into the displayed string: two events at the exact same real
// instant, logged by different sensors in different formats, must produce
// the exact same wall-clock display.
func TestWhenNormalizesDisplayToUTC(t *testing.T) {
	cases := []struct {
		name string
		e    map[string]any
	}{
		{"Z-suffixed UTC (cowrie-shaped)", map[string]any{"timestamp": "2026-08-01T13:52:10.013146Z"}},
		{"suricata eve.json +0200 offset", map[string]any{"timestamp": "2026-08-01T15:52:10.013146+0200"}},
		{"unlabeled, no zone in the layout (dionaea-shaped)", map[string]any{"timestamp": "2026-08-01T13:52:10.013146"}},
		{"unix epoch seconds", map[string]any{"timestamp": float64(1785592330)}}, // 2026-08-01T13:52:10Z
	}

	const want = "2026-08-01 13:52:10"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, whenStr := when(tc.e)
			if whenStr != want {
				t.Fatalf("whenStr = %q, want %q (all four represent the same real instant and must display identically)", whenStr, want)
			}
		})
	}
}

// TestWhenAgeMathIsLocationIndependent guards the other half of #198's fix:
// normalizing the *display* string must not change the returned time.Time
// itself -- age/sort comparisons elsewhere (aggregate.go) are correct
// regardless of Location, and there is no reason to touch that value.
func TestWhenAgeMathIsLocationIndependent(t *testing.T) {
	utc, _ := when(map[string]any{"timestamp": "2026-08-01T13:52:10Z"})
	offset, _ := when(map[string]any{"timestamp": "2026-08-01T15:52:10+0200"})
	if !utc.Equal(offset) {
		t.Fatalf("the same real instant in two formats must compare equal: %v vs %v", utc, offset)
	}
}

// TestDionaeaDCERPCRequestSurfacesUUIDAndOpnum (#624): log_incident's
// generic handler already stores uuid/opnum/transfersyntax for every
// smb.dcerpc.bind/request incident -- this dashboard branch just never read
// them, so an operator saw only "smb.dcerpc.request" with no indication of
// which RPC interface or operation was actually targeted.
func TestDionaeaDCERPCRequestSurfacesUUIDAndOpnum(t *testing.T) {
	ev := classify(map[string]any{
		"origin": "dionaea.modules.python.smb.dcerpc.request",
		"data": map[string]any{
			"con":   map[string]any{"local_host": "203.0.113.5"},
			"uuid":  "4b324fc8-1670-01d3-1278-5a47bf6ee188",
			"opnum": float64(9),
		},
	}, "dionaea")
	if !strings.Contains(ev.detail, "uuid=4b324fc8-1670-01d3-1278-5a47bf6ee188") {
		t.Fatalf("detail must include the RPC interface uuid, got %q", ev.detail)
	}
	if !strings.Contains(ev.detail, "opnum=9") {
		t.Fatalf("detail must include the operation number, got %q", ev.detail)
	}
}

// TestDionaeaDCERPCBindSurfacesTransferSyntax covers the bind side of #624
// (transfersyntax, no opnum -- a bind negotiates the interface, it doesn't
// invoke an operation on it).
func TestDionaeaDCERPCBindSurfacesTransferSyntax(t *testing.T) {
	ev := classify(map[string]any{
		"origin": "dionaea.modules.python.smb.dcerpc.bind",
		"data": map[string]any{
			"con":            map[string]any{"local_host": "203.0.113.5"},
			"uuid":           "4b324fc8-1670-01d3-1278-5a47bf6ee188",
			"transfersyntax": "8a885d04-1ceb-11c9-9fe8-08002b104860",
		},
	}, "dionaea")
	if !strings.Contains(ev.detail, "uuid=4b324fc8-1670-01d3-1278-5a47bf6ee188") {
		t.Fatalf("detail must include the RPC interface uuid, got %q", ev.detail)
	}
	if !strings.Contains(ev.detail, "transfersyntax=8a885d04-1ceb-11c9-9fe8-08002b104860") {
		t.Fatalf("detail must include the transfer syntax, got %q", ev.detail)
	}
	if strings.Contains(ev.detail, "opnum=") {
		t.Fatalf("a bind has no opnum, must not fabricate one: %q", ev.detail)
	}
}

// TestDionaeaIncidentWithoutDCERPCFieldsIsUnaffected proves the #624 change
// is additive: an incident with no uuid (every non-dcerpc origin -- login
// attempts, downloads, etc.) must not gain a stray "uuid=" in its detail.
func TestDionaeaIncidentWithoutDCERPCFieldsIsUnaffected(t *testing.T) {
	ev := classify(map[string]any{
		"origin": "dionaea.modules.python.ftp.login",
		"data": map[string]any{
			"con":      map[string]any{"local_host": "203.0.113.5"},
			"username": "anonymous",
			"password": "guest@example.com",
		},
	}, "dionaea")
	if strings.Contains(ev.detail, "uuid=") {
		t.Fatalf("a non-dcerpc incident must not gain a uuid field: %q", ev.detail)
	}
}

// TestDionaeaExploitIncidentSurfacesNameAndCVE (#1276): data.cve/data.name
// carry the actual exploit identity on an exploit-attempt incident (live
// sample: name "DoublePulsar connection attempt", cve
// "CVE-2017-0144..CVE-2017-0148") -- previously unread, so ev.detail only
// ever showed the generic Python module path (kind), e.g.
// "modules.python.smb.exploit", with no indication of which real-world
// exploit was actually being tried.
func TestDionaeaExploitIncidentSurfacesNameAndCVE(t *testing.T) {
	ev := classify(map[string]any{
		"origin": "dionaea.modules.python.smb.exploit",
		"data": map[string]any{
			"connection": map[string]any{"protocol": "smbd", "remote_ip": "203.0.113.5", "local_port": float64(445)},
			"cve":        "CVE-2017-0144..CVE-2017-0148",
			"name":       "DoublePulsar connection attempt",
		},
	}, "dionaea")
	if ev.detail != "DoublePulsar connection attempt (CVE-2017-0144..CVE-2017-0148)" {
		t.Fatalf("detail = %q, want the exploit name plus its CVE range, not the raw module path", ev.detail)
	}
}

// TestDionaeaIncidentWithNameButNoCVESurfacesNameOnly covers a named
// incident with no known CVE mapping (e.g. #1276's own live sample, "MS17-010
// SMB RCE exploit scanning" carries both, but a future named-only incident
// kind should not fabricate a CVE parenthetical).
func TestDionaeaIncidentWithNameButNoCVESurfacesNameOnly(t *testing.T) {
	ev := classify(map[string]any{
		"origin": "dionaea.modules.python.smb.exploit",
		"data": map[string]any{
			"connection": map[string]any{"protocol": "smbd", "remote_ip": "203.0.113.5", "local_port": float64(445)},
			"name":       "MS17-010 SMB RCE exploit scanning",
		},
	}, "dionaea")
	if ev.detail != "MS17-010 SMB RCE exploit scanning" {
		t.Fatalf("detail = %q, want the bare name with no CVE parenthetical", ev.detail)
	}
}

// TestDionaeaIncidentWithoutNameFallsBackToKind proves the #1276 change is
// additive: an incident with neither data.name nor data.cve (login/bind/
// connection incidents, the vast majority) must still show the generic
// module-path kind exactly as before.
func TestDionaeaIncidentWithoutNameFallsBackToKind(t *testing.T) {
	ev := classify(map[string]any{
		"origin": "dionaea.modules.python.ftp.login",
		"data": map[string]any{
			"con":      map[string]any{"local_host": "203.0.113.5"},
			"username": "anonymous",
			"password": "guest@example.com",
		},
	}, "dionaea")
	if !strings.HasPrefix(ev.detail, "modules.python.ftp.login") {
		t.Fatalf("detail = %q, want it to still fall back to the module-path kind", ev.detail)
	}
}

// TestBeelzebubSSHAuthSurfacesCredentials covers #1418's classify.go block
// reading the flat lowercase fields ip-enrichment-worker/beelzebub.go
// promotes, not upstream's own PascalCase Event field names.
func TestBeelzebubSSHAuthSurfacesCredentials(t *testing.T) {
	ev := classify(map[string]any{
		"sensor":   "beelzebub",
		"protocol": "SSH",
		"username": "root",
		"password": "changeme",
	}, "beelzebub")
	if ev.sensor != "beelzebub" {
		t.Fatalf("sensor = %q, want beelzebub", ev.sensor)
	}
	if ev.proto != "ssh" {
		t.Fatalf("proto = %q, want lowercased ssh", ev.proto)
	}
	if !ev.isLogin {
		t.Fatal("expected isLogin=true when username/password are present")
	}
	if !strings.Contains(ev.detail, "root / changeme") {
		t.Fatalf("detail = %q, want it to surface the attempted credentials", ev.detail)
	}
}

// TestBeelzebubHTTPCommandTakesPriorityOverPath proves a command (an LLM
// or regex-plugin response body) wins over a bare path when both are
// present -- matches cowrie's own command-over-auth precedence just above.
func TestBeelzebubHTTPCommandTakesPriorityOverPath(t *testing.T) {
	ev := classify(map[string]any{
		"sensor":   "beelzebub",
		"protocol": "HTTP",
		"path":     "/wp-login.php",
		"command":  "POST /wp-login.php",
	}, "beelzebub")
	if !strings.HasPrefix(ev.detail, "cmd:") {
		t.Fatalf("detail = %q, want command to take priority over path", ev.detail)
	}
}

func TestGalahSurfacesPathAndUserAgent(t *testing.T) {
	ev := classify(map[string]any{
		"sensor":     "galah",
		"protocol":   "HTTP",
		"dst_port":   "8888",
		"path":       "/wp-login.php?a=1",
		"user_agent": "curl/8.18.0",
		"msg":        "successfulResponse",
	}, "galah")
	if ev.sensor != "galah" {
		t.Fatalf("sensor = %q, want galah", ev.sensor)
	}
	if ev.proto != "http" {
		t.Fatalf("proto = %q, want lowercased http", ev.proto)
	}
	if ev.port != "8888" {
		t.Fatalf("port = %q, want 8888", ev.port)
	}
	if ev.fingerKind != "User-Agent" {
		t.Fatalf("fingerKind = %q, want User-Agent", ev.fingerKind)
	}
	if !strings.Contains(ev.detail, "/wp-login.php?a=1") {
		t.Fatalf("detail = %q, want it to surface the request path", ev.detail)
	}
}

func TestGalahWithoutPathFallsBackToMsg(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "galah",
		"msg":    "successfulResponse",
	}, "galah")
	if ev.detail != "successfulResponse" {
		t.Fatalf("detail = %q, want the raw msg fallback", ev.detail)
	}
}

// TestWordpotLoginAttemptSurfacesCredentials covers #1421's classify.go
// block reading the flat lowercase fields ip-enrichment-worker/wordpot.go
// promotes from wordpot_patch.py's fixed message templates.
func TestWordpotLoginAttemptSurfacesCredentials(t *testing.T) {
	ev := classify(map[string]any{
		"sensor":   "wordpot",
		"protocol": "HTTP",
		"path":     "/wp-login.php",
		"username": "admin",
		"password": "hunter2",
	}, "wordpot")
	if ev.sensor != "wordpot" {
		t.Fatalf("sensor = %q, want wordpot", ev.sensor)
	}
	if !ev.isLogin {
		t.Fatal("expected isLogin=true when a password is present")
	}
	if !strings.Contains(ev.detail, "admin / hunter2") {
		t.Fatalf("detail = %q, want it to surface the attempted credentials", ev.detail)
	}
}

// TestWordpotPluginProbeTakesPriorityOverBarePath proves a plugin probe
// (the more specific signal) wins over a bare path when both are present.
func TestWordpotPluginProbeTakesPriorityOverBarePath(t *testing.T) {
	ev := classify(map[string]any{
		"sensor":   "wordpot",
		"protocol": "HTTP",
		"path":     "/wp-content/plugins/akismet/readme.txt",
		"plugin":   "akismet",
	}, "wordpot")
	if !strings.HasPrefix(ev.detail, "plugin probe: akismet") {
		t.Fatalf("detail = %q, want plugin probe to take priority over a bare path", ev.detail)
	}
}
