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
