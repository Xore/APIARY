package main

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// poisonedTransport fails the test the instant anything in the process
// attempts a real network round trip through http.DefaultTransport --
// which is what an *http.Client{} with no explicit Transport field (exactly
// what liveSender would build) uses. Installed for the whole test binary in
// TestMain, not just this file: proves no code path anywhere in this
// package can reach the network during these tests, not merely that the
// functions this file happens to call don't.
type poisonedTransport struct{ t *testing.T }

func (p poisonedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p.t.Fatalf("FAIL: outbound network request attempted: %s %s -- dry-run must never reach the network", req.Method, req.URL)
	return nil, nil
}

// TestDryRunIsTheDefaultAndNeverReachesTheNetwork is the property #68 /
// WORK-LEDGER.md rule 7 requires to be proven by a test, not asserted by
// convention: with REPORTER_LIVE unset (this program's default, see
// newSender), a reportable event produces a would_report audit entry and
// the network is never touched -- proven by poisoning the process-wide
// default transport above, not just by inspecting which sender type got
// constructed.
func TestDryRunIsTheDefaultAndNeverReachesTheNetwork(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = poisonedTransport{t: t}
	t.Cleanup(func() { http.DefaultTransport = original })

	dir := t.TempDir()
	st, err := openStore(filepath.Join(dir, "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	wl, err := loadWhitelist("")
	if err != nil {
		t.Fatal(err)
	}

	var audit strings.Builder
	al := newAuditLog(&audit)

	// The exact gate this test exists to prove: no REPORTER_LIVE env var,
	// no API key -- newSender must return dryRunSender, never liveSender.
	send := newSender(false, "", al)
	if _, ok := send.(dryRunSender); !ok {
		t.Fatalf("newSender with live=false returned %T, want dryRunSender", send)
	}

	sendBD := newBlocklistDeSender(false, "", "", al)
	if _, ok := sendBD.(dryRunBlocklistDeSender); !ok {
		t.Fatalf("newBlocklistDeSender with live=false returned %T, want dryRunBlocklistDeSender", sendBD)
	}

	proc := newProcessor(wl, st, send, sendBD, al, 24*time.Hour, 1)

	// A real-shaped cowrie login attempt from a real-looking public IP --
	// exactly the event that, if this reporter were live, would produce an
	// outbound AbuseIPDB POST.
	line := []byte(`{"eventid":"cowrie.login.failed","src_ip":"203.0.113.7","username":"root","password":"admin","time":"2026-08-02T00:00:00.000Z"}`)
	proc.handle("cowrie", line)

	got := audit.String()
	if !strings.Contains(got, `"action":"would_report"`) {
		t.Fatalf("audit log missing would_report entry: %s", got)
	}
	if !strings.Contains(got, `"ip":"203.0.113.7"`) {
		t.Fatalf("audit log missing the reported IP: %s", got)
	}
	if strings.Contains(got, `"action":"reported"`) {
		t.Fatalf("audit log contains a real 'reported' entry in dry-run: %s", got)
	}
}

// TestLiveRequiresBothTheFlagAndAnAPIKey proves the gate fails closed: live
// mode needs REPORTER_LIVE *and* a real key. Either alone must still
// produce dryRunSender.
func TestLiveRequiresBothTheFlagAndAnAPIKey(t *testing.T) {
	al := newAuditLog(&strings.Builder{})

	cases := []struct {
		name   string
		live   bool
		apiKey string
	}{
		{"neither set", false, ""},
		{"flag set, no key", true, ""},
		{"key set, flag not", false, "fake-key-not-a-real-credential"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			send := newSender(c.live, c.apiKey, al)
			if _, ok := send.(dryRunSender); !ok {
				t.Fatalf("newSender(live=%v, apiKey=%q) returned %T, want dryRunSender", c.live, c.apiKey, send)
			}
		})
	}
}

// TestBlocklistDeLiveRequiresFlagEmailAndAPIKey mirrors
// TestLiveRequiresBothTheFlagAndAnAPIKey for the second destination: live
// mode needs REPORTER_LIVE *and* both a sender identity and an API key. Any
// one of the three missing must still produce dryRunBlocklistDeSender.
func TestBlocklistDeLiveRequiresFlagEmailAndAPIKey(t *testing.T) {
	al := newAuditLog(&strings.Builder{})

	cases := []struct {
		name   string
		live   bool
		email  string
		apiKey string
	}{
		{"nothing set", false, "", ""},
		{"flag set, nothing else", true, "", ""},
		{"flag and key set, no email", true, "", "fake-key-not-a-real-credential"},
		{"flag and email set, no key", true, "sender@example.com", ""},
		{"email and key set, flag not", false, "sender@example.com", "fake-key-not-a-real-credential"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			send := newBlocklistDeSender(c.live, c.email, c.apiKey, al)
			if _, ok := send.(dryRunBlocklistDeSender); !ok {
				t.Fatalf("newBlocklistDeSender(live=%v, email=%q, apiKey=%q) returned %T, want dryRunBlocklistDeSender",
					c.live, c.email, c.apiKey, send)
			}
		})
	}
}
