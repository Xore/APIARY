package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewIPBlockManagerNilWithoutES(t *testing.T) {
	if m := newIPBlockManager(nil); m != nil {
		t.Fatalf("expected nil ipBlockManager without an ES client, got %+v", m)
	}
}

func newTestIPBlockManager(t *testing.T) *ipBlockManager {
	t.Helper()
	store := newMemESDocStore()
	srv := httptest.NewServer(store.handler())
	t.Cleanup(srv.Close)
	es := newESClient(srv.URL, "")
	return newIPBlockManager(es)
}

func TestIPBlockRecordActiveAccountsForExpiry(t *testing.T) {
	cases := []struct {
		name string
		r    ipBlockRecord
		want bool
	}{
		{"not blocked", ipBlockRecord{Blocked: false}, false},
		{"blocked, no expiry", ipBlockRecord{Blocked: true}, true},
		{"blocked, expires in the future", ipBlockRecord{Blocked: true, ExpiresAt: time.Now().Add(time.Hour)}, true},
		{"blocked, expired", ipBlockRecord{Blocked: true, ExpiresAt: time.Now().Add(-time.Hour)}, false},
	}
	for _, c := range cases {
		if got := c.r.Active(); got != c.want {
			t.Errorf("%s: Active() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIPBlockCreateReopenAndReblockWithNewExpiry(t *testing.T) {
	m := newTestIPBlockManager(t)
	if !m.block("203.0.113.9", true, "alice", time.Time{}) {
		t.Fatal("block on a never-seen IP should succeed")
	}
	r := m.get("203.0.113.9")
	if !r.Active() || r.BlockedBy != "alice" || !r.ExpiresAt.IsZero() {
		t.Fatalf("unexpected record after block: %+v", r)
	}

	if !m.block("203.0.113.9", false, "", time.Time{}) {
		t.Fatal("unblock failed")
	}
	if m.get("203.0.113.9").Active() {
		t.Fatal("record still active after unblock")
	}
	afterUnblock, err := m.blockedIPs()
	if err != nil {
		t.Fatalf("blockedIPs(): %v", err)
	}
	if len(afterUnblock) != 0 {
		t.Fatalf("blockedIPs() after unblock = %v, want empty", afterUnblock)
	}

	// Re-blocking with a new expiry must apply even though Blocked is
	// already the target value on a stale read -- exercised here via two
	// sequential blocks with different expiries.
	expiry := time.Now().Add(48 * time.Hour)
	if !m.block("203.0.113.9", true, "bob", expiry) {
		t.Fatal("re-block with expiry failed")
	}
	r = m.get("203.0.113.9")
	if r.BlockedBy != "bob" || r.ExpiresAt.IsZero() {
		t.Fatalf("expiry not applied on re-block: %+v", r)
	}
}

func TestIPBlockedIPsExcludesExpired(t *testing.T) {
	m := newTestIPBlockManager(t)
	m.block("203.0.113.1", true, "alice", time.Time{})                // permanent
	m.block("203.0.113.2", true, "alice", time.Now().Add(time.Hour))  // future expiry, still active
	m.block("203.0.113.3", true, "alice", time.Now().Add(-time.Hour)) // already expired

	got, err := m.blockedIPs()
	if err != nil {
		t.Fatalf("blockedIPs(): %v", err)
	}
	want := []string{"203.0.113.1", "203.0.113.2"}
	if len(got) != len(want) {
		t.Fatalf("blockedIPs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("blockedIPs() = %v, want %v", got, want)
		}
	}
}

func TestServeManualBlackholeExportRendersPlainTextList(t *testing.T) {
	m := newTestIPBlockManager(t)
	m.block("203.0.113.9", true, "alice", time.Time{})
	m.block("198.51.100.1", true, "alice", time.Time{})
	s := &store{ipBlocks: m}

	r := httptest.NewRequest(http.MethodGet, "/export/portbridge-manual-blackhole.txt", nil)
	w := httptest.NewRecorder()
	s.serveManualBlackholeExport(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "203.0.113.9\n") || !strings.Contains(body, "198.51.100.1\n") {
		t.Fatalf("export missing expected IPs: %q", body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
}

func TestServeManualBlackholeExportEmptyWhenUnconfigured(t *testing.T) {
	s := &store{}
	r := httptest.NewRequest(http.MethodGet, "/export/portbridge-manual-blackhole.txt", nil)
	w := httptest.NewRecorder()
	s.serveManualBlackholeExport(w, r)
	if w.Body.String() != "" {
		t.Fatalf("expected empty export when ipBlocks is nil, got %q", w.Body.String())
	}
}

// Regression test for #1342: on a genuine Elasticsearch failure,
// serveManualBlackholeExport must respond with a 5xx status, not the same
// 200-with-empty-body response it gives for a legitimately empty block
// list -- vps/portbridge-manual-blackhole-refresh.sh treats this response
// as authoritative and has no other way to tell "ES is down, keep the
// existing rules" apart from "operator cleared every block".
func TestServeManualBlackholeExportReturns5xxOnESError(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "simulated ES outage", http.StatusInternalServerError)
	}))
	defer es.Close()
	m := newIPBlockManager(newESClient(es.URL, ""))
	s := &store{ipBlocks: m}

	r := httptest.NewRequest(http.MethodGet, "/export/portbridge-manual-blackhole.txt", nil)
	w := httptest.NewRecorder()
	s.serveManualBlackholeExport(w, r)

	if w.Code/100 == 2 {
		t.Fatalf("expected a non-2xx status on an ES failure, got %d with body %q", w.Code, w.Body.String())
	}
}

// TestServeManualBlackholeExportEmptyWithNoErrorWhenGenuinelyUnblocked is
// #1342's other half: a genuinely empty block list (no ES error at all)
// must still be the normal 200 with an empty body, distinct from the 5xx
// error case above.
func TestServeManualBlackholeExportEmptyWithNoErrorWhenGenuinelyUnblocked(t *testing.T) {
	m := newTestIPBlockManager(t) // real, reachable, empty ES index
	s := &store{ipBlocks: m}

	r := httptest.NewRequest(http.MethodGet, "/export/portbridge-manual-blackhole.txt", nil)
	w := httptest.NewRecorder()
	s.serveManualBlackholeExport(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a genuinely empty block list", w.Code)
	}
	if w.Body.String() != "" {
		t.Fatalf("expected empty body for a genuinely empty block list, got %q", w.Body.String())
	}
}

// Regression test for #1342: blockedIPs() must return the error instead of
// collapsing it to the same nil slice a genuinely empty index produces.
func TestBlockedIPsReturnsErrorOnESFailure(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "simulated ES outage", http.StatusInternalServerError)
	}))
	defer es.Close()
	m := newIPBlockManager(newESClient(es.URL, ""))

	ips, err := m.blockedIPs()
	if err == nil {
		t.Fatalf("expected an error on ES failure, got ips=%v err=nil", ips)
	}
}

func TestServeIPBlockActionBlocksAndRedirects(t *testing.T) {
	s := &store{ipBlocks: newTestIPBlockManager(t)}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/investigate/ip/block",
		strings.NewReader("ip=203.0.113.9&blocked=true&return=/investigate/ip/203.0.113.9"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveIPBlockAction(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/investigate/ip/203.0.113.9" {
		t.Fatalf("Location = %q", loc)
	}
	if !s.ipBlocks.get("203.0.113.9").Active() {
		t.Fatal("IP not blocked after the request")
	}
}

func TestServeIPBlockActionAppliesExpiresDays(t *testing.T) {
	s := &store{ipBlocks: newTestIPBlockManager(t)}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/investigate/ip/block",
		strings.NewReader("ip=203.0.113.9&blocked=true&expires_days=7"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveIPBlockAction(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	rec := s.ipBlocks.get("203.0.113.9")
	if rec.ExpiresAt.IsZero() {
		t.Fatal("expires_days=7 did not set an expiry")
	}
	wantAround := time.Now().Add(7 * 24 * time.Hour)
	if diff := rec.ExpiresAt.Sub(wantAround); diff > time.Minute || diff < -time.Minute {
		t.Fatalf("ExpiresAt = %v, want ~%v", rec.ExpiresAt, wantAround)
	}
}

func TestServeIPBlockActionRejectsBadExpiresDays(t *testing.T) {
	s := &store{ipBlocks: newTestIPBlockManager(t)}
	for _, bad := range []string{"0", "-1", "not-a-number"} {
		r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/investigate/ip/block",
			strings.NewReader("ip=203.0.113.9&blocked=true&expires_days="+bad))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://honeypot.example")
		w := httptest.NewRecorder()
		s.serveIPBlockAction(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expires_days=%q: status=%d, want 400", bad, w.Code)
		}
	}
}

func TestServeIPBlockActionRejectsInvalidIP(t *testing.T) {
	s := &store{ipBlocks: newTestIPBlockManager(t)}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/investigate/ip/block",
		strings.NewReader("ip=not-an-ip&blocked=true"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveIPBlockAction(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", w.Code)
	}
}

func TestServeIPBlockActionRequiresPOST(t *testing.T) {
	s := &store{ipBlocks: newTestIPBlockManager(t)}
	r := httptest.NewRequest(http.MethodGet, "https://honeypot.example/investigate/ip/block", nil)
	w := httptest.NewRecorder()
	s.serveIPBlockAction(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", w.Code)
	}
}

func TestServeIPBlockActionRejectsCrossOrigin(t *testing.T) {
	s := &store{ipBlocks: newTestIPBlockManager(t)}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/investigate/ip/block",
		strings.NewReader("ip=203.0.113.9&blocked=true"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.serveIPBlockAction(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", w.Code)
	}
}

func TestServeIPBlockActionRefusedWhenUnconfigured(t *testing.T) {
	s := &store{}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/investigate/ip/block",
		strings.NewReader("ip=203.0.113.9&blocked=true"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveIPBlockAction(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", w.Code)
	}
}

// TestServeIPBlockActionRejectsAnOversizedBody (#1323): r.Body is now
// wrapped in http.MaxBytesReader(w, r.Body, maxActionFormBody) before
// ParseForm() reads it -- this form only ever carries a handful of short
// fields (ip, blocked, expires_days, return), so a body well past
// maxActionFormBody must fail ParseForm() and 400, not be read in full.
func TestServeIPBlockActionRejectsAnOversizedBody(t *testing.T) {
	s := &store{ipBlocks: newTestIPBlockManager(t)}
	oversized := "ip=203.0.113.9&blocked=true&junk=" + strings.Repeat("A", maxActionFormBody+1)
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/investigate/ip/block",
		strings.NewReader(oversized))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveIPBlockAction(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 for a body past maxActionFormBody", w.Code)
	}
	if s.ipBlocks.get("203.0.113.9").Active() {
		t.Fatal("an oversized, rejected request must not have blocked the IP")
	}
}

// #914: the attacker block-state fragment must offer a block/unblock action for any IP,
// not just IPs IOC correlation happens to have flagged confirmed-malicious
// (that badge is informational only -- decided explicitly after scoping
// this narrower in an earlier draft).
func TestAttackerPageRendersBlockAction(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	open := attackerPage{IP: "203.0.113.9", Total: 1, Events: []storedEvent{{Time: "now", Sensor: "cowrie", SrcIP: "203.0.113.9"}}}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "attacker-block-body", &open); err != nil {
		t.Fatalf("render unblocked: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, `action="/investigate/ip/block"`) || !strings.Contains(body, `name="blocked" value="true"`) {
		t.Fatalf("unblocked IP is missing its block form: %s", body)
	}
	if strings.Contains(body, ">unblock<") {
		t.Fatal("unblocked IP must not show an unblock button")
	}

	blocked := open
	blocked.Block = ipBlockRecord{IP: "203.0.113.9", Blocked: true, BlockedBy: "alice", BlockedAt: time.Now()}
	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "attacker-block-body", &blocked); err != nil {
		t.Fatalf("render blocked: %v", err)
	}
	body = buf.String()
	if !strings.Contains(body, "blocked by alice") {
		t.Fatalf("blocked IP does not show who blocked it: %s", body)
	}
	if !strings.Contains(body, `name="blocked" value="false"`) {
		t.Fatal("blocked IP is missing its unblock form")
	}

	confirmed := open
	confirmed.ConfirmedMalicious = true
	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "attacker", &confirmed); err != nil {
		t.Fatalf("render confirmed-malicious: %v", err)
	}
	if !strings.Contains(buf.String(), "confirmed malicious") {
		t.Fatal("ConfirmedMalicious=true did not render the informational badge")
	}
}
