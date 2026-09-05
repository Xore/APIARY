package main

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClientIPTakesTheHopCloudflareAppended covers #1350 and its
// correction in #1908. Cloudflare appends the real client to any
// X-Forwarded-For the client already sent rather than replacing it, so an
// attacker controlling the leftmost hop must not be able to spoof SrcIP.
// This test asserted the *rightmost* hop for that reason, which was wrong:
// Traefik appends the peer it saw, a Cloudflare edge node, so the chain
// ends one past the client and proxied requests were filed against
// Cloudflare. Live example: `<client>, 172.69.150.126`.
func TestClientIPTakesTheHopCloudflareAppended(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = tunnelPeerIP + ":12345"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9, 172.69.150.126")

	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP() = %q, want the hop Cloudflare appended %q", got, "203.0.113.9")
	}
}

// TestClientIPPrefersCFConnectingIP covers the direct answer: one value,
// the client, set by Cloudflare, with no chain to index into.
func TestClientIPPrefersCFConnectingIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = tunnelPeerIP + ":12345"
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 172.69.150.126")

	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP() = %q, want %q", got, "203.0.113.9")
	}
}

// TestClientIPSingleXFFHop covers a chain nothing appended to -- there is
// no proxy entry to step back past, so the lone hop is the answer.
func TestClientIPSingleXFFHop(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = tunnelPeerIP + ":12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")

	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP() = %q, want %q", got, "203.0.113.9")
	}
}

// TestClientIPPreferRemoteAddrWhenNotTunnelPeer covers the PROXY-protocol
// path: when RemoteAddr has already been rewritten to the real attacker
// address (not the tunnel peer), XFF must be ignored entirely, even if an
// attacker sets it.
func TestClientIPPreferRemoteAddrWhenNotTunnelPeer(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.7:54321"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")

	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("clientIP() = %q, want RemoteAddr's own host %q, XFF must be ignored", got, "198.51.100.7")
	}
}

// TestServeHTTPSkipsLoggingOwnHealthcheck covers #1677: main()'s -healthcheck
// mode dials 127.0.0.1 directly, and that connection is accepted by the same
// listener as real traffic -- a real external request can never present that
// address (it always arrives as either a real attacker IP via a ":pp"
// portbridge rule or the tunnel peer otherwise), so a loopback RemoteAddr can
// only be the container's own healthcheck. It must still get a 200 (the
// healthcheck's own success check) but must not be logged as a sensor event.
func TestServeHTTPSkipsLoggingOwnHealthcheck(t *testing.T) {
	var buf bytes.Buffer
	s := &server{log: &logger{out: &buf}, sensor: "http-honeypot"}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 (the healthcheck's own success check)", w.Code)
	}
	if buf.Len() != 0 {
		t.Fatalf("logged an event for the container's own healthcheck: %s", buf.String())
	}
}

// TestServeHTTPLogsRealRequests confirms the guard above doesn't swallow
// genuine traffic -- only a literal loopback RemoteAddr is skipped.
func TestServeHTTPLogsRealRequests(t *testing.T) {
	var buf bytes.Buffer
	s := &server{log: &logger{out: &buf}, sensor: "http-honeypot"}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:54321"
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if !strings.Contains(buf.String(), "203.0.113.9") {
		t.Fatalf("a genuine request was not logged: %s", buf.String())
	}
}

// TestClassifySwitchvoxCVE covers #2919 (CVE-2026-9586): an exact match on
// the vulnerable Switchvox /pa endpoint, distinct from generic "scan", and
// confirms the exact-match guard doesn't false-positive on an unrelated
// path that merely contains "pa".
func TestClassifySwitchvoxCVE(t *testing.T) {
	if got := classify("/pa"); got != "switchvox-cve-2026-9586" {
		t.Fatalf("classify(%q) = %q, want switchvox-cve-2026-9586", "/pa", got)
	}
	if got := classify("/api/params"); got == "switchvox-cve-2026-9586" {
		t.Fatalf("classify(%q) false-positived as switchvox-cve-2026-9586", "/api/params")
	}
}
