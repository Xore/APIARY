package main

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClientIPTakesRightmostXFFHop covers #1350: Cloudflare appends the
// real client IP to any X-Forwarded-For value the client already sent
// rather than replacing it, and socat forwards byte-for-byte with no
// header rewriting -- so an attacker who sets their own X-Forwarded-For
// must not be able to spoof the logged SrcIP by controlling the leftmost
// hop.
func TestClientIPTakesRightmostXFFHop(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = tunnelPeerIP + ":12345"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")

	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP() = %q, want the rightmost (Cloudflare-appended) hop %q", got, "203.0.113.9")
	}
}

// TestClientIPSingleXFFHop covers the common case -- no spoofed prefix, just
// the one hop Cloudflare appended.
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
