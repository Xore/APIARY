package main

import (
	"net/http/httptest"
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
