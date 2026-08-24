package main

import (
	"net/http"
	"testing"
)

// #1889: the ports are the half of the flow tuple this sensor never
// logged, so Community ID could not be computed and no flow-level join
// worked for it. The rule that matters is when *not* to report one.

func TestClientPortIsTheAttackersOwnPort(t *testing.T) {
	// Behind a ":pp" portbridge rule the PROXY-aware listener has already
	// rewritten RemoteAddr to the real client, address and port together.
	r := &http.Request{RemoteAddr: "203.0.113.7:54321"}
	if got := clientPort(r); got != 54321 {
		t.Errorf("clientPort = %d, want 54321", got)
	}
}

func TestClientPortIsAbsentWhenARelayReplacedIt(t *testing.T) {
	// On the Traefik path RemoteAddr is the tunnel peer and the port
	// belongs to socat's outbound connection. Reporting it would produce a
	// Community ID hashing a tuple no packet ever had, joining this event
	// to somebody else's flow -- worse than having no port at all.
	r := &http.Request{RemoteAddr: tunnelPeerIP + ":35518"}
	if got := clientPort(r); got != 0 {
		t.Errorf("clientPort = %d, want 0 for a relayed request", got)
	}
}

func TestClientPortSurvivesAMalformedRemoteAddr(t *testing.T) {
	for _, addr := range []string{"", "203.0.113.7", "garbage", "203.0.113.7:notaport"} {
		if got := clientPort(&http.Request{RemoteAddr: addr}); got != 0 {
			t.Errorf("clientPort(%q) = %d, want 0", addr, got)
		}
	}
}

func TestListenPortReadsTheConfiguredAddress(t *testing.T) {
	cases := map[string]int{
		":8080":          8080,
		"0.0.0.0:19081":  19081,
		"127.0.0.1:8080": 8080,
		"[::]:8080":      8080,
		"":               0,
		"not-an-address": 0,
		":notaport":      0,
	}
	for addr, want := range cases {
		if got := listenPort(addr); got != want {
			t.Errorf("listenPort(%q) = %d, want %d", addr, got, want)
		}
	}
}

func TestTheAddressAndThePortAgree(t *testing.T) {
	// One source of truth: the server reports the port it actually listens
	// on, so a changed LISTEN_ADDR cannot leave the two disagreeing.
	addr := "0.0.0.0:19081"
	s := &server{listenPort: listenPort(addr)}
	if s.listenPort != 19081 {
		t.Errorf("server listenPort = %d, want 19081", s.listenPort)
	}
}
