package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testIKEMaxSessions is the session cap these tests hand handleIKEPacket. It
// is deliberately far above the handful of sessions they create, so the
// cap-and-evict path (#2324) never fires and they keep testing only the
// one-reply-per-source behavior.
const testIKEMaxSessions = 4096

func buildIKEPacket(exchangeType byte) []byte {
	h := ikeHeader(0x1122334455667788, 0, payloadNone, exchangeType, flagInitiator, 0, ikeHeaderSize)
	return h
}

// TestIKEResponderRepliesOnceThenGoesSilent is the behavior this whole
// package's IKE side exists to reproduce (see ike.go's doc comment): a
// real DH+nonce reply to the first IKE_SA_INIT from an address, then no
// further reply to anything else from that same address, ever (until it
// starts an entirely new IKE_SA_INIT exchange).
func TestIKEResponderRepliesOnceThenGoesSilent(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	log := newLogger("")
	var mu sync.Mutex
	sessions := map[string]ikeSession{}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	send := func(exchangeType byte) {
		pkt := buildIKEPacket(exchangeType)
		if _, err := client.WriteToUDP(pkt, serverAddr); err != nil {
			t.Fatal(err)
		}
	}
	recvReply := func() ([]byte, bool) {
		client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 4096)
		n, err := client.Read(buf)
		if err != nil {
			return nil, false
		}
		return buf[:n], true
	}
	serveOne := func() {
		buf := make([]byte, 4096)
		n, raddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		handleIKEPacket(serverConn, raddr, data, log, 500, &mu, sessions, testIKEMaxSessions)
	}

	// First IKE_SA_INIT -> real reply.
	send(exchangeInit)
	serveOne()
	reply, ok := recvReply()
	if !ok {
		t.Fatal("expected a reply to the first IKE_SA_INIT")
	}
	if exchangeType, ok := parseIKEHeader(reply); !ok || exchangeType != exchangeInit {
		t.Fatalf("reply exchange type = %d ok=%v, want IKE_SA_INIT", exchangeType, ok)
	}

	// Second packet (any type) from the same address -> no reply.
	send(exchangeInit)
	serveOne()
	if _, ok := recvReply(); ok {
		t.Fatal("expected no reply to the second packet from an already-replied session")
	}

	// Session was dropped by the second packet, so a THIRD packet (a fresh
	// IKE_SA_INIT) starts over and gets a reply again.
	send(exchangeInit)
	serveOne()
	if _, ok := recvReply(); !ok {
		t.Fatal("expected a reply again after the session reset")
	}
}

func TestIKEResponderIgnoresMalformedDatagram(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	log := newLogger("")
	var mu sync.Mutex
	sessions := map[string]ikeSession{}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	if _, err := client.WriteToUDP([]byte("short"), serverAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, raddr, err := serverConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	handleIKEPacket(serverConn, raddr, buf[:n], log, 500, &mu, sessions, testIKEMaxSessions) // must not panic

	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := client.Read(buf); err == nil {
		t.Fatal("expected no reply to a malformed datagram")
	}
}

func TestParseIKEHeaderReturnsSameExchangeTypeItWasBuiltWith(t *testing.T) {
	pkt := buildIKEPacket(exchangeAuth)
	et, ok := parseIKEHeader(pkt)
	if !ok || et != exchangeAuth {
		t.Fatalf("exchangeType = %d ok=%v, want IKE_AUTH", et, ok)
	}
}

// TestEmitSetsProtoByEventKind guards a real gap found after live deploy:
// this sensor covers two distinct protocols on two ports, and proto was
// never populated at all (always empty), breaking the dashboard's
// attack-path filter for every event this sensor emits.
func TestEmitSetsProtoByEventKind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	l := newLogger(path)
	l.emit(event{Event: "ike_sa_init"})
	l.emit(event{Event: "get"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	var ikeEvent, httpEvent event
	if err := json.Unmarshal([]byte(lines[0]), &ikeEvent); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &httpEvent); err != nil {
		t.Fatal(err)
	}
	if ikeEvent.Proto != "ike" {
		t.Fatalf("ike_sa_init proto = %q, want ike", ikeEvent.Proto)
	}
	if httpEvent.Proto != "https" {
		t.Fatalf("get proto = %q, want https", httpEvent.Proto)
	}
}
