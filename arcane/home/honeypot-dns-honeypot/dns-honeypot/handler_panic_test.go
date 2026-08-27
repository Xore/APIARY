package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #2210: handlePacket is entered fresh off ReadFromUDP for every datagram
// and walks attacker bytes bare through buildCappedResponse's question walk,
// so these are the forced-panic probes for the boundary at the top of it,
// shaped like the #2186 harnesses (dicompot/dnp3/multipot): what is asserted
// is that the per-datagram entrypoint RETURNS from hostile input and that
// subsequent queries are still answered and logged afterwards. The fault is
// injected by wrapping the connection rather than crafted bytes because this
// honeypot's own parsing path is bounds-checked (dns.go refuses to walk past
// short or pointer-labeled input); the boundary exists for what future edits
// -- and vendored parsing past it -- could add.

// panicReplyConn stands in for a connection whose response path detonates
// the receiver mid-handler: every WriteToUDP faults instead of delivering a
// reply. A nil embedded writer is fine -- the override shadows everything
// the promoted interface would offer.
type panicReplyConn struct{ udpReplyWriter }

func (c panicReplyConn) WriteToUDP([]byte, *net.UDPAddr) (int, error) { panic("crafted #2210 query") }

// readEventsFromFile mirrors dicompot's #2186 harness shape: the logger here
// writes straight to stdout plus an append-only file, so the file leg is
// what tests read back.
func readEventsFromFile(t *testing.T, path string) []event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

// A panicking datagram must return from handlePacket after emitting exactly
// one handler_panic event carrying the recovered value and the attacker
// attribution -- not kill the process. main() hands each datagram its own
// goroutine, so the probe reproduces that shape: without the boundary the
// panic unwinds out of handlePacket and ends the whole test binary, exactly
// what restart: unless-stopped turns into sensor death on a bad datagram.
func TestHandlePacketContainsQueryPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-honeypot.json")
	log := newLogger(path)

	// src_ip/src_port are real here because addr is whatever the datagram
	// claimed (fabricated onto a TEST-NET-3 documentation range like
	// dns.go's own fakeAIP) -- nothing dialable ever sees the wire.
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40321}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handlePacket(panicReplyConn{nil}, addr, buildQuery("example.com", qtypeA), log, 53)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handlePacket did not return from a panicking datagram -- the recover boundary is gone")
	}

	events := readEventsFromFile(t, path)
	if len(events) != 1 {
		t.Fatalf("expected exactly one event from the panicking datagram, got %+v", events)
	}
	ev := events[0]
	if ev.Event != "handler_panic" {
		t.Fatalf("event = %q, want handler_panic", ev.Event)
	}
	if !strings.Contains(ev.Data, "crafted #2210 query") {
		t.Fatalf("handler_panic lost the recovered value: %+v", ev)
	}
	if ev.SrcIP != "203.0.113.7" || ev.SrcPort != 40321 || ev.Port != 53 {
		t.Fatalf("handler_panic missing attacker/listener attribution: %+v", ev)
	}
}

// Continuity is the point: after one datagram died inside its goroutine, the
// next ones must still be served normally -- here that means a real bounded
// response written back to a real loopback socket, and a second follow-up
// from a non-loopback source landing its normal query event in the pipeline.
func TestHandlePacketStillServesQueriesAfterPanickedDatagram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-honeypot.json")
	log := newLogger(path)

	done := make(chan struct{})
	go func() {
		defer close(done)
		handlePacket(panicReplyConn{nil}, &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40321},
			buildQuery("example.com", qtypeA), log, 53)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("panicking datagram was not contained")
	}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer client.Close()

	req := buildQuery("example.com", qtypeA)
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		handlePacket(listener, client.LocalAddr().(*net.UDPAddr), req, log, 53)
	}()
	select {
	case <-done2:
	case <-time.After(10 * time.Second):
		t.Fatal("the answering datagram was not contained")
	}

	// Same decode-and-reply shape the loopback pair itself answers with
	// (cf. TestBuildCappedResponseEchoesQuestionAndAnswersA): any capped
	// response echoes the ID and carries QR, whatever branch the ratio cap
	// picked for this request size.
	reply := make([]byte, 512)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := client.Read(reply)
	if err != nil {
		t.Fatalf("no response for the follow-up query after a panicking predecessor: %v", err)
	}
	resp := reply[:n]
	if resp[0] != req[0] || resp[1] != req[1] {
		t.Fatalf("follow-up response did not echo the request ID: req=%x resp=%x", req[0:2], resp[0:2])
	}
	if resp[2]&0x80 == 0 {
		t.Fatalf("QR bit not set in follow-up response: %x", resp)
	}

	// Non-loopback follow-up: the normal query logging path must also keep
	// running past the panicked predecessor.
	done3 := make(chan struct{})
	go func() {
		defer close(done3)
		handlePacket(listener, &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40322}, req, log, 53)
	}()
	select {
	case <-done3:
	case <-time.After(10 * time.Second):
		t.Fatal("the logged datagram was not contained")
	}

	var panics, queries int
	for _, ev := range readEventsFromFile(t, path) {
		switch ev.Event {
		case "handler_panic":
			panics++
		case "query":
			queries++
			if ev.SrcIP != "203.0.113.7" || ev.SrcPort != 40322 || ev.Port != 53 {
				t.Errorf("follow-up query missing attacker/listener attribution: %+v", ev)
			}
			if ev.Query != "example.com" || ev.ReqBytes != len(req) || ev.RespBytes <= 0 {
				t.Errorf("follow-up query mis-decoded: %+v", ev)
			}
		default:
			t.Errorf("unexpected event %q after the panicking predecessor: %+v", ev.Event, ev)
		}
	}
	if panics != 1 {
		t.Errorf("expected exactly one handler_panic from the contained predecessor, got %d", panics)
	}
	if queries != 1 {
		t.Errorf("expected exactly one query event from the non-loopback follow-up, got %d", queries)
	}
}
