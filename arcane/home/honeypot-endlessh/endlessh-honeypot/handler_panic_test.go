package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// #2210: serve() constructs banner content per connection and trickles it
// straight off main()'s accept loop -- nothing downstream of our wiring
// carries a recover() -- so these are the forced-panic probes for the
// boundary at the top of it, shaped like the #2186 harnesses
// (dicompot/dnp3/multipot): what is asserted is that the per-connection
// entrypoint RETURNS from hostile input and that the next connection is
// still held and drip-fed afterwards. The fault is injected by wrapping the
// conn rather than crafted bytes because this tarpit never parses anything
// inbound; its fault surface is the banner construction and the stream the
// trickle writes to, so every Write faults instead of delivering a line.

// panicWriteConn stands in for a connection whose trickle stream detonates
// the tarpit mid-banner: every Write faults instead of delivering a line.
type panicWriteConn struct{ net.Conn }

func (c panicWriteConn) Write(p []byte) (int, error) { panic("crafted #2210 banner") }

// A panicking connection must return from serve() after emitting exactly one
// handler_panic event carrying the recovered value -- not kill the process.
// net.Pipe stands in for the socket like TestServeHoldsConnectionAndDripFeedsLines.
func TestServeContainsConnectionPanic(t *testing.T) {
	buf := &syncBuffer{}
	log := &logger{out: buf}

	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(panicWriteConn{server}, log, 2222, 5*time.Millisecond)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return from a panicking connection -- the recover boundary is gone")
	}

	events := buf.lines(t)
	if len(events) != 2 {
		t.Fatalf("expected connect plus exactly one handler_panic from the panicking connection, got %+v", events)
	}
	if events[0].Event != "connect" {
		t.Fatalf("first event = %q, want \"connect\": %+v", events[0].Event, events)
	}
	last := events[1]
	if last.Event != "handler_panic" {
		t.Fatalf("second event = %q, want handler_panic: %+v", last.Event, events)
	}
	if !strings.Contains(last.Data, "crafted #2210 banner") {
		t.Fatalf("handler_panic lost the recovered value: %+v", last)
	}
	// No disconnect line: the held-forever story would otherwise claim a
	// hold that ended cleanly with a Lines/HeldMS tally it never earned.
	for _, ev := range events {
		if ev.Event == "disconnect" {
			t.Fatalf("panicked connection must not be misreported as a clean disconnect: %+v", events)
		}
	}
	// src_ip stays empty here only because a net.Pipe peer has no host part;
	// every real accept()ed socket does.
	if last.Port != 2222 {
		t.Fatalf("handler_panic missing listener attribution: %+v", last)
	}
}

// Continuity is the point: after one connection died inside its goroutine,
// the next one must still be held and drip-fed end to end -- real banners,
// CRLF-framed, none starting the SSH prefix -- and get its connect/disconnect
// pair logged when the scanner finally lets go. Same host-frame shape as
// TestServeHoldsConnectionAndDripFeedsLines, on a fresh buffer.
func TestServeStillServesBannersAfterPanickedConnection(t *testing.T) {
	buf := &syncBuffer{}
	log := &logger{out: buf}
	server, _ := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(panicWriteConn{server}, log, 2222, 5*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("panicking connection was not contained")
	}

	buf2 := &syncBuffer{}
	log2 := &logger{out: buf2}
	server2, client2 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		serve(server2, log2, 2222, 5*time.Millisecond)
		close(done2)
	}()

	client2.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf3 := make([]byte, 512)
	total := 0
	for total < 20 { // wait for a few drip-fed lines before giving up
		n, err := client2.Read(buf3[total:])
		if err != nil {
			t.Fatalf("reading from the tarpit failed after a panicking predecessor -- the follow-up connection is not being served: %v", err)
		}
		total += n
	}
	got := string(buf3[:total])
	if strings.Contains(got, "SSH-") {
		t.Fatalf("tarpit connection must never send the real SSH identification string: %q", got)
	}
	if !strings.Contains(got, "\r\n") {
		t.Fatalf("banner lines must be CRLF-terminated: %q", got)
	}

	client2.Close()
	select {
	case <-done2:
	case <-time.After(10 * time.Second):
		t.Fatal("the follow-up connection was not released when its client let go")
	}

	events := buf2.lines(t)
	if len(events) != 2 {
		t.Fatalf("follow-up connection logged %d events, want exactly 2 (connect, disconnect): %+v", len(events), events)
	}
	if events[0].Event != "connect" {
		t.Fatalf("first event = %q, want \"connect\"", events[0].Event)
	}
	last := events[len(events)-1]
	if last.Event != "disconnect" || last.Lines == 0 || last.HeldMS == 0 {
		t.Fatalf("follow-up disconnect mis-decoded: %+v", last)
	}
	for _, ev := range events {
		if ev.Event == "handler_panic" {
			t.Fatalf("the follow-up connection leaked a handler_panic of its own: %+v", events)
		}
	}
}
