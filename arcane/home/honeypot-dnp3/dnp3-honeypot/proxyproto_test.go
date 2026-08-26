package main

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"
)

// TestParseProxyV1ParsesWellFormedHeader is the control case, proving the
// size cap added for #1348 doesn't break real PROXY v1 headers.
func TestParseProxyV1ParsesWellFormedHeader(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte("PROXY TCP4 198.51.100.7 10.8.0.2 54321 20000\r\n")))
	addr := parseProxyV1(r)
	if addr == nil {
		t.Fatal("expected a parsed address for a well-formed header")
	}
	if addr.String() != "198.51.100.7:54321" {
		t.Fatalf("addr = %q, want 198.51.100.7:54321", addr.String())
	}
}

// TestParseProxyV1CapsBufferedBytesOnUnterminatedLine covers #1348: without
// a size cap, ReadString('\n') buffers every byte read chasing a newline
// that never arrives -- an attacker sending "PROXY" followed by megabytes
// of non-newline data can force unbounded memory growth per connection.
func TestParseProxyV1CapsBufferedBytesOnUnterminatedLine(t *testing.T) {
	huge := bytes.Repeat([]byte{'A'}, 10<<20) // 10MB, no newline anywhere
	src := bytes.NewReader(huge)
	r := bufio.NewReader(src)

	addr := parseProxyV1(r)
	if addr != nil {
		t.Fatalf("expected nil for a header line with no terminating newline, got %v", addr)
	}

	consumed := len(huge) - src.Len()
	if consumed > 8192 {
		t.Fatalf("parseProxyV1 pulled %d bytes out of the underlying connection chasing an unterminated line, want it bounded near maxProxyV1Line (%d)", consumed, maxProxyV1Line)
	}
}

// TestParseProxyV1RejectsLineLongerThanCap covers the boundary case: a line
// that does contain a newline, but only after exceeding the cap, must still
// be rejected rather than silently truncated and misparsed.
func TestParseProxyV1RejectsLineLongerThanCap(t *testing.T) {
	overlong := append(bytes.Repeat([]byte{'A'}, maxProxyV1Line+10), '\n')
	r := bufio.NewReader(bytes.NewReader(overlong))
	if addr := parseProxyV1(r); addr != nil {
		t.Fatalf("expected nil for a line exceeding maxProxyV1Line, got %v", addr)
	}
}

// TestProxyListenerAcceptDoesNotBlockOnSlowPeer covers #2099 (the port of
// #1346's cisco-asa fix into this stack): Accept() must return as soon as
// the underlying listener accepts a connection, even if the peer then sends
// nothing at all -- the PROXY header decode (and its 5-second deadline)
// must not run synchronously inside Accept(), or one slow/silent connection
// stalls admission of every other connection in main's own accept loop.
func TestProxyListenerAcceptDoesNotBlockOnSlowPeer(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer raw.Close()
	ln := &proxyListener{raw}

	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	// Deliberately send nothing -- a real PROXY-header decode would
	// otherwise block here for up to its own 5s deadline.

	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Accept() returned an error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Accept() blocked on a silent peer instead of returning immediately")
	}
}

// TestProxyConnRemoteAddrResolvesRealAddressBeforeAnyRead covers the
// correctness half of the lazy decode: a fix that only decoded the PROXY
// header lazily on first Read would silently break attacker-IP attribution
// for any path that reads the address first -- RemoteAddr() must itself
// trigger (and wait for) the decode.
func TestProxyConnRemoteAddrResolvesRealAddressBeforeAnyRead(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go func() {
		client.Write([]byte("PROXY TCP4 198.51.100.7 10.8.0.2 54321 20000\r\nhello"))
	}()

	pc := &proxyConn{Conn: server, r: bufio.NewReader(server)}
	addr := pc.RemoteAddr()
	if addr == nil || addr.String() != "198.51.100.7:54321" {
		t.Fatalf("RemoteAddr() = %v, want 198.51.100.7:54321", addr)
	}
}
