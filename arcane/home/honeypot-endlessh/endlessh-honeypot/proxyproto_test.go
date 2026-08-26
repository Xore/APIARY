package main

import (
	"bufio"
	"net"
	"testing"
	"time"
)

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
		client.Write([]byte("PROXY TCP4 198.51.100.7 10.8.0.2 54321 2222\r\nSSH-2.0-x\r\n"))
	}()

	pc := &proxyConn{Conn: server, r: bufio.NewReader(server)}
	addr := pc.RemoteAddr()
	if addr == nil || addr.String() != "198.51.100.7:54321" {
		t.Fatalf("RemoteAddr() = %v, want 198.51.100.7:54321", addr)
	}
}

// TestProxyConnReadDeliversBytesPastTheHeader is the control case: once
// decoded, Read must still deliver whatever followed the PROXY header to
// the caller.
func TestProxyConnReadDeliversBytesPastTheHeader(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go func() {
		client.Write([]byte("PROXY TCP4 198.51.100.7 10.8.0.2 54321 2222\r\nhello"))
	}()

	pc := &proxyConn{Conn: server, r: bufio.NewReader(server)}
	buf := make([]byte, 5)
	if _, err := pc.Read(buf); err != nil {
		t.Fatalf("Read past header: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("Read = %q, want \"hello\"", buf)
	}
}
