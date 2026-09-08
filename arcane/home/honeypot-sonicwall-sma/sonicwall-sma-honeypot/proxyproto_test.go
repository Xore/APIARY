package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestProxyListenerAcceptDoesNotBlockOnSlowPeer covers #2099 (the port of
// #1346's cisco-asa fix into this stack): Accept() must return as soon as
// the underlying listener accepts a connection, even if the peer then sends
// nothing at all -- the PROXY header decode (and its 5-second deadline)
// must not run synchronously inside Accept(), or one slow/silent connection
// stalls admission of every other connection on the shared accept loop
// net/http.Server.Serve() drives.
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
// correctness half of the lazy decode: net/http captures RemoteAddr()
// before the TLS handshake (and therefore before any Read) even starts, so
// a fix that only decoded the PROXY header lazily on first Read would
// silently break attacker-IP attribution -- RemoteAddr() must itself
// trigger (and wait for) the decode.
func TestProxyConnRemoteAddrResolvesRealAddressBeforeAnyRead(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go func() {
		client.Write([]byte("PROXY TCP4 198.51.100.7 10.8.0.2 54321 443\r\nGET / HTTP/1.1\r\n\r\n"))
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
		client.Write([]byte("PROXY TCP4 198.51.100.7 10.8.0.2 54321 443\r\nhello"))
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

// --- #2187: parser size caps (v1 line cap propagates #1348's dnp3 fix to
// this mirror copy; v2 address-block cap is new here). ---

// TestParseProxyV1ParsesWellFormedHeader is the control case, proving the
// size cap doesn't break real PROXY v1 headers.
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

// TestParseProxyV1CapsBufferedBytesOnUnterminatedLine covers the #2187 v1
// cap: without it, ReadString('\n') buffers every byte read chasing a
// newline that never arrives -- an attacker sending "PROXY" followed by
// megabytes of non-newline data forces unbounded memory growth per
// connection for the full decode deadline.
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

// TestParseProxyV2ParsesWellFormedHeader is the control case for the #2187
// v2 cap: a legitimate AF_INET v2 header must still parse.
func TestParseProxyV2ParsesWellFormedHeader(t *testing.T) {
	hdr := append([]byte{}, proxyV2Sig...)
	hdr = append(hdr, 0x21, 0x11, 0x00, 0x0c) // PROXY command, AF_INET, 12-byte address block
	hdr = append(hdr, 198, 51, 100, 7, 10, 8, 0, 2, 0xd4, 0x31, 0x4e, 0x20)
	addr := parseProxyV2(bufio.NewReader(bytes.NewReader(hdr)))
	if addr == nil {
		t.Fatal("expected a parsed address for a well-formed v2 header")
	}
	if addr.String() != "198.51.100.7:54321" {
		t.Fatalf("addr = %q, want 198.51.100.7:54321", addr.String())
	}
}

// TestParseProxyV2AcceptsSpecMaxAddressBlock pins the cap to the spec's own
// maximum: a header declaring exactly maxProxyV2Addr bytes is inside the
// spec and must parse rather than trip the oversize reject.
func TestParseProxyV2AcceptsSpecMaxAddressBlock(t *testing.T) {
	hdr := append([]byte{}, proxyV2Sig...)
	hdr = append(hdr, 0x21, 0x11, byte(maxProxyV2Addr>>8), byte(maxProxyV2Addr&0xff))
	addrBlock := make([]byte, maxProxyV2Addr)
	copy(addrBlock, []byte{198, 51, 100, 7, 10, 8, 0, 2, 0xd4, 0x31, 0x4e, 0x20})
	hdr = append(hdr, addrBlock...)
	addr := parseProxyV2(bufio.NewReader(bytes.NewReader(hdr)))
	if addr == nil {
		t.Fatal("expected a parsed address for a spec-maximum v2 header")
	}
	if addr.String() != "198.51.100.7:54321" {
		t.Fatalf("addr = %q, want 198.51.100.7:54321", addr.String())
	}
}

// TestParseProxyV2RejectsOversizeDeclaredAddress covers the #2187 v2 cap:
// the address block length is peer-declared as a raw 16-bit field, and
// allocating it before validating anything let a 16-byte signature plus a
// declared 64KB park ~64KB per connection behind the decode deadline --
// the v1 memory DoS at 64x the bytes and no newline required.
func TestParseProxyV2RejectsOversizeDeclaredAddress(t *testing.T) {
	hdr := append([]byte{}, proxyV2Sig...)
	hdr = append(hdr, 0x21, 0x11, 0xff, 0xff) // declares a 65535-byte address block
	addr := parseProxyV2(bufio.NewReader(bytes.NewReader(hdr)))
	if addr != nil {
		t.Fatalf("expected nil for a v2 header declaring %d address bytes, got %v", 0xffff, addr)
	}
}

// TestParseProxyV1LeavesBufferedPayloadIntact pins the property the #1348
// LimitReader construction broke: whatever follows the header's newline
// must stay in the shared reader's buffer for the handler, never be
// swallowed by the header read itself -- a client whose request coalesced
// with the PROXY header (the common case, one TCP segment) would otherwise
// lose the start of its first exchange.
func TestParseProxyV1LeavesBufferedPayloadIntact(t *testing.T) {
	payload := "REQ-1 REQ-2"
	src := bytes.NewReader([]byte("PROXY TCP4 198.51.100.7 10.8.0.2 54321 20000\r\n" + payload))
	r := bufio.NewReader(src)
	if addr := parseProxyV1(r); addr == nil {
		t.Fatal("expected a parsed address for a well-formed header")
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read past header: %v", err)
	}
	if string(rest) != payload {
		t.Fatalf("payload past the header = %q, want %q", rest, payload)
	}
}
