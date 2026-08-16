package main

import (
	"bufio"
	"bytes"
	"testing"
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
