package main

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadLineReadsANormalLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("USER anonymous\r\n"))
	line, ok := readLine(r)
	if !ok || line != "USER anonymous" {
		t.Fatalf("got %q, %v, want %q, true", line, ok, "USER anonymous")
	}
}

func TestReadLineReturnsFinalPartialLineOnEOF(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("QUIT"))
	line, ok := readLine(r)
	if ok || line != "QUIT" {
		t.Fatalf("got %q, %v, want %q, false", line, ok, "QUIT")
	}
	// A second call sees the real EOF with nothing left to return.
	line, ok = readLine(r)
	if ok || line != "" {
		t.Fatalf("got %q, %v, want empty, false", line, ok)
	}
}

// TestReadLineBoundsAnUnterminatedLine (#889): an attacker who withholds
// the newline must not be able to buffer unbounded data in one readLine
// call -- proven by writing far more than maxLineLength bytes with no
// newline and requiring readLine to bail rather than block accumulating
// forever.
func TestReadLineBoundsAnUnterminatedLine(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.SetWriteDeadline(time.Now().Add(5 * time.Second))
		// Far more than maxLineLength, no trailing newline.
		client.Write([]byte(strings.Repeat("A", maxLineLength*4)))
	}()

	done := make(chan struct{})
	var gotOK bool
	go func() {
		server.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, gotOK = readLine(bufio.NewReader(server))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("readLine did not return promptly for an unterminated, oversized line -- missing length bound")
	}
	if gotOK {
		t.Fatal("expected ok=false for a line that exceeded maxLineLength without a newline")
	}
}

// TestReadLineHandlesALineAtExactlyTheCap proves the cap doesn't reject an
// ordinary line that merely happens to span more than one internal bufio
// read chunk.
func TestReadLineHandlesALineAtExactlyTheCap(t *testing.T) {
	body := strings.Repeat("B", maxLineLength-1)
	r := bufio.NewReader(strings.NewReader(body + "\r\n"))
	line, ok := readLine(r)
	if !ok || line != body {
		t.Fatalf("got ok=%v len(line)=%d, want ok=true len=%d", ok, len(line), len(body))
	}
}
