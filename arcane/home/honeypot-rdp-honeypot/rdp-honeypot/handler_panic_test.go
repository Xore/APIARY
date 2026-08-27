package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scriptedConn is a fully concrete net.Conn the tests drive without a
// network: it serves one scripted read payload, detonates on the chosen leg
// (read = the decodeProxy path, write = the negFailure response inside
// serve), and reports a fixed remote address so handler_panic attribution is
// assertable. Nothing is left to promoted nil methods -- serve's deferred
// Close and the deadline calls all run for real.
type scriptedConn struct {
	remote      net.Addr
	readPayload []byte
	readDone    bool
	panicOn     string // "read" or "write"
	writes      bytes.Buffer
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	if c.panicOn == "read" {
		panic("crafted #2489 decode")
	}
	if c.readDone {
		return 0, io.EOF
	}
	c.readDone = true
	n := copy(b, c.readPayload)
	return n, nil
}

func (c *scriptedConn) Write(b []byte) (int, error) {
	if c.panicOn == "write" {
		panic("crafted #2489 response")
	}
	return c.writes.Write(b)
}

func (*scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr            { return c.remote }
func (c *scriptedConn) RemoteAddr() net.Addr           { return c.remote }
func (*scriptedConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func testRemote() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51344}
}

// newFileLogger hands back a logger writing to a temp file -- newLogger("")
// would only echo to stdout, which a test can't read back.
func newFileLogger(t *testing.T) (*logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rdp.json")
	l := newLogger(path)
	if l.out == nil {
		t.Fatal("expected a usable log file")
	}
	return l, path
}

func readFileEvents(t *testing.T, path string) []event {
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
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// A connection whose PROXY-decode leg detonates must return from handleConn
// after emitting exactly one attributable handler_panic event -- not unwind
// out of the spawned goroutine and kill the whole sensor (restart:
// unless-stopped would hand the attacker the same replayable bytes right
// back; that failure mode is the entire point of the boundary).
func TestHandleConnDecodeLegPanicContainedAndAttributed(t *testing.T) {
	log, path := newFileLogger(t)
	c := &scriptedConn{remote: testRemote(), panicOn: "read"}

	handleConn(c, true /* proxy forces the decodeProxy leg */, log, 3389)

	events := readFileEvents(t, path)
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 event, got %d: %+v", len(events), events)
	}
	e := events[0]
	if e.Event != "handler_panic" {
		t.Fatalf("event = %q, want handler_panic", e.Event)
	}
	if e.Port != 3389 || e.SrcIP != "203.0.113.7" || e.SrcPort != 51344 {
		t.Fatalf("unexpected attribution: %+v", e)
	}
	if !strings.Contains(e.Data, "crafted #2489 decode") {
		t.Fatalf("data = %q, want it to carry the recovered value", e.Data)
	}
}

// A connection that decodes cleanly but detonates while serve writes the
// negFailure response must come out as connect-then-handler_panic in order,
// proving the boundary covers the serve body too rather than only the
// PROXY stage in front of it.
func TestHandleConnServeLegPanicContainedAfterCleanDecode(t *testing.T) {
	log, path := newFileLogger(t)
	payload := append([]byte("Cookie: mstshash=jdoe\r\n"), 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00)
	c := &scriptedConn{remote: testRemote(), readPayload: payload, panicOn: "write"}

	handleConn(c, false, log, 3389)

	events := readFileEvents(t, path)
	if len(events) != 2 {
		t.Fatalf("expected exactly 2 events [connect, handler_panic], got %d", len(events))
	}
	if events[0].Event != "connect" || events[0].Username != "jdoe" {
		t.Fatalf("first event = %+v, want the connect line with the extracted username", events[0])
	}
	if events[1].Event != "handler_panic" || !strings.Contains(events[1].Data, "crafted #2489 response") {
		t.Fatalf("second event = %+v, want handler_panic carrying the recovered value", events[1])
	}
}

// Continuity across connections: after two contained panics on hostile
// conns, the next healthy connection is still served normally --
// connect logged, response swallowed into its buffer, no stray panics.
func TestHandleConnHealthyConnectionServedAfterContainedPanics(t *testing.T) {
	log, path := newFileLogger(t)

	handleConn(&scriptedConn{remote: testRemote(), panicOn: "read"}, true, log, 3389)
	payload := []byte("\x03\x00\x00\x2b\x25\xe0\x00\x00\x00\x00\x00Cookie: mstshash=scan\r\n")
	handleConn(&scriptedConn{remote: testRemote(), readPayload: payload}, false, log, 3389)

	events := readFileEvents(t, path)
	var kinds []string
	for _, e := range events {
		kinds = append(kinds, e.Event)
	}
	want := []string{"handler_panic", "connect"}
	if len(kinds) != len(want) {
		t.Fatalf("event sequence = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("event sequence = %v, want %v", kinds, want)
		}
	}
	if events[1].Username != "scan" {
		t.Fatalf("healthy connection username = %q, want scan", events[1].Username)
	}
}
