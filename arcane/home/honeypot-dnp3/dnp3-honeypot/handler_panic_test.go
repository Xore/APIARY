package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// #2186: serve() decodes attacker frames straight off the socket with no
// recover anywhere downstream, so these are the forced-panic probes for the
// boundary at the top of it, shaped like the #888 deadline harness in
// dicompot's aetitle_test.go: assert that serve() RETURNS from hostile
// input and that a subsequent connection is still served end to end. The
// fault is injected by wrapping the conn rather than crafted bytes because
// this honeypot's own frame path is bounds-checked; the boundary exists for
// what future edits (and vendored parsing past it) could add.

// panicReadConn stands in for a connection whose bytes detonate the receiver
// mid-parse: every Read faults instead of delivering data.
type panicReadConn struct{ net.Conn }

func (c panicReadConn) Read([]byte) (int, error) { panic("crafted #2186 frame") }

// dnp3LogLine mirrors the wire shape MarshalJSON emits -- the event struct
// itself has no json tags, so a straight Unmarshal would silently drop every
// snake_case key (src_ip, frame_hex, ...).
type dnp3LogLine struct {
	SrcIP           string `json:"src_ip"`
	SrcPort         int    `json:"src_port"`
	Port            int    `json:"port"`
	Event           string `json:"event"`
	FrameHex        string `json:"frame_hex"`
	Function        string `json:"function"`
	AppFunction     string `json:"app_function"`
	Data            string `json:"data"`
	DNP3Source      int    `json:"dnp3_source"`
	DNP3Destination int    `json:"dnp3_destination"`
}

func readDNP3Events(t *testing.T, buf *bytes.Buffer) []dnp3LogLine {
	t.Helper()
	var out []dnp3LogLine
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var ev dnp3LogLine
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

// A panicking connection must return from serve() after emitting exactly one
// handler_panic event carrying the recovered value -- not kill the process.
func TestServeContainsConnectionPanic(t *testing.T) {
	var buf bytes.Buffer
	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(panicReadConn{server}, &logger{out: &buf})
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return from a panicking connection -- the recover boundary is gone")
	}

	events := readDNP3Events(t, &buf)
	if len(events) != 1 {
		t.Fatalf("expected exactly one event from the panicking connection, got %+v", events)
	}
	if events[0].Event != "handler_panic" {
		t.Fatalf("event = %q, want handler_panic", events[0].Event)
	}
	if !strings.Contains(events[0].Data, "crafted #2186 frame") {
		t.Fatalf("handler_panic lost the recovered value: %+v", events[0])
	}
	// src_ip stays empty here only because a net.Pipe peer has no host part;
	// every real accept()ed socket does.
	if events[0].Port != 20000 {
		t.Fatalf("handler_panic missing listener attribution: %+v", events[0])
	}
}

// Continuity is the point: after one connection died inside its goroutine,
// the next one must still be decoded and answered end to end -- here that
// means a real DNP3 link+application READ frame gets its statusResponse and
// its frame event.
func TestServeStillServesFramesAfterPanickedConnection(t *testing.T) {
	var buf bytes.Buffer
	server, _ := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(panicReadConn{server}, &logger{out: &buf})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("panicking connection was not contained")
	}

	frame := []byte{
		0x05, 0x64, 0x0c, 0xc0, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, // link header (dst=4 src=1; CRC unchecked here)
		0xc1, // transport header (FIR/FIN/SEQ)
		0xc0, // application control
		0x01, // function code: READ
	}

	// Same host-frame decode shape as TestAppFunctionCodeDecodesKnownRequestCode.
	buf.Reset()
	server2, client2 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		serve(server2, &logger{out: &buf})
	}()
	client2.Write(frame)

	reply := make([]byte, 10)
	if err := readFullDeadline(client2, reply); err != nil {
		t.Fatalf("no statusResponse for the follow-up connection: %v", err)
	}
	if want := statusResponse(1, 4); !bytes.Equal(reply, want) {
		t.Fatalf("follow-up reply = %x, want %x", reply, want)
	}
	client2.Close()
	<-done2

	events := readDNP3Events(t, &buf)
	if len(events) != 1 {
		t.Fatalf("expected exactly one frame event from the follow-up connection, got %+v", events)
	}
	if events[0].Event != "frame" || events[0].Function != "reset_link_states" ||
		events[0].AppFunction != "read" || events[0].DNP3Source != 1 || events[0].DNP3Destination != 4 {
		t.Fatalf("follow-up frame mis-decoded: %+v", events[0])
	}
}

// readFullDeadline bounds the client-side wait like the #888 harness does:
// if the wire went quiet for the wrong reason the test fails instead of
// hanging.
func readFullDeadline(c net.Conn, p []byte) error {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadFull(c, p)
	if n != len(p) {
		return err
	}
	return nil
}
