package main

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// panicUpstream stands in for an upstream session socket whose FORWARD leg
// detonates the relay mid-datagram: every WriteToUDP faults instead of
// delivering. Only the methods handleDatagram actually invokes are
// implemented -- anything else hits the promoted nil interface, which is
// exactly what we want a test to notice.
type panicUpstream struct{ upstreamConn }

func (panicUpstream) SetReadDeadline(time.Time) error               { return nil }
func (panicUpstream) WriteToUDP([]byte, *net.UDPAddr) (int, error)  { panic("crafted #2489 datagram") }
func (panicUpstream) ReadFromUDP([]byte) (int, *net.UDPAddr, error) { return 0, nil, net.ErrClosed }
func (panicUpstream) Close() error                                  { return nil }

// recordingUpstream is the healthy counterpart: it swallows writes into a
// buffer so the test can prove forwarding still happened after a contained
// panic elsewhere in the table.
type recordingUpstream struct {
	writes bytes.Buffer
	closed bool
}

func (*recordingUpstream) SetReadDeadline(time.Time) error { return nil }
func (r *recordingUpstream) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	return r.writes.Write(b)
}
func (*recordingUpstream) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	return 0, nil, net.ErrClosed
}
func (r *recordingUpstream) Close() error { r.closed = true; return nil }

// panicSink detonates the listener-facing reply leg relayReplies writes
// through -- in the real process that is the accept socket itself, so the
// crafted sink replaces relay.server, not the session's upstream conn.
type panicSink struct{}

func (panicSink) WriteToUDP([]byte, *net.UDPAddr) (int, error) { panic("crafted #2489 reply") }

// scriptedRelay drives relayReplies without a network: the first read hands
// back one valid reply datagram from the upstream peer, everything after is
// closed-socket -- the precise shape that exercises containment AND the
// cleanup-after-recover contract in a single synchronous pass.
type scriptedRelay struct {
	upstreamConn // nil: only overridden methods are called
	readPayload  []byte
	reads        int
	closed       bool
}

func (*scriptedRelay) SetReadDeadline(time.Time) error { return nil }
func (*scriptedRelay) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	return len(b), nil
}
func (s *scriptedRelay) ReadFromUDP(_ []byte) (int, *net.UDPAddr, error) {
	s.reads++
	if s.reads == 1 {
		return len(s.readPayload), &net.UDPAddr{IP: net.IPv4(10, 66, 0, 9), Port: 69}, nil
	}
	return 0, nil, net.ErrClosed
}
func (s *scriptedRelay) Close() error { s.closed = true; return nil }

func clientAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 44444}
}

func swapPanicOut(t *testing.T) *bytes.Buffer {
	t.Helper()
	old := panicOut
	buf := &bytes.Buffer{}
	panicOut = buf
	t.Cleanup(func() { panicOut = old })
	return buf
}

func readPanicEvents(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad panic line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// A panicking datagram must RETURN from handleDatagram after emitting exactly
// one handler_panic event carrying the recovered value and the client
// attribution -- not kill the process. Without the boundary the panic unwinds
// out of the extraction point straight through main's accept loop, ending the
// whole binary: exactly what restart: unless-stopped turns into sensor death
// on a replayable packet (#2210's dns-honeypot rationale, same family).
func TestHandleDatagramPanickingSessionEmitsOneHandlerPanicAndSurvives(t *testing.T) {
	buf := swapPanicOut(t)
	client := clientAddr()
	r := &relay{
		listenPort: 1069,
		server:     &recordingUpstream{},
		sessions: map[string]*session{
			client.String(): {conn: panicUpstream{}, target: &net.UDPAddr{IP: net.IPv4(10, 8, 0, 5), Port: 69}},
		},
	}

	r.handleDatagram([]byte("forged RRQ"), client)

	events := readPanicEvents(t, buf)
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 handler_panic event, got %d", len(events))
	}
	e := events[0]
	if e["event"] != "handler_panic" {
		t.Fatalf("event = %v, want handler_panic", e["event"])
	}
	if e["sensor"] != "tftp-relay" || e["proto"] != "tftp" || e["port"] != float64(1069) {
		t.Fatalf("unexpected envelope fields: %+v", e)
	}
	if e["src_ip"] != "203.0.113.7" || e["src_port"] != float64(44444) {
		t.Fatalf("unexpected attribution: %+v", e)
	}
	if !strings.Contains(e["data"].(string), "crafted #2489") {
		t.Fatalf("data = %v, want it to carry the recovered value", e["data"])
	}

	// Continuity: the very next datagram for a healthy session must still be
	// forwarded normally, with no further panic events recorded.
	rec := &recordingUpstream{}
	r.sessions[client.String()] = &session{conn: rec, target: &net.UDPAddr{IP: net.IPv4(10, 8, 0, 5), Port: 69}}
	r.handleDatagram([]byte("healthy RRQ"), client)
	if rec.writes.String() != "healthy RRQ" {
		t.Fatalf("healthy datagram not forwarded after contained panic: got %q", rec.writes.String())
	}
	if got := len(readPanicEvents(t, buf)); got != 1 {
		t.Fatalf("healthy datagram produced extra panic lines: %d total", got)
	}
}

// The relayReplies boundary wraps the LOOP BODY, not the whole goroutine:
// recovering around the whole function would contain the panic but skip past
// the error-path cleanup that deletes the session entry -- and after #882's
// hard cap, one leaked entry is one permanently burned slot. So after a
// contained mid-loop detonation on the reply-sink write, the NEXT read error
// must still delete the session and close the socket exactly as the
// unpanicked path always did.
func TestRelayRepliesPanicContainedThenCleanupStillRuns(t *testing.T) {
	buf := swapPanicOut(t)
	client := clientAddr()
	scripted := &scriptedRelay{readPayload: []byte("DATA block")}
	r := &relay{
		listenPort: 1069,
		server:     panicSink{},
		sessions: map[string]*session{
			client.String(): {conn: scripted, target: &net.UDPAddr{IP: net.IPv4(10, 8, 0, 5), Port: 1069}},
		},
	}

	// Synchronous call: returns only once the cleanup path fires, proving the
	// loop survived its own contained panic instead of unwinding away.
	r.relayReplies(client, client.String(), r.sessions[client.String()])

	r.lock.Lock()
	_, stillTracked := r.sessions[client.String()]
	r.lock.Unlock()
	if stillTracked {
		t.Fatal("panicked session was never cleaned up from the table")
	}
	if !scripted.closed {
		t.Fatal("panicked session's socket was never closed")
	}
	events := readPanicEvents(t, buf)
	if len(events) != 1 || !strings.Contains(events[0]["data"].(string), "crafted #2489 reply") {
		t.Fatalf("expected exactly one recovered 'crafted #2489 reply' event, got %+v", events)
	}
}

// emitPanic itself stays honest: one JSON line, all the attribution keys,
// shape-compatible with the sensors' stdout stream.
func TestEmitPanicWritesSingleJSONLineWithAttribution(t *testing.T) {
	buf := swapPanicOut(t)

	emitPanic(1069, clientAddr(), "crafted probe")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one line, got %d: %q", len(lines), buf.String())
	}
	var e map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("line not valid JSON: %v (%s)", err, lines[0])
	}
	for _, key := range []string{"time", "sensor", "proto", "port", "src_ip", "src_port", "event", "data"} {
		if _, ok := e[key]; !ok {
			t.Fatalf("missing key %q in %s", key, lines[0])
		}
	}
}
