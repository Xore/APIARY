package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #2186: protocol handlers parse attacker bytes directly on their connection
// goroutine with no recover underneath, so this exercises the real serve()
// accept loop -- not a handler called against a pipe, like most tests here --
// with one handler deliberately detonating mid-connection. The assertions are
// continuity ones: serve() keeps accepting, the very next connection is
// served to completion, and the panicking leg collapsed into exactly one
// handler_panic event. Before the boundary existed, a forced panic in any
// handler ended the entire test binary instead of producing a red assert.

// multipot serves real listeners, so its test connections are real dials --
// which the #1677 healthcheck guard would silently drop as 127.0.0.1
// traffic. Fronting each dial with a PROXY v1 header (the same ":pp" shape
// portbridge prepends) restores an external source address, exactly like
// production.
func dialProxied(t *testing.T, port int, src string) net.Conn {
	t.Helper()
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "PROXY TCP4 %s 10.8.0.2 51234 %d\r\n", src, port); err != nil {
		t.Fatalf("write proxy header: %v", err)
	}
	return conn
}

func waitFor(t *testing.T, what string, buf *bytes.Buffer, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !pred() {
		if time.Now().After(deadline) {
			t.Fatalf("%s never happened; events so far: %+v", what, decodeEvents(t, buf.String()))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServeContainsHandlerPanicAndKeepsServing(t *testing.T) {
	const testPort = 19659
	var mu sync.Mutex
	var buf bytes.Buffer // guarded: two legs' events land in one stream
	log := &logger{out: writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	})}

	var calls atomic.Int32
	entered1 := make(chan struct{})
	served2 := make(chan struct{})
	handler := func(_ net.Conn, _ *sessionLogger, _ int) {
		if calls.Add(1) == 1 {
			close(entered1)
			panic("#2186 crafted explosion inside the vendored-shaped handler")
		}
		close(served2)
	}

	// proxy=true is what makes the dialProxied harness work: without it the
	// connections would keep their real (loopback) address and #1677's
	// healthcheck guard would drop them before any handler ran.
	go serve(service{proto: "test-proto", port: testPort, handler: handler}, log, true, make(chan struct{}, 4096))

	c1 := dialProxied(t, testPort, "203.0.113.9")
	select {
	case <-entered1:
	case <-time.After(5 * time.Second):
		t.Fatal("first connection never reached its handler")
	}
	c1.Close()

	waitFor(t, "the handler_panic event", &buf, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, ev := range decodeEvents(t, buf.String()) {
			if ev.Event == "handler_panic" {
				return true
			}
		}
		return false
	})

	// Continuity: the same listener accepts and fully serves the next
	// connection end to end.
	c2 := dialProxied(t, testPort, "203.0.113.77")
	select {
	case <-served2:
	case <-time.After(5 * time.Second):
		t.Fatal("second connection was never served after the panicking predecessor")
	}
	c2.Close()

	mu.Lock()
	defer mu.Unlock()
	events := decodeEvents(t, buf.String())
	var panics, connects []event
	for _, ev := range events {
		switch ev.Event {
		case "connect":
			connects = append(connects, ev)
		case "handler_panic":
			panics = append(panics, ev)
		case "listening":
			// serve()'s one-time startup event is expected and unrelated.
		default:
			t.Fatalf("unexpected event from the test handlers: %+v", ev)
		}
	}
	if len(panics) != 1 || len(connects) != 2 {
		t.Fatalf("expected 2 connects + 1 handler_panic, got connects=%+v panics=%+v", connects, panics)
	}
	p := panics[0]
	if p.Proto != "test-proto" || p.Port != testPort || p.SrcIP != "203.0.113.9" {
		t.Fatalf("handler_panic missing attacker/service attribution: %+v", p)
	}
	if !strings.Contains(p.Data, "#2186 crafted explosion") {
		t.Fatalf("handler_panic lost the recovered value: %+v", p)
	}
}

// writerFunc adapts a func([]byte)(int,error) to io.Writer without dragging
// in iotest.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
