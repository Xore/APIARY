package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #2186: nothing below handleConn's own wiring carries a recover() -- the
// vendored state machine and grailbio/go-dicom both parse attacker bytes
// bare -- so these are the forced-panic probes for the boundary itself,
// shaped like aetitle_test.go's #888 deadline harness: what is asserted is
// that the connection entrypoint RETURNS from hostile input and that the
// next connection is still served afterwards. Before the boundary existed,
// either failure mode ended the entire test binary mid-run instead of
// producing a red assert.

// panicReadConn stands in for a crafted connection whose bytes detonate the
// receiver mid-parse: every Read faults instead of delivering data, so the
// fault surfaces wherever our wiring or the vendored parser touches the
// stream.
type panicReadConn struct{ net.Conn }

func (c panicReadConn) Read([]byte) (int, error) { panic("crafted #2186 payload") }

func readEventsFromFile(t *testing.T, path string) []event {
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
		var ev event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

// One crafted connection must cost exactly one handler_panic event carrying
// the recovered value -- and must not end the process serving it.
func TestHandleConnContainsConnectionPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dicompot.json")
	log := newLogger(path)

	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConn(panicReadConn{server}, log, false, "RADIANT", 11112)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleConn did not return from a panicking connection -- the recover boundary is gone")
	}

	var panics int
	sawConnect := false
	for _, ev := range readEventsFromFile(t, path) {
		switch ev.Event {
		case "connect":
			sawConnect = true
		case "handler_panic":
			panics++
			if !strings.Contains(ev.Data, "crafted #2186 payload") {
				t.Errorf("handler_panic lost the recovered value: %+v", ev)
			}
			if ev.SrcIP == "" {
				t.Errorf("handler_panic missing attacker address: %+v", ev)
			}
		}
	}
	if !sawConnect {
		t.Fatal("connection never reached the normal logging path before the panic fired")
	}
	if panics != 1 {
		t.Fatalf("expected exactly one handler_panic event, got %d", panics)
	}
}

// The point of the boundary is continuity: after one connection died inside
// its goroutine, the very next one must still walk past the same depth --
// PROXY decode, healthcheck guard, A-ASSOCIATE peek attribution -- and get
// handed to the ServiceProvider.
func TestHandleConnServesNextConnectionAfterPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dicompot.json")
	log := newLogger(path)

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConn(panicReadConn{server}, log, false, "RADIANT", 11112)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("panicking connection was not contained")
	}
	client.Close()

	// Next connection: a real A-ASSOCIATE-RQ encoded by the vendored
	// package's own encoder (same shape as aetitle_test.go), so the associate
	// event proves the connection made it through the full pre-vendor path.
	server2, client2 := net.Pipe()
	defer client2.Close()
	go func() {
		client2.Write(realAssociateRQ(t, "ANY-SCP", "STORESCU"))
	}()
	go handleConn(server2, log, false, "RADIANT", 11112)

	deadline := time.Now().Add(10 * time.Second)
	for {
		var sawAssociate bool
		for _, ev := range readEventsFromFile(t, path) {
			if ev.Event == "associate" && ev.CalledAE == "ANY-SCP" && ev.CallingAE == "STORESCU" {
				sawAssociate = true
			}
		}
		if sawAssociate {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("next connection never reached the associate peek after a panicking predecessor: %+v", readEventsFromFile(t, path))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// This one pins the vector the issue is actually about -- the vendored
// parser itself. An A-ASSOCIATE-RQ carrying no presentation contexts (built
// here with the package's own encoder, so the wire format is authoritative)
// makes nsmfoo/dicompot's ServiceProvider panic "index out of range" while
// running the association on the connection goroutine. Before #2186's
// boundary that meant instant death of the whole sensor; now it must be
// contained like any other handler_panic. (Pinned pseudo-version via
// go.mod: a dependency bump re-reviews this alongside everything else.)
func TestHandleConnContainsVendorParserPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dicompot.json")
	log := newLogger(path)

	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConn(server, log, false, "RADIANT", 11112)
	}()
	client.Write(realAssociateRQ(t, "ANY-SCP", "STORESCU"))

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleConn did not return when the vendored state machine panicked")
	}

	var contained bool
	for _, ev := range readEventsFromFile(t, path) {
		if ev.Event == "handler_panic" && strings.Contains(ev.Data, "index out of range") {
			contained = true
		}
	}
	if !contained {
		t.Fatalf("no handler_panic captured the vendored parser's index-out-of-range panic: %+v", readEventsFromFile(t, path))
	}
}
