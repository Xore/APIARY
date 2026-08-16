package main

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
)

// #608: every event within one connection must share one session id, and
// separate connections must get distinct ids -- otherwise multi-step
// interactions (FTP's USER -> PASS -> command loop) can't be grouped in the
// dashboard/ES the way cowrie's "session" field already lets them.

func TestSessionIDCorrelatesEventsWithinOneConnection(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	sl := &sessionLogger{logger: &logger{out: &output}, id: newSessionID()}
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handleFTP(server, sl, 21) }()

	r := bufio.NewReader(client)
	r.ReadString('\n') // 220 banner
	client.Write([]byte("USER attacker\r\n"))
	r.ReadString('\n') // 331
	client.Write([]byte("PASS hunter2\r\n"))
	r.ReadString('\n') // 530
	client.Write([]byte("QUIT\r\n"))
	r.ReadString('\n') // 221
	client.Close()
	<-done

	events := decodeEvents(t, output.String())
	if len(events) != 1 {
		t.Fatalf("expected 1 login event, got %d: %+v", len(events), events)
	}
	if events[0].Session == "" {
		t.Fatal("expected non-empty session id on emitted event")
	}
	if events[0].Session != sl.id {
		t.Fatalf("event session = %q, want %q", events[0].Session, sl.id)
	}
}

func TestSessionIDsDifferAcrossConnections(t *testing.T) {
	id1, id2 := newSessionID(), newSessionID()
	if id1 == id2 {
		t.Fatalf("expected distinct session ids, got %q twice", id1)
	}
	if len(id1) == 0 || strings.ContainsAny(id1, " \n\t") {
		t.Fatalf("session id looks malformed: %q", id1)
	}
}
