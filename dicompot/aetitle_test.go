package main

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/nsmfoo/dicompot/pdu"
)

// realAssociateRQ encodes a real A-ASSOCIATE-RQ PDU via the vendored
// package's own encoder, so this test exercises the actual wire format
// rather than a hand-rolled guess at it.
func realAssociateRQ(t *testing.T, called, calling string) []byte {
	t.Helper()
	b, err := pdu.EncodePDU(&pdu.AAssociate{
		Type:            pdu.TypeAAssociateRq,
		ProtocolVersion: pdu.CurrentProtocolVersion,
		CalledAETitle:   called,
		CallingAETitle:  calling,
	})
	if err != nil {
		t.Fatalf("EncodePDU: %v", err)
	}
	return b
}

func TestPeekAETitlesExtractsFromRealPDU(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	payload := realAssociateRQ(t, "ANY-SCP", "STORESCU")
	// Tack on a marker after the fixed-size header so we can confirm the
	// wrapped conn replays every byte, not just the ones peeked.
	payload = append(payload, []byte("tail-marker")...)

	go func() {
		client.Write(payload)
	}()

	wrapped, calledAE, callingAE := peekAETitles(server)
	if calledAE != "ANY-SCP" {
		t.Errorf("calledAE = %q, want ANY-SCP", calledAE)
	}
	if callingAE != "STORESCU" {
		t.Errorf("callingAE = %q, want STORESCU", callingAE)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("ReadFull on wrapped conn: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("wrapped conn replayed %q, want %q", got, payload)
	}
}

func TestPeekAETitlesTrimsPadding(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	payload := realAssociateRQ(t, "AE1", "AE2") // short titles, space-padded to 16 bytes
	go func() { client.Write(payload) }()

	_, calledAE, callingAE := peekAETitles(server)
	if calledAE != "AE1" || callingAE != "AE2" {
		t.Errorf("got called=%q calling=%q, want AE1/AE2 (untrimmed padding?)", calledAE, callingAE)
	}
}

func TestPeekAETitlesIgnoresNonAssociatePDU(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	payload, err := pdu.EncodePDU(&pdu.AReleaseRq{})
	if err != nil {
		t.Fatalf("EncodePDU: %v", err)
	}
	go func() {
		client.Write(payload)
		client.Close() // signal EOF: this PDU alone is far short of the 42 bytes peekAETitles wants
	}()

	_, calledAE, callingAE := peekAETitles(server)
	if calledAE != "" || callingAE != "" {
		t.Errorf("got called=%q calling=%q for a non-associate PDU, want both empty", calledAE, callingAE)
	}
}

// TestPeekAETitlesHasAReadDeadline (#888): a connection that never sends
// anything (and never closes) must not block peekAETitles -- and the
// goroutine/fd behind it -- forever. Proven by requiring it to return well
// within twice the function's own 5s deadline; before the fix this test
// would hang until forcibly killed.
func TestPeekAETitlesHasAReadDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		peekAETitles(server)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("peekAETitles did not return within 8s of a connection that never sent data -- missing read deadline")
	}
}

func TestPeekAETitlesHandlesShortRead(t *testing.T) {
	server, client := net.Pipe()

	go func() {
		client.Write([]byte{1, 0, 0, 0, 0, 4}) // valid header, then close before the body
		client.Close()
	}()

	_, calledAE, callingAE := peekAETitles(server)
	if calledAE != "" || callingAE != "" {
		t.Errorf("got called=%q calling=%q on a truncated PDU, want both empty", calledAE, callingAE)
	}
}
