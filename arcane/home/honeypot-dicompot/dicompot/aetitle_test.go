package main

import (
	"bytes"
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

	wrapped, calledAE, callingAE, malformed := peekAETitles(server)
	if malformed {
		t.Error("malformed = true for a real A-ASSOCIATE-RQ")
	}
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

	_, calledAE, callingAE, malformed := peekAETitles(server)
	if calledAE != "AE1" || callingAE != "AE2" {
		t.Errorf("got called=%q calling=%q, want AE1/AE2 (untrimmed padding?)", calledAE, callingAE)
	}
	if malformed {
		t.Error("malformed = true for a real A-ASSOCIATE-RQ")
	}
}

// TestPeekAETitlesIgnoresShortNonAssociatePDU exercises the "peek came up
// short" path (err != nil from r.Peek(42)): an AReleaseRq alone is far short
// of 42 bytes, so this never reaches the PDU-type check at all. malformed
// must stay false here -- a short/closed connection isn't a protocol
// violation, just silence (#3155).
func TestPeekAETitlesIgnoresShortNonAssociatePDU(t *testing.T) {
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

	_, calledAE, callingAE, malformed := peekAETitles(server)
	if calledAE != "" || callingAE != "" {
		t.Errorf("got called=%q calling=%q for a short non-associate PDU, want both empty", calledAE, callingAE)
	}
	if malformed {
		t.Error("malformed = true for a short read, want false (not a protocol violation, just silence)")
	}
}

// TestPeekAETitlesFlagsMalformedFirstPDU (#3155): 42+ bytes arrive, but the
// first PDU type isn't A-ASSOCIATE-RQ. This is the "malformed/garbage
// association" case that used to fall through to a silent TCP close --
// peekAETitles must flag it so the caller sends an A-ABORT instead.
func TestPeekAETitlesFlagsMalformedFirstPDU(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		// A-RELEASE-RQ (type 5) header, padded well past 42 bytes so the
		// peek succeeds without a short read.
		payload := append([]byte{5, 0, 0, 0, 0, 4, 0, 0, 0, 0}, make([]byte, 40)...)
		client.Write(payload)
	}()

	_, calledAE, callingAE, malformed := peekAETitles(server)
	if !malformed {
		t.Error("malformed = false for a non-A-ASSOCIATE-RQ first PDU, want true")
	}
	if calledAE != "" || callingAE != "" {
		t.Errorf("got called=%q calling=%q for a malformed first PDU, want both empty", calledAE, callingAE)
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

	_, calledAE, callingAE, malformed := peekAETitles(server)
	if calledAE != "" || callingAE != "" {
		t.Errorf("got called=%q calling=%q on a truncated PDU, want both empty", calledAE, callingAE)
	}
	if malformed {
		t.Error("malformed = true for a truncated read, want false (not a protocol violation, just silence)")
	}
}

// realAssociateAC encodes a real A-ASSOCIATE-AC via the vendored package's
// own encoder, with a User Information item carrying the Max PDU Length
// upstream always sends today (#3155) and, unless extraItems says
// otherwise, nothing else -- matching statemachine.go's actual output,
// which never includes Implementation Class UID or Version Name.
func realAssociateAC(t *testing.T, maxPDU uint32, extraItems ...pdu.SubItem) []byte {
	t.Helper()
	items := append([]pdu.SubItem{&pdu.UserInformationMaximumLengthItem{MaximumLengthReceived: maxPDU}}, extraItems...)
	b, err := pdu.EncodePDU(&pdu.AAssociate{
		Type:            pdu.TypeAAssociateAc,
		ProtocolVersion: pdu.CurrentProtocolVersion,
		CalledAETitle:   "RADIANT",
		CallingAETitle:  "STORESCU",
		Items:           []pdu.SubItem{&pdu.UserInformationItem{Items: items}},
	})
	if err != nil {
		t.Fatalf("EncodePDU: %v", err)
	}
	return b
}

// decodeAC re-decodes patched/unpatched AC bytes and returns the Max PDU
// Length plus whether Implementation Class UID / Version Name are present,
// so tests can assert on the actual wire result rather than internal state.
func decodeAC(t *testing.T, raw []byte) (maxPDU uint32, classUID, versionName string) {
	t.Helper()
	decoded, err := pdu.ReadPDU(bytes.NewReader(raw), len(raw))
	if err != nil {
		t.Fatalf("ReadPDU: %v", err)
	}
	ac, ok := decoded.(*pdu.AAssociate)
	if !ok {
		t.Fatalf("decoded %T, want *pdu.AAssociate", decoded)
	}
	for _, item := range ac.Items {
		ui, ok := item.(*pdu.UserInformationItem)
		if !ok {
			continue
		}
		for _, sub := range ui.Items {
			switch v := sub.(type) {
			case *pdu.UserInformationMaximumLengthItem:
				maxPDU = v.MaximumLengthReceived
			case *pdu.ImplementationClassUIDSubItem:
				classUID = v.Name
			case *pdu.ImplementationVersionNameSubItem:
				versionName = v.Name
			}
		}
	}
	return maxPDU, classUID, versionName
}

func TestPatchAssociateAc(t *testing.T) {
	// #3155 tell 3: MaximumLengthReceived is always replaced with the fixed
	// maxPDULengthReceived, regardless of what upstream advertised -- never
	// mirrored from the SCU's own proposal (that would be an echo oracle).
	cases := []struct {
		name        string
		upstreamMax uint32
	}{
		{name: "upstream's hardcoded default", upstreamMax: 4194304},
		{name: "some other upstream value", upstreamMax: 8388608},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := realAssociateAC(t, tc.upstreamMax)
			patched, ok := patchAssociateAc(raw)
			if !ok {
				t.Fatal("patchAssociateAc returned ok=false for a well-formed AC")
			}
			gotMax, classUID, versionName := decodeAC(t, patched)
			if gotMax != maxPDULengthReceived {
				t.Errorf("MaximumLengthReceived = %d, want %d", gotMax, maxPDULengthReceived)
			}
			if classUID != implementationClassUID {
				t.Errorf("Implementation Class UID = %q, want %q (#3155 tell 1)", classUID, implementationClassUID)
			}
			if versionName != implementationVersionName {
				t.Errorf("Implementation Version Name = %q, want %q (#3155 tell 1)", versionName, implementationVersionName)
			}
		})
	}
}

func TestPatchAssociateAcSkipsNonAssociateAc(t *testing.T) {
	raw := realAssociateRQ(t, "RADIANT", "STORESCU") // an RQ, not an AC
	if _, ok := patchAssociateAc(raw); ok {
		t.Error("patchAssociateAc returned ok=true for a non-AC PDU")
	}
}

func TestPeekConnWritePatchesFirstAssociateAc(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	wrapped := &peekConn{Conn: server}
	raw := realAssociateAC(t, 4194304)

	go func() {
		if _, err := wrapped.Write(raw); err != nil {
			t.Errorf("Write: %v", err)
		}
	}()

	got := make([]byte, 0, len(raw)+64)
	buf := make([]byte, 256)
	// The patched AC gained two sub-items, so it's longer than raw; read
	// until the peer closes rather than assuming the original length.
	go func() { time.Sleep(200 * time.Millisecond); server.Close() }()
	for {
		n, err := client.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}

	gotMax, classUID, versionName := decodeAC(t, got)
	if gotMax != 16384 {
		t.Errorf("MaximumLengthReceived = %d, want 16384", gotMax)
	}
	if classUID != implementationClassUID || versionName != implementationVersionName {
		t.Errorf("got classUID=%q versionName=%q, want %q/%q", classUID, versionName, implementationClassUID, implementationVersionName)
	}
}

// TestRejectAssociation (#3155 tell 4): an unrecognized Called AE Title must
// get a real A-ASSOCIATE-RJ on the wire, not a bare closed socket.
func TestRejectAssociation(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		if err := rejectAssociation(server); err != nil {
			t.Errorf("rejectAssociation: %v", err)
		}
	}()

	raw := make([]byte, 10) // 6-byte header + 4-byte RJ payload
	if _, err := io.ReadFull(client, raw); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	decoded, err := pdu.ReadPDU(bytes.NewReader(raw), len(raw))
	if err != nil {
		t.Fatalf("ReadPDU: %v", err)
	}
	rj, ok := decoded.(*pdu.AAssociateRj)
	if !ok {
		t.Fatalf("decoded %T, want *pdu.AAssociateRj", decoded)
	}
	if rj.Result != pdu.ResultRejectedPermanent {
		t.Errorf("Result = %v, want ResultRejectedPermanent", rj.Result)
	}
	if rj.Source != pdu.SourceULServiceUser {
		t.Errorf("Source = %v, want SourceULServiceUser (PS3.8 Table 9-21 scopes called-AE-title-not-recognized to service-user)", rj.Source)
	}
	if rj.Reason != pdu.RejectReasonCalledAETitleNotRecognized {
		t.Errorf("Reason = %v, want RejectReasonCalledAETitleNotRecognized", rj.Reason)
	}
}

// TestAbortAssociation (#3155 tell 4): a first PDU that isn't a well-formed
// A-ASSOCIATE-RQ must get a real A-ABORT on the wire, not a bare closed
// socket.
func TestAbortAssociation(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	done := make(chan error, 1)
	go func() { done <- abortAssociation(server) }()

	raw := make([]byte, 10)
	if _, err := io.ReadFull(client, raw); err != nil {
		t.Fatalf("read A-ABORT: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("abortAssociation: %v", err)
	}

	decoded, err := pdu.ReadPDU(bytes.NewReader(raw), len(raw))
	if err != nil {
		t.Fatalf("ReadPDU: %v", err)
	}
	ab, ok := decoded.(*pdu.AAbort)
	if !ok {
		t.Fatalf("decoded %T, want *pdu.AAbort", decoded)
	}
	if ab.Source != pdu.SourceULServiceProviderACSE {
		t.Errorf("Source = %v, want SourceULServiceProviderACSE", ab.Source)
	}
	if ab.Reason != pdu.AbortReasonUnexpectedPDU {
		t.Errorf("Reason = %v, want AbortReasonUnexpectedPDU", ab.Reason)
	}
}
