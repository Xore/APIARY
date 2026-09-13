package main

// AE Title capture (#606): a peek at the first PDU on the wire -- always an
// A-ASSOCIATE-RQ per the DICOM UL state machine (P3.8 9.3.2) -- for the
// attacker's Called/Calling AE Title, before handing the connection to
// dicompot.RunProviderForConn. Which AE title a scanner probes with
// (ANY-SCP, STORESCP, DCM4CHEE, ...) is itself recon signal, same class as
// the C-FIND/C-MOVE/C-GET query-filter capture main.go already does.
//
// This can't be read out of dicompot.ConnectionState -- confirmed against
// the vendored package (serviceprovider.go's getConnState always returns a
// zero-value ConnectionState{}, an empty struct) or any DIMSE callback
// param: statemachine.go's AE-6 action parses these fields into a local
// variable and only ever logs them conditionally (gated behind
// enforceStatus != "no", which main.go deliberately never sets), with no
// public API surfacing them afterward. Peeking the raw bytes ourselves,
// mirroring proxyproto.go's own bufio.Reader-peek pattern in this same
// package, avoids forking the vendored state machine for two fields.
//
// Wire layout verified directly against decodeAAssociate (pdu/pdu.go):
// 6-byte PDU header (1-byte type, 1 reserved, 4-byte big-endian length),
// then 2-byte protocol version + 2 reserved + 16-byte CalledAETitle +
// 16-byte CallingAETitle, always in that order regardless of how many
// presentation-context items follow.
//
// #3155 (sensor-fidelity audit, tier 3b): three of the five reported
// fingerprint tells are reachable from here, below RunProviderForConn but
// above the raw socket, without forking the vendored state machine:
//   - the Called AE Title is only ever logged, never checked, so any title
//     is accepted and an unrecognized one gets silently dropped by the OS
//     instead of a real A-ASSOCIATE-RJ -- see rejectAssociation below; a
//     first PDU that isn't even a well-formed A-ASSOCIATE-RQ gets the same
//     treatment via abortAssociation, since there's no AE title to reject;
//   - the A-ASSOCIATE-AC statemachine.go builds never carries an
//     Implementation Class UID or Implementation Version Name item, a gap
//     a real PACS never has -- patched in on the way out by peekConn.Write;
//   - Max PDU Length in that same AC is a hardcoded 4194304; peekConn.Write
//     replaces it with the fixed maxPDULengthReceived instead, deliberately
//     not mirrored from the SCU's own proposal -- echoing it back would
//     itself be a probe oracle (send maxpdu=N, read N back in the AC).
// Tells 2 and 5 stay open; both live inside DIMSE handling the wrapper
// never touches (see the tracking issue linked from docs/SENSORS.md).

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"time"

	"github.com/nsmfoo/dicompot/pdu"
)

const (
	pduTypeAAssociateRq = 1

	// peekBufferSize bounds how much of the initial stream bufio buffers;
	// only the first 42 bytes (the Called/Calling AE Title header) are ever
	// peeked, this just keeps reads efficient once RunProviderForConn takes
	// over.
	peekBufferSize = 4096

	// Implementation Class UID / Version Name reported in the patched
	// A-ASSOCIATE-AC (#3155), consistent with the NexusAI Research GmbH
	// persona this sensor claims elsewhere (see main.go's org/site config).
	implementationClassUID    = "1.2.826.0.1.3680043.9.4674.1.1"
	implementationVersionName = "NEXUSAI_PACS_3.2"

	// maxPDULengthReceived is the Max PDU Length this persona advertises in
	// the A-ASSOCIATE-AC, replacing upstream's hardcoded 4194304 (#3155).
	// Fixed rather than mirrored from the SCU's proposal -- dcmtk storescp's
	// own default, close to pynetdicom's (16382) and dcm4che's (16378).
	maxPDULengthReceived = 16384
)

// peekConn delegates Read to the buffered reader that already peeked the
// handshake, so RunProviderForConn sees the exact same byte stream. Write is
// passed straight through, except that the first A-ASSOCIATE-AC written by
// upstream is patched per #3155 (see patchAssociateAc).
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p *peekConn) Write(b []byte) (int, error) {
	if len(b) >= 6 && b[0] == pdu.TypeAAssociateAc {
		if patched, ok := patchAssociateAc(b); ok {
			if _, err := p.Conn.Write(patched); err != nil {
				return 0, err
			}
			return len(b), nil
		}
	}
	return p.Conn.Write(b)
}

// patchAssociateAc adds a persona-consistent Implementation Class UID and
// Version Name to the AC's User Information item if upstream omitted them
// (it always does today), and replaces Max PDU Length with the fixed
// maxPDULengthReceived regardless of upstream's own value (a hardcoded
// 4194304) or what the SCU proposed -- see maxPDULengthReceived for why this
// isn't mirrored from the SCU. Returns ok=false on anything unexpected,
// telling the caller to forward the original bytes untouched rather than
// risk a malformed handshake.
func patchAssociateAc(raw []byte) ([]byte, bool) {
	decoded, err := pdu.ReadPDU(bytes.NewReader(raw), len(raw))
	if err != nil {
		return nil, false
	}
	ac, ok := decoded.(*pdu.AAssociate)
	if !ok || ac.Type != pdu.TypeAAssociateAc {
		return nil, false
	}

	var userInfo *pdu.UserInformationItem
	for _, item := range ac.Items {
		if ui, ok := item.(*pdu.UserInformationItem); ok {
			userInfo = ui
			break
		}
	}
	if userInfo == nil {
		return nil, false
	}

	var haveClassUID, haveVersionName bool
	for _, sub := range userInfo.Items {
		switch v := sub.(type) {
		case *pdu.UserInformationMaximumLengthItem:
			v.MaximumLengthReceived = maxPDULengthReceived
		case *pdu.ImplementationClassUIDSubItem:
			haveClassUID = true
		case *pdu.ImplementationVersionNameSubItem:
			haveVersionName = true
		}
	}
	if !haveClassUID {
		userInfo.Items = append(userInfo.Items, &pdu.ImplementationClassUIDSubItem{Name: implementationClassUID})
	}
	if !haveVersionName {
		userInfo.Items = append(userInfo.Items, &pdu.ImplementationVersionNameSubItem{Name: implementationVersionName})
	}

	out, err := pdu.EncodePDU(ac)
	if err != nil {
		return nil, false
	}
	return out, true
}

// rejectAssociation sends a real A-ASSOCIATE-RJ (permanent rejection,
// service-user source, called-AE-title-not-recognized -- PS3.8 Table 9-21
// scopes that reason to service-user; dcmtk (ASC_SOURCE_SERVICEUSER +
// ASC_REASON_SU_CALLEDAETITLENOTRECOGNIZED) and pynetdicom (0x01/0x01/0x07)
// pair them the same way) and lets the caller close the connection. #3155:
// replaces the previous behavior of just letting an unrecognized Called AE
// Title fall through to RunProviderForConn, or dropping the connection with
// no PDU at all.
func rejectAssociation(conn net.Conn) error {
	rj := &pdu.AAssociateRj{
		Result: pdu.ResultRejectedPermanent,
		Source: pdu.SourceULServiceUser,
		Reason: pdu.RejectReasonCalledAETitleNotRecognized,
	}
	out, err := pdu.EncodePDU(rj)
	if err != nil {
		return err
	}
	_, err = conn.Write(out)
	return err
}

// abortAssociation sends an A-ABORT (service-provider source, unrecognized
// PDU) and lets the caller close the connection. #3155: a first PDU that
// isn't a well-formed A-ASSOCIATE-RQ used to fall straight through to a
// silent TCP close; PS3.8 9.3.4's Sta2 "receive invalid PDU" transition
// raises an A-ABORT instead, and there's no parsed AE title here for
// rejectAssociation's A-ASSOCIATE-RJ to name.
func abortAssociation(conn net.Conn) error {
	ab := &pdu.AAbort{
		Source: pdu.SourceULServiceProviderACSE,
		Reason: pdu.AbortReasonUnexpectedPDU,
	}
	out, err := pdu.EncodePDU(ab)
	if err != nil {
		return err
	}
	_, err = conn.Write(out)
	return err
}

// peekAETitles wraps conn and peeks (without consuming) the first 42 bytes
// of the stream, extracting the Called/Calling AE Title if that prefix
// looks like a well-formed A-ASSOCIATE-RQ header. Returns the wrapped conn
// -- pass this to RunProviderForConn, not the original -- the two AE titles
// (empty if the peek came up short or timed out, in which case malformed is
// also false: silence isn't a protocol violation), and malformed=true when
// bytes did arrive but the first PDU type isn't A-ASSOCIATE-RQ (#3155),
// which the caller should answer with abortAssociation rather than routing
// into RunProviderForConn.
func peekAETitles(conn net.Conn) (net.Conn, string, string, bool) {
	r := bufio.NewReaderSize(conn, peekBufferSize)
	wrapped := &peekConn{Conn: conn, r: r}

	// #888: without a deadline here, a connection that never sends 42 bytes
	// (and never closes) parks this goroutine and its socket/fd in r.Peek
	// forever -- decodeProxy's own "handlers set their own deadlines"
	// comment (proxyproto.go) promises exactly this guard, which was never
	// actually added. Cleared afterward so RunProviderForConn's own DIMSE
	// handling isn't bound by a stale short deadline.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	head, err := r.Peek(42)
	if err != nil {
		conn.SetReadDeadline(time.Time{})
		return wrapped, "", "", false
	}
	if head[0] != pduTypeAAssociateRq {
		conn.SetReadDeadline(time.Time{})
		return wrapped, "", "", true
	}
	calledAE := strings.TrimSpace(string(head[10:26]))
	callingAE := strings.TrimSpace(string(head[26:42]))

	conn.SetReadDeadline(time.Time{})
	return wrapped, calledAE, callingAE, false
}
