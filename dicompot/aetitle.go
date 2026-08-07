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

import (
	"bufio"
	"net"
	"strings"
	"time"
)

const pduTypeAAssociateRq = 1

// peekConn delegates Read to the buffered reader that already peeked the
// handshake, so RunProviderForConn sees the exact same byte stream.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// peekAETitles wraps conn and peeks (without consuming) the first 42 bytes
// of the stream, extracting the Called/Calling AE Title if that prefix
// looks like a well-formed A-ASSOCIATE-RQ header. Returns the wrapped conn
// -- pass this to RunProviderForConn, not the original -- and the two AE
// titles (empty if the peek came up short, timed out, or the PDU type
// doesn't match; an attacker skipping the handshake entirely is not this
// function's problem to solve).
func peekAETitles(conn net.Conn) (net.Conn, string, string) {
	r := bufio.NewReaderSize(conn, 4096)
	wrapped := &peekConn{Conn: conn, r: r}

	// #888: without a deadline here, a connection that never sends 42 bytes
	// (and never closes) parks this goroutine and its socket/fd in r.Peek
	// forever -- decodeProxy's own "handlers set their own deadlines"
	// comment (proxyproto.go) promises exactly this guard, which was never
	// actually added. Cleared afterward so RunProviderForConn's own DIMSE
	// handling isn't bound by a stale short deadline.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	head, err := r.Peek(42)
	conn.SetReadDeadline(time.Time{})
	if err != nil || head[0] != pduTypeAAssociateRq {
		return wrapped, "", ""
	}
	calledAE := strings.TrimSpace(string(head[10:26]))
	callingAE := strings.TrimSpace(string(head[26:42]))
	return wrapped, calledAE, callingAE
}
