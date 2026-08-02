// p0f.go — query p0f's passive-fingerprint API for an attacker's OS guess.
//
// portbridge already sees every real attacker IP before anything else on the
// VPS (that's its whole job), and p0f (vps/docker-compose.yml, run in -s API
// mode rather than its -j JSON-log mode) already sniffs the same public
// interface and keeps a live in-memory table of what it has fingerprinted per
// source IP. Rather than shipping a second, independently-rotated JSON log
// for the dashboard to correlate by IP after the fact, portbridge queries p0f
// directly at connection time and folds the answer into the one JSON line it
// already writes per connection (connLogger.log) — one log, one join, same as
// every other field on that line.
//
// Wire format is p0f's own binary API protocol (vendored at vps/p0f/api.h),
// unchanged from vanilla p0f: a single packed request/response pair over a
// Unix domain socket, native byte order (no htonl/ntohl anywhere in p0f's own
// client, tools/p0f-client.c — this never leaves the host, so there is
// nothing to convert). encoding/binary.LittleEndian matches the x86_64 VPS
// this runs on.
package main

import (
	"encoding/binary"
	"net"
	"time"
)

const (
	p0fQueryMagic = 0x50304601
	p0fRespMagic  = 0x50304602

	p0fStatusOK      = 0x10
	p0fStatusNoMatch = 0x20

	p0fAddrIPv4 = 0x04
	p0fAddrIPv6 = 0x06

	p0fQueryTimeout = 300 * time.Millisecond
)

// p0fQuery mirrors struct p0f_api_query (api.h) byte-for-byte: 4 + 1 + 16 = 21
// bytes, no padding — encoding/binary walks fields in order regardless of Go's
// own in-memory struct layout, so this doesn't need a packed pragma.
type p0fQuery struct {
	Magic    uint32
	AddrType uint8
	Addr     [16]byte
}

// p0fResponse mirrors struct p0f_api_response (api.h): 232 bytes.
type p0fResponse struct {
	Magic      uint32
	Status     uint32
	FirstSeen  uint32
	LastSeen   uint32
	TotalConn  uint32
	UptimeMin  uint32
	UpModDays  uint32
	LastNAT    uint32
	LastChg    uint32
	Distance   int16
	BadSW      uint8
	OSMatchQ   uint8
	OSName     [32]byte
	OSFlavor   [32]byte
	HTTPName   [32]byte
	HTTPFlavor [32]byte
	LinkType   [32]byte
	Language   [32]byte
}

// cString trims a fixed-size, NUL-padded C string (strncpy in api.c never
// guarantees a trailing NUL when the source fills the whole buffer) at its
// first zero byte, or returns it whole if none is present.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// queryP0f asks p0f what it knows about ip and returns a display string like
// "Linux 3.11 and newer", or "" if p0f is unconfigured, unreachable, or has
// no match — never an error the caller needs to handle. sock == "" (the
// common case when p0f isn't deployed, e.g. every non-VPS portbridge
// instance) short-circuits before touching the network.
func queryP0f(sock, ip string) string {
	if sock == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	q := p0fQuery{Magic: p0fQueryMagic}
	if v4 := parsed.To4(); v4 != nil {
		q.AddrType = p0fAddrIPv4
		copy(q.Addr[:], v4)
	} else {
		q.AddrType = p0fAddrIPv6
		copy(q.Addr[:], parsed.To16())
	}

	conn, err := net.DialTimeout("unix", sock, p0fQueryTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p0fQueryTimeout))

	if err := binary.Write(conn, binary.LittleEndian, &q); err != nil {
		return ""
	}
	var r p0fResponse
	if err := binary.Read(conn, binary.LittleEndian, &r); err != nil {
		return ""
	}
	if r.Magic != p0fRespMagic || r.Status != p0fStatusOK {
		return "" // bad magic, BADQUERY, or NOMATCH (p0f hasn't seen this IP yet)
	}

	name := cString(r.OSName[:])
	if name == "" {
		return ""
	}
	if flavor := cString(r.OSFlavor[:]); flavor != "" {
		return name + " " + flavor
	}
	return name
}
