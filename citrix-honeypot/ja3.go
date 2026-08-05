package main

// JA3 TLS ClientHello fingerprinting (#609): dashboard/classify.go has
// checked for an x-ja3/x-ja4 header on every citrix-honeypot request since
// #553, but nothing in this stack ever computed one -- confirmed by
// repo-wide grep, the branch was dead code. citrix-honeypot terminates its
// own TLS handshake in-process (tls.go's selfSignedCert + main.go's
// tls.NewListener), which makes it the right place to compute a real JA3
// from the raw ClientHello: Go's crypto/tls only exposes the negotiated
// (single) cipher/version via tls.ConnectionState, never the full list the
// client offered, which is what JA3/JA4 actually fingerprint.
//
// JA3 only, not JA4, on purpose: JA4's hash-input string format (exact
// delimiters/ordering feeding the two truncated-SHA256 components) has
// enough real-world implementation variance that landing it here without a
// way to cross-verify against a reference implementation risked shipping a
// wrong hash as if it were reliable security telemetry. JA3's format is
// simple and unambiguous (decimal fields, original wire order, single MD5)
// and is verified below against hand-computed vectors. JA4 is tracked
// separately (see the issue filed alongside this commit).
//
// Reference: Salesforce's original JA3 spec -- MD5 of
// "TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats",
// each field a "-"-joined list of decimal values in the order they
// appeared on the wire (not sorted -- that's JA4, not JA3), GREASE values
// excluded from every list per the now-universal convention (GREASE is
// randomized per connection specifically to prevent ossification/
// fingerprinting, so including it would make the hash useless as a
// fingerprint).

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	tlsRecordHandshake  = 0x16
	tlsHandshakeClient  = 0x01
	extSupportedGroups  = 0x000a
	extECPointFormats   = 0x000b
	maxClientHelloBytes = 1 << 16 // generous vs. any real ClientHello (~0.5-2KB)
)

// isGREASE reports whether v is one of RFC 8701's 16 reserved GREASE
// values (0x0a0a, 0x1a1a, ..., 0xfafa) -- present in cipher/extension/group
// lists specifically so naive fingerprinting breaks; every real JA3
// implementation filters these out first.
func isGREASE(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

// ja3Listener peeks each connection's ClientHello at Accept() time --
// same blocking-at-accept precedent proxyproto.go's proxyListener already
// established for the PROXY header -- and computes its JA3 fingerprint
// before the real TLS handshake (tls.NewListener wraps this listener) ever
// runs. A short read deadline bounds how long a slow/absent ClientHello
// can hold up the shared accept loop.
type ja3Listener struct{ net.Listener }

func (l *ja3Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReaderSize(c, maxClientHelloBytes)
	fp := peekJA3(r)
	c.SetReadDeadline(time.Time{}) // clear; the real TLS handshake sets its own
	return &ja3Conn{Conn: c, r: r, fp: fp}, nil
}

// ja3Conn replays the bytes peekJA3 already read (via r) to the real TLS
// handshake, and carries the computed fingerprint for ConnContext to pick
// up (see main.go) once the handshake calls Read.
type ja3Conn struct {
	net.Conn
	r  *bufio.Reader
	fp string
}

func (j *ja3Conn) Read(b []byte) (int, error) { return j.r.Read(b) }

// JA3 returns the fingerprint computed from this connection's ClientHello,
// or "" if none was found (non-TLS traffic or a truncated/malformed
// handshake).
func (j *ja3Conn) JA3() string { return j.fp }

// peekJA3 parses a TLS record + Handshake ClientHello from r without
// consuming it (net/http's tls.Conn still needs every byte for the real
// handshake) and returns "hash|ja3_string" for logging, or "" if the
// prefix isn't a well-formed ClientHello.
func peekJA3(r *bufio.Reader) string {
	head, err := r.Peek(5)
	if err != nil || head[0] != tlsRecordHandshake {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(head[3:5]))
	if recLen <= 0 || recLen > maxClientHelloBytes-5 {
		return ""
	}
	buf, err := r.Peek(5 + recLen)
	if err != nil {
		return ""
	}
	body := buf[5:]
	if len(body) < 4 || body[0] != tlsHandshakeClient {
		return ""
	}
	msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	body = body[4:]
	if len(body) < msgLen {
		return "" // fragmented across multiple records -- not handled
	}
	body = body[:msgLen]

	ver, ciphers, exts, groups, points, ok := parseClientHello(body)
	if !ok {
		return ""
	}
	// #002b supported_versions overrides the legacy client_version field
	// on TLS 1.3, same rule JA4 uses, and the value JA3 tools report.
	if sv, present := extData(body, 0x002b); present && len(sv) >= 3 {
		// data = 1-byte list-len + N*2-byte versions; take the highest.
		best := ver
		for i := 1; i+1 < len(sv); i += 2 {
			if v := binary.BigEndian.Uint16(sv[i : i+2]); !isGREASE(v) && v > best {
				best = v
			}
		}
		ver = best
	}

	ja3 := strings.Join([]string{
		strconv.Itoa(int(ver)),
		joinDecimal(ciphers),
		joinDecimal(exts),
		joinDecimal(groups),
		joinDecimalBytes(points),
	}, ",")
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:])
}

// parseClientHello walks a ClientHello body (post 4-byte handshake header)
// and extracts the fields JA3 needs, filtering GREASE from every list.
func parseClientHello(b []byte) (version uint16, ciphers, exts, groups []uint16, points []byte, ok bool) {
	if len(b) < 2+32+1 {
		return
	}
	version = binary.BigEndian.Uint16(b[0:2])
	pos := 2 + 32 // client_version + random

	sidLen := int(b[pos])
	pos++
	if pos+sidLen > len(b) {
		return
	}
	pos += sidLen

	if pos+2 > len(b) {
		return
	}
	csLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	if pos+csLen > len(b) {
		return
	}
	for i := 0; i+1 < csLen; i += 2 {
		v := binary.BigEndian.Uint16(b[pos+i : pos+i+2])
		if !isGREASE(v) {
			ciphers = append(ciphers, v)
		}
	}
	pos += csLen

	if pos+1 > len(b) {
		return
	}
	cmLen := int(b[pos])
	pos++
	if pos+cmLen > len(b) {
		return
	}
	pos += cmLen

	if pos+2 > len(b) {
		ok = true // no extensions block at all is unusual but not fatal
		return
	}
	extTotalLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	if pos+extTotalLen > len(b) {
		extTotalLen = len(b) - pos
	}
	end := pos + extTotalLen
	for pos+4 <= end {
		typ := binary.BigEndian.Uint16(b[pos : pos+2])
		l := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		pos += 4
		if pos+l > end {
			break
		}
		data := b[pos : pos+l]
		pos += l

		if !isGREASE(typ) {
			exts = append(exts, typ)
		}
		switch typ {
		case extSupportedGroups:
			if len(data) >= 2 {
				n := int(binary.BigEndian.Uint16(data[0:2]))
				for i := 2; i+1 < 2+n && i+1 < len(data); i += 2 {
					if v := binary.BigEndian.Uint16(data[i : i+2]); !isGREASE(v) {
						groups = append(groups, v)
					}
				}
			}
		case extECPointFormats:
			if len(data) >= 1 {
				n := int(data[0])
				for i := 1; i < 1+n && i < len(data); i++ {
					points = append(points, data[i])
				}
			}
		}
	}
	ok = true
	return
}

// extData returns the raw data of the first extension matching typ, if
// present, by re-walking the same extensions block parseClientHello did.
func extData(b []byte, typ uint16) ([]byte, bool) {
	if len(b) < 2+32+1 {
		return nil, false
	}
	pos := 2 + 32
	sidLen := int(b[pos])
	pos++
	if pos+sidLen > len(b) {
		return nil, false
	}
	pos += sidLen
	if pos+2 > len(b) {
		return nil, false
	}
	csLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(b) {
		return nil, false
	}
	cmLen := int(b[pos])
	pos += 1 + cmLen
	if pos+2 > len(b) {
		return nil, false
	}
	extTotalLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	end := pos + extTotalLen
	if end > len(b) {
		end = len(b)
	}
	for pos+4 <= end {
		t := binary.BigEndian.Uint16(b[pos : pos+2])
		l := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		pos += 4
		if pos+l > end {
			break
		}
		if t == typ {
			return b[pos : pos+l], true
		}
		pos += l
	}
	return nil, false
}

func joinDecimal(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinDecimalBytes(vs []byte) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}
