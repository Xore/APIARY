package main

// dns.go builds a DNS response for a raw query, with one rule this file
// exists to enforce: the response must never be usable as a UDP
// amplification vector (#238, #415). This sensor never contacts a real
// resolver at all (unlike T-Pot's ddospot, whose dns.py forwards every new
// query to a real upstream resolver and relays its real -- unbounded --
// response straight through; verified directly against ddospot's own
// source before deciding not to vendor it, see #415), so there is no
// upstream answer size to inherit in the first place. What this file adds
// on top of that is a second, independent belt-and-suspenders guarantee:
// even the small canned answer it constructs itself is capped in code, at
// a ratio far below anything that matters for real amplification abuse
// (see ratioCap below), not just "small in practice."

import "encoding/binary"

const (
	// hardMaxBytes is the classic RFC 1035 non-EDNS UDP response ceiling.
	// Independent of ratioCap below -- either one alone would already
	// prevent amplification for realistically-sized queries; both are
	// enforced so neither has to be perfectly tuned on its own.
	hardMaxBytes = 512
	// ratioCap bounds the response to at most 1.5x the request's own byte
	// length -- far below any ratio that matters for real-world DDoS
	// amplification (historical DNS/NTP/memcached incidents abuse ratios
	// from ~28x into the tens of thousands; industry treats amplification
	// as a concern starting around 3x). 1.0 was considered and rejected:
	// this decoy's own reply always echoes the question verbatim (so the
	// question-echo portion of any response is exactly the request's own
	// remaining length after the 12-byte header) plus a fixed 16-byte
	// answer RR, so a 1.0 cap makes the answer mathematically unreachable
	// for every possible request (idealLen is always exactly reqLen+16,
	// which a 1.0 cap can never admit) -- safe, but a permanently
	// non-functional-looking decoy. 1.5 keeps the same "cannot realistically
	// amplify" guarantee while letting real-sized queries (roughly 32+
	// bytes, i.e. almost everything but the shortest single-letter names)
	// get an actual small answer instead of always falling back to REFUSED.
	ratioCap = 1.5

	rcodeNoError = 0
	rcodeFormErr = 1
	rcodeRefused = 5
	qtypeA       = 1
	qclassIN     = 1
	answerTTL    = 60
	fakeAIP      = "203.0.113.1" // TEST-NET-3 (RFC 5737): documentation range, never a routed real host.
)

// responseCap returns the maximum number of bytes buildCappedResponse may
// return for a request of this length.
func responseCap(reqLen int) int {
	cap := int(float64(reqLen) * ratioCap)
	if cap > hardMaxBytes {
		cap = hardMaxBytes
	}
	return cap
}

// question is the first (and only, for this honeypot's purposes) question
// this decoy parses out of a request.
type question struct {
	// raw is the question's exact on-the-wire bytes (name + qtype + qclass),
	// echoed back verbatim rather than re-encoded -- simplest way to
	// guarantee the echoed question is byte-identical to what was asked.
	raw   []byte
	qtype uint16
	name  string // best-effort decoded, for logging only
}

// parseQuestion reads the first question immediately following the 12-byte
// header. It does not support name compression (a query's own question
// section never legitimately uses it) and gives up on anything it can't
// walk cleanly -- an honeypot has no obligation to make sense of malformed
// input, only to never crash on it and never answer it expensively.
func parseQuestion(req []byte) (question, bool) {
	if len(req) < 12 {
		return question{}, false
	}
	qdcount := binary.BigEndian.Uint16(req[4:6])
	if qdcount == 0 {
		return question{}, false
	}
	i := 12
	var nameBuilder []byte
	for {
		if i >= len(req) {
			return question{}, false
		}
		labelLen := int(req[i])
		if labelLen&0xc0 != 0 {
			return question{}, false // compression pointer: not expected in a query
		}
		if labelLen == 0 {
			i++
			break
		}
		i++
		if i+labelLen > len(req) {
			return question{}, false
		}
		if len(nameBuilder) > 0 {
			nameBuilder = append(nameBuilder, '.')
		}
		nameBuilder = append(nameBuilder, req[i:i+labelLen]...)
		i += labelLen
	}
	if i+4 > len(req) {
		return question{}, false
	}
	qtype := binary.BigEndian.Uint16(req[i : i+2])
	end := i + 4
	return question{raw: req[12:end], qtype: qtype, name: string(nameBuilder)}, true
}

// parseHeaderFlags extracts OPCODE and RD from a request's 12-byte header.
// Which opcode an attacker sends (0=QUERY is normal traffic; IQUERY/STATUS/
// NOTIFY/UPDATE are non-standard probes worth telling apart in logs) was
// previously computed inline inside buildCappedResponse purely to echo it
// back, and never surfaced to the caller for logging.
func parseHeaderFlags(req []byte) (opcode byte, rd bool, ok bool) {
	if len(req) < 12 {
		return 0, false, false
	}
	return (req[2] & 0x78) >> 3, req[2]&0x01 != 0, true
}

// buildCappedResponse constructs a reply to req, choosing the most
// complete response that still fits within responseCap(len(req)). It never
// returns a slice longer than that cap. Callers should treat a nil return
// as "do not reply" -- reserved for input too short to safely reason
// about at all.
func buildCappedResponse(req []byte) []byte {
	if len(req) < 12 {
		return nil
	}
	id := req[0:2]
	opcode := req[2] & 0x78 // preserve OPCODE nibble, drop QR/AA/TC/RD from the request's own byte
	rd := req[2] & 0x01

	header := func(qdcount, ancount uint16, rcode byte) []byte {
		h := make([]byte, 12)
		copy(h[0:2], id)
		h[2] = 0x80 | opcode | rd // QR=1, echo opcode, echo RD
		h[3] = rcode & 0x0f       // RA=0: this sensor never recurses, and says so honestly
		binary.BigEndian.PutUint16(h[4:6], qdcount)
		binary.BigEndian.PutUint16(h[6:8], ancount)
		return h
	}

	capBytes := responseCap(len(req))

	q, ok := parseQuestion(req)
	if !ok {
		resp := header(0, 0, rcodeFormErr)
		if len(resp) <= capBytes {
			return resp
		}
		return nil // cap smaller than a bare header: nothing safe to send
	}

	// Ideal reply: echo the question, answer with one small fixed A record.
	// Answer name is a compression pointer at offset 12 (the question we're
	// echoing right after the header), not a second copy of the name --
	// smaller, and standard practice for any real server's own replies.
	answer := make([]byte, 16) // ptr(2) + type(2) + class(2) + ttl(4) + rdlength(2) + rdata(4)
	answer[0], answer[1] = 0xc0, 0x0c
	binary.BigEndian.PutUint16(answer[2:4], qtypeA)
	binary.BigEndian.PutUint16(answer[4:6], qclassIN)
	binary.BigEndian.PutUint32(answer[6:10], answerTTL)
	binary.BigEndian.PutUint16(answer[10:12], 4)
	copy(answer[12:16], ipv4Bytes(fakeAIP))

	ideal := append(header(1, 1, rcodeNoError), q.raw...)
	ideal = append(ideal, answer...)
	if len(ideal) <= capBytes {
		return ideal
	}

	// Fallback: echo the question, no answer -- looks like a server that
	// heard the query and declined to resolve it, which is true.
	fallback := append(header(1, 0, rcodeRefused), q.raw...)
	if len(fallback) <= capBytes {
		return fallback
	}

	// Last resort: bare header. Always fits: cap >= len(req) >= 12 whenever
	// we got this far (ratioCap >= 1.0), and a bare header is exactly 12
	// bytes.
	return header(0, 0, rcodeFormErr)
}

func ipv4Bytes(s string) []byte {
	b := make([]byte, 4)
	n, part := 0, 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			b[n] = byte(part)
			n++
			part = 0
			continue
		}
		part = part*10 + int(s[i]-'0')
	}
	return b
}
