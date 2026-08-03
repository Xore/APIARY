package main

import (
	"encoding/binary"
	"testing"
)

// buildQuery constructs a minimal, well-formed DNS query for name, with
// standard query flags (opcode 0, RD=1) and a fixed ID.
func buildQuery(name string, qtype uint16) []byte {
	req := make([]byte, 12)
	binary.BigEndian.PutUint16(req[0:2], 0x1234)
	req[2] = 0x01 // RD=1
	binary.BigEndian.PutUint16(req[4:6], 1)
	for _, label := range splitLabels(name) {
		req = append(req, byte(len(label)))
		req = append(req, label...)
	}
	req = append(req, 0) // root label
	qt := make([]byte, 2)
	binary.BigEndian.PutUint16(qt, qtype)
	req = append(req, qt...)
	req = append(req, 0, 1) // qclass IN
	return req
}

func splitLabels(name string) []string {
	if name == "" {
		return nil
	}
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return labels
}

// TestResponseNeverExceedsAmplificationCap is the test #415 explicitly asks
// for: a crafted scenario stressing the ratio cap, not just "looks small in
// practice." It sweeps a range of realistic and adversarial query shapes
// and asserts the hard invariant directly.
func TestResponseNeverExceedsAmplificationCap(t *testing.T) {
	cases := []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"short_name_A", "a.co", qtypeA},
		{"typical_name_A", "example.com", qtypeA},
		{"long_name_A", "www.this-is-a-fairly-long-subdomain-label.example.com", qtypeA},
		// ANY/TXT are the query types real amplification attacks abuse to
		// pull a large answer from a real resolver -- this sensor must cap
		// its own (fixed, small) answer regardless of what was asked.
		{"short_name_ANY", "a.co", 255},
		{"short_name_TXT", "a.co", 16},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := buildQuery(c.qname, c.qtype)
			resp := buildCappedResponse(req)
			if resp == nil {
				t.Fatalf("no response for request of %d bytes", len(req))
			}
			if ratio := float64(len(resp)) / float64(len(req)); ratio > ratioCap {
				t.Fatalf("AMPLIFICATION: request %d bytes, response %d bytes (ratio %.2f > cap %.2f)",
					len(req), len(resp), ratio, ratioCap)
			}
			if len(resp) > hardMaxBytes {
				t.Fatalf("response %d bytes exceeds hardMaxBytes %d", len(resp), hardMaxBytes)
			}
		})
	}
}

// TestResponseCapHoldsForPathologicallyShortRequests covers the worst case
// for the ratio cap: the smallest requests a real client can legitimately
// send, where even a few bytes of fixed overhead (header + answer RR) would
// blow the ratio if not actively capped.
func TestResponseCapHoldsForPathologicallyShortRequests(t *testing.T) {
	for reqLen := 12; reqLen <= 20; reqLen++ {
		req := make([]byte, reqLen)
		binary.BigEndian.PutUint16(req[0:2], 0xbeef)
		if reqLen > 12 {
			// A single one-byte label plus a root terminator, truncated to
			// whatever fits -- deliberately malformed/edge-shaped input.
			binary.BigEndian.PutUint16(req[4:6], 1)
		}
		resp := buildCappedResponse(req)
		if resp == nil {
			continue // dropping is always safe
		}
		if ratio := float64(len(resp)) / float64(reqLen); ratio > ratioCap {
			t.Fatalf("reqLen=%d: response %d bytes, ratio %.2f exceeds cap %.2f (AMPLIFICATION)", reqLen, len(resp), ratio, ratioCap)
		}
	}
}

func TestBuildCappedResponseNeverPanicsOnGarbage(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x00},
		make([]byte, 12), // header claiming qdcount=0
		{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01}, // compression pointer in question (malformed)
		append(make([]byte, 12), 0xff, 0xff, 0xff), // garbage label length claiming to run off the end
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("input %d panicked: %v", i, r)
				}
			}()
			buildCappedResponse(in)
		}()
	}
}

func TestBuildCappedResponseEchoesQuestionAndAnswersA(t *testing.T) {
	req := buildQuery("example.com", qtypeA)
	resp := buildCappedResponse(req)
	if resp == nil {
		t.Fatal("expected a response")
	}
	// ID echoed.
	if resp[0] != req[0] || resp[1] != req[1] {
		t.Fatalf("ID not echoed: req=%x resp=%x", req[0:2], resp[0:2])
	}
	// QR bit set.
	if resp[2]&0x80 == 0 {
		t.Fatal("QR bit not set in response")
	}
	// RA bit not set -- this sensor never recurses.
	if resp[3]&0x80 != 0 {
		t.Fatal("RA bit set, but this sensor must never claim recursion")
	}
}

func TestParseQuestionRejectsShortInput(t *testing.T) {
	if _, ok := parseQuestion([]byte{1, 2, 3}); ok {
		t.Fatal("expected parseQuestion to reject a too-short input")
	}
}

func TestResponseCapScalesWithRequestLength(t *testing.T) {
	if got, want := responseCap(100), 150; got != want {
		t.Fatalf("responseCap(100) = %d, want %d (ratioCap=%.1f)", got, want, ratioCap)
	}
	if got := responseCap(10000); got != hardMaxBytes {
		t.Fatalf("responseCap(10000) = %d, want hardMaxBytes=%d", got, hardMaxBytes)
	}
}

// TestIdealAnswerBranchIsReachable guards against the cap being tightened
// back down to a value that makes the answer-bearing branch permanently
// unreachable (ratioCap=1.0 does exactly that: idealLen is always exactly
// reqLen+16, so a 1.0 cap can never admit it -- see ratioCap's own
// comment). A realistically-sized query must get an actual answer, not
// just REFUSED every time.
func TestIdealAnswerBranchIsReachable(t *testing.T) {
	// A realistic, if slightly long, real-world hostname -- long enough
	// (>=32 bytes total) that the 1.5x cap can actually admit the 16-byte
	// answer RR on top of the echoed question.
	req := buildQuery("www.this-is-a-fairly-long-subdomain-label.example.com", qtypeA)
	resp := buildCappedResponse(req)
	if resp == nil {
		t.Fatal("expected a response")
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 1 {
		t.Fatalf("expected ancount=1 (an actual answer) for a realistic query, got %d -- ratioCap may be too tight", ancount)
	}
}

func TestParseHeaderFlagsExtractsOpcodeAndRD(t *testing.T) {
	req := buildQuery("example.com", qtypeA) // opcode 0, RD=1 per buildQuery's own doc comment
	opcode, rd, ok := parseHeaderFlags(req)
	if !ok {
		t.Fatal("expected ok=true for a well-formed 12-byte-plus header")
	}
	if opcode != 0 {
		t.Fatalf("opcode = %d, want 0 (QUERY)", opcode)
	}
	if !rd {
		t.Fatal("expected rd=true (buildQuery sets RD=1)")
	}

	// IQUERY (opcode 1), RD=0.
	req[2] = 0x08
	opcode, rd, ok = parseHeaderFlags(req)
	if !ok || opcode != 1 || rd {
		t.Fatalf("opcode=%d rd=%v ok=%v, want opcode=1 rd=false ok=true", opcode, rd, ok)
	}

	if _, _, ok := parseHeaderFlags([]byte{1, 2, 3}); ok {
		t.Fatal("expected ok=false for input shorter than a DNS header")
	}
}
