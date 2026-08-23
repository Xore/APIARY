package main

import (
	"net"
	"testing"
)

// suricataVectors began as real (tuple → Community ID) pairs from this
// deployment's own Elasticsearch, and the responder address has since been
// replaced with RFC 5737 documentation space: this is a public repository and
// the real one is deployment-specific (scripts/check-public-leaks.py enforces
// that, and caught it).
//
// Substituting the address invalidates every expected hash, so these were
// recomputed rather than edited -- with Zeek's own community_id_v1(), not with
// the implementation under test. That keeps the property these fixtures exist
// for: the Go code is checked against an independent implementation of the
// same spec, and specifically the one this stack must agree with. What is lost
// is that the tuples are literally captured traffic; what is kept is the
// cross-implementation guarantee, which is the half that catches bugs.
//
// The originator addresses are left as captured -- they are real scanners, and
// nothing about them is specific to this deployment.
var suricataVectors = []struct {
	proto   string
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
	want    string
}{
	{"tcp", "198.51.100.20", 23, "123.188.73.228", 42451, "1:IIqFM6s6T7Q3qpPtQlcLozWAsqc="},
	{"tcp", "198.51.100.20", 23, "123.188.73.228", 42454, "1:U7bTdnEE0KkShgNEwLj+sJ/dRQg="},
	{"tcp", "123.188.73.228", 42482, "198.51.100.20", 23, "1:YCy2phL1VvHw/ee7ABoEJYPCcRk="},
	{"tcp", "198.51.100.20", 23, "123.188.73.228", 42480, "1:xzaGr2HzD6xPBtKSCud1UwzsGfE="},
	{"tcp", "123.188.73.228", 42600, "198.51.100.20", 23, "1:Zw+D+8+o/xGCYgXUbILTq5rPV80="},
	{"tcp", "94.131.219.245", 57806, "198.51.100.20", 23, "1:b0iDcD8ZThtLhSFx7oYoSQE0l58="},
	{"tcp", "123.188.73.228", 42609, "198.51.100.20", 23, "1:Z0uDFSDJ8BA6l5L2SE+6eqVZidc="},
	{"tcp", "124.222.229.150", 53260, "198.51.100.20", 5900, "1:sQ1WP/gQDETidlyH4iAwiUGYyFI="},
	{"tcp", "124.220.77.252", 36356, "198.51.100.20", 5900, "1:XcNpqUxrNFfbnALEd7M2XWpoxFI="},
	{"tcp", "121.196.193.173", 37440, "198.51.100.20", 5900, "1:a76hEXF3PiTtuXIlehOEL+J8apA="},
	{"tcp", "85.217.140.16", 60747, "198.51.100.20", 46289, "1:UNE6fvrvzraqUf0OLOq3jTVbauI="},
	{"tcp", "198.51.100.20", 23, "85.14.245.122", 56566, "1:2buCQRvxuKUm447oPSsr1SO1cv0="},
	{"tcp", "198.74.50.114", 47150, "198.51.100.20", 5003, "1:YDXfCSDYgtLn7PkRgKQywAQMYf0="},
	{"tcp", "103.183.74.72", 40380, "198.51.100.20", 5900, "1:H2Qx8TMRgj/w88LvoVYx0ajYNEY="},
}

// zeekVectors cover the UDP half. Same provenance and same substitution as
// above.
//
// Two reasons this exists alongside suricataVectors. First, agreeing with one
// implementation could mean both are wrong the same way; agreeing with two
// written by different projects is much stronger evidence the hash is right.
// Second and more practically, **every usable Suricata fixture was TCP** --
// so without these, UDP hashing was only ever tested for the cases where it
// declines to produce an ID, never for producing the correct one. Zeek's
// conn.log carried 250 UDP flows, which closes that gap.
var zeekVectors = []struct {
	proto   string
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
	want    string
}{
	{"udp", "107.174.188.218", 1032, "198.51.100.20", 5060, "1:dTygMYvbdFFKpWRBgjgdXy82+ec="},
	{"udp", "217.160.124.58", 49692, "198.51.100.20", 5060, "1:8XD/U0T0Np6Hfqm8KEiL8wFgyXo="},
	{"udp", "167.172.89.195", 1434, "198.51.100.20", 1900, "1:UvV/ad2me9OyoAKUSWKX9jUX/+I="},
	{"udp", "46.105.160.250", 54723, "198.51.100.20", 5060, "1:OuGHk+tSDv+eV114znY+Qo5Jqfo="},
	{"udp", "217.160.124.58", 53486, "198.51.100.20", 5060, "1:/1l1BdLm36u+pcTN9CZ3HpD0Lmw="},
	{"udp", "144.172.112.245", 50808, "198.51.100.20", 5060, "1:+SljFPLoBy8bhhRXRqMDyUoHBhk="},
	{"udp", "46.105.160.250", 61609, "198.51.100.20", 5060, "1:2CXXgkGidLD54I7VGjydTgdDBeM="},
	{"udp", "138.117.127.7", 34528, "198.51.100.20", 38698, "1:2B8cMkAxqDpzI6juGBf82Y1oDoo="},
	{"udp", "217.160.124.58", 58271, "198.51.100.20", 5060, "1:5BKDjw2YONkfYk41DiFFZghr3BM="},
	{"udp", "107.189.21.227", 57423, "198.51.100.20", 5060, "1:VWoJ1lAmt8unRAQNqayTWDEU8jI="},
	{"udp", "46.105.160.250", 51604, "198.51.100.20", 5060, "1:h+VyutXo9VQ8zS/BWC5Bv1ynK3U="},
	{"udp", "217.160.124.58", 62466, "198.51.100.20", 5060, "1:V9NkjK4Y3HdeT0B6kWu/+1JeUF0="},
}

func TestCommunityIDMatchesZeek(t *testing.T) {
	for _, v := range zeekVectors {
		got := communityIDFromParts(v.proto, v.srcIP, v.srcPort, v.dstIP, v.dstPort)
		if got != v.want {
			t.Errorf("communityID(%s %s:%d -> %s:%d) = %q, Zeek says %q",
				v.proto, v.srcIP, v.srcPort, v.dstIP, v.dstPort, got, v.want)
		}
	}
}

func TestCommunityIDMatchesSuricata(t *testing.T) {
	for _, v := range suricataVectors {
		got := communityIDFromParts(v.proto, v.srcIP, v.srcPort, v.dstIP, v.dstPort)
		if got != v.want {
			t.Errorf("communityID(%s %s:%d -> %s:%d) = %q, Suricata says %q",
				v.proto, v.srcIP, v.srcPort, v.dstIP, v.dstPort, got, v.want)
		}
	}
}

// The hash must be direction-agnostic: portbridge sees a flow from the
// attacker's side, Suricata sniffs the same packets off the wire, and Zeek may
// order the endpoints the other way round. If reversing the tuple changed the
// ID, none of them would ever join.
func TestCommunityIDIsBidirectional(t *testing.T) {
	for _, v := range suricataVectors {
		forward := communityIDFromParts(v.proto, v.srcIP, v.srcPort, v.dstIP, v.dstPort)
		reverse := communityIDFromParts(v.proto, v.dstIP, v.dstPort, v.srcIP, v.srcPort)
		if forward != reverse {
			t.Errorf("%s:%d <-> %s:%d hashed differently per direction: %q vs %q",
				v.srcIP, v.srcPort, v.dstIP, v.dstPort, forward, reverse)
		}
	}
}

// Go hands out IPv4 addresses in either 4- or 16-byte form depending on how
// they were produced. Both must hash identically, or the ID silently depends
// on which constructor a call site happened to use.
func TestCommunityIDIPv4FormIndependent(t *testing.T) {
	four := net.IPv4(203, 0, 113, 5).To4()
	sixteen := net.IPv4(203, 0, 113, 5).To16()
	dst := net.ParseIP("198.51.100.7")

	got4 := communityID(protoTCP, four, 1234, dst, 80)
	got16 := communityID(protoTCP, sixteen, 1234, dst, 80)
	if got4 == "" || got4 != got16 {
		t.Fatalf("4-byte and 16-byte IPv4 forms disagree: %q vs %q", got4, got16)
	}
}

func TestCommunityIDIPv6(t *testing.T) {
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")
	forward := communityID(protoTCP, src, 40000, dst, 443)
	reverse := communityID(protoTCP, dst, 443, src, 40000)
	if forward == "" {
		t.Fatal("IPv6 tuple produced no Community ID")
	}
	if forward != reverse {
		t.Errorf("IPv6 hash is direction-dependent: %q vs %q", forward, reverse)
	}
}

// Anything we cannot hash correctly must yield "", never a plausible-looking
// value. An ID derived from a wildcard bind or an unknown protocol would look
// joinable in Elasticsearch and match nothing, which is strictly worse than an
// absent field.
func TestCommunityIDRefusesIncompleteTuples(t *testing.T) {
	cases := []struct {
		name         string
		proto, srcIP string
		srcPort      int
		dstIP        string
		dstPort      int
	}{
		{"wildcard v4 destination", "udp", "203.0.113.5", 1234, "0.0.0.0", 53},
		{"wildcard v6 destination", "udp", "2001:db8::1", 1234, "::", 53},
		{"wildcard source", "tcp", "0.0.0.0", 1234, "203.0.113.5", 80},
		{"unknown protocol", "sctp", "203.0.113.5", 1234, "198.51.100.7", 80},
		{"unparseable address", "tcp", "not-an-ip", 1234, "198.51.100.7", 80},
		{"empty address", "tcp", "", 1234, "198.51.100.7", 80},
	}
	for _, c := range cases {
		if got := communityIDFromParts(c.proto, c.srcIP, c.srcPort, c.dstIP, c.dstPort); got != "" {
			t.Errorf("%s: expected no Community ID, got %q", c.name, got)
		}
	}
}

func TestCommunityIDRejectsMixedAddressFamilies(t *testing.T) {
	v4 := net.ParseIP("203.0.113.5")
	v6 := net.ParseIP("2001:db8::1")
	if got := communityID(protoTCP, v4, 1234, v6, 80); got != "" {
		t.Errorf("mixed v4/v6 tuple should not hash, got %q", got)
	}
}

func TestCommunityIDFromAddrs(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("123.188.73.228"), Port: 42482}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 23}
	want := "1:YCy2phL1VvHw/ee7ABoEJYPCcRk="

	if got := communityIDFromAddrs("tcp", src, dst); got != want {
		t.Errorf("communityIDFromAddrs = %q, want %q", got, want)
	}
	if got := communityIDFromAddrs("tcp", nil, dst); got != "" {
		t.Errorf("nil source should yield no ID, got %q", got)
	}
	if got := communityIDFromAddrs("tcp", src, nil); got != "" {
		t.Errorf("nil destination should yield no ID, got %q", got)
	}
}

func TestProtoNumber(t *testing.T) {
	if protoNumber("tcp") != protoTCP {
		t.Error("tcp should map to 6")
	}
	if protoNumber("udp") != protoUDP {
		t.Error("udp should map to 17")
	}
	if protoNumber("icmp") != 0 {
		t.Error("unsupported protocols should map to 0")
	}
}
