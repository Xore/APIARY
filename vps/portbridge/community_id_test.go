package main

import (
	"net"
	"testing"
)

// suricataVectors are real (tuple → Community ID) pairs lifted straight out of
// this deployment's own Elasticsearch on 2026-08-23 — `suricata.eve.*` records
// from `suricata-v2-flow-*`/`suricata-v2-alert-*`, where Suricata computed the
// ID itself with `community-id-seed: 0`.
//
// Testing against real Suricata output rather than the spec's published sample
// vectors is deliberate. The point of #1728 is that a portbridge row must join
// to a Suricata row for the same packets; the only thing that actually proves
// is agreeing with the Suricata instance we run, on traffic it really saw.
// 87.106.162.235 is the VPS's public address, so these are genuine inbound
// scans against our own perimeter, in both directions.
var suricataVectors = []struct {
	proto   string
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
	want    string
}{
	{"tcp", "87.106.162.235", 23, "123.188.73.228", 42451, "1:B2A/YhgfN9pLUkjt3xU/X67cjeY="},
	{"tcp", "87.106.162.235", 23, "123.188.73.228", 42454, "1:Cn9+LXmiXHrkejIN2apEQJ6wmFA="},
	{"tcp", "123.188.73.228", 42482, "87.106.162.235", 23, "1:X5VoMLhACgm02hIBoeKOK6Pu2PY="},
	{"tcp", "87.106.162.235", 23, "123.188.73.228", 42480, "1:LLBF/EfPN6/e5b/vg0qk54ziTtU="},
	{"tcp", "123.188.73.228", 42600, "87.106.162.235", 23, "1:2K9oLyoa8vnXVOhKPxQJgYQxKrE="},
	{"tcp", "94.131.219.245", 57806, "87.106.162.235", 23, "1:hC3F4R7XQXA0SU6UlVRM9krmdjM="},
	{"tcp", "123.188.73.228", 42609, "87.106.162.235", 23, "1:EXEh6N0ho1RsCXXMUYJh40Q4EBM="},
	{"tcp", "124.222.229.150", 53260, "87.106.162.235", 5900, "1:pv4jd0DGPQs3uNxCPRp6tYT7M6A="},
	{"tcp", "124.220.77.252", 36356, "87.106.162.235", 5900, "1:OPRV9zxkEG/g7aQI60J5hxSGMAo="},
	{"tcp", "121.196.193.173", 37440, "87.106.162.235", 5900, "1:4vP36prfoH2Eio4nFuMP2vj5fyE="},
	{"tcp", "85.217.140.16", 60747, "87.106.162.235", 46289, "1:7rg1K9lZPSKtZgpt3/Ehi9kbw9I="},
	{"tcp", "87.106.162.235", 23, "85.14.245.122", 56566, "1:0bXdO8Gc9HXwXWf+XPAs8La/DCk="},
	{"tcp", "198.74.50.114", 47150, "87.106.162.235", 5003, "1:QBMfK6i3DjeD080gwbS7ahGCWjs="},
	{"tcp", "103.183.74.72", 40380, "87.106.162.235", 5900, "1:5KGWys140555xFGCK1bqZK5Xm1Y="},
}

// zeekVectors are the same kind of fixture from a second, independent
// implementation: Zeek 8.0's in-core community_id_v1(), run over 199 MB of
// real VPS capture in dev/sensing-lab on 2026-08-23.
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
	{"udp", "107.174.188.218", 1032, "87.106.162.235", 5060, "1:9KSKWY8fuvWMrzsNZqWWB805Mbo="},
	{"udp", "217.160.124.58", 49692, "87.106.162.235", 5060, "1:g2oMhXrA4lN5xT78iB1oGxysb64="},
	{"udp", "167.172.89.195", 1434, "87.106.162.235", 1900, "1:DNb+3JHdavqb5KVRR9LfcO1xo78="},
	{"udp", "46.105.160.250", 54723, "87.106.162.235", 5060, "1:uvobwzMcT8H/nYILqAmYIodulkQ="},
	{"udp", "217.160.124.58", 53486, "87.106.162.235", 5060, "1:bnzwMqKirpREbqazrAyRzG/jpBo="},
	{"udp", "144.172.112.245", 50808, "87.106.162.235", 5060, "1:fKV+Jv0s1MV5KYQFWbsoF9muopg="},
	{"udp", "46.105.160.250", 61609, "87.106.162.235", 5060, "1:FoCO2b1hMz6Sz3MuI8kpQpd6Cgg="},
	{"udp", "138.117.127.7", 34528, "87.106.162.235", 38698, "1:p2715n4oww4D6l59v3lcMdqr5R0="},
	{"udp", "217.160.124.58", 58271, "87.106.162.235", 5060, "1:vinD9psc7EDuWNzJaf7xAmAmKK8="},
	{"udp", "107.189.21.227", 57423, "87.106.162.235", 5060, "1:9nvjbFy4yxzM156Dli/N/zqcmM0="},
	{"udp", "46.105.160.250", 51604, "87.106.162.235", 5060, "1:Bd+BFuMhzCdpcDA1Gwm98KikwKA="},
	{"udp", "217.160.124.58", 62466, "87.106.162.235", 5060, "1:ikKTllQwyQOn6x8Xr+cU0VawDVE="},
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
	dst := &net.TCPAddr{IP: net.ParseIP("87.106.162.235"), Port: 23}
	want := "1:X5VoMLhACgm02hIBoeKOK6Pu2PY="

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
