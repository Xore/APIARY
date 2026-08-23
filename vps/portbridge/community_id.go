// community_id.go — Community ID v1 flow hashing (#1728).
//
// portbridge holds the one fact nothing else on the wire can recover: the real
// attacker IP for every relayed connection. Suricata already stamps every flow
// it sees with a Community ID (vps/suricata/suricata.yaml's `community-id:
// true`), and Zeek has computed the same hash in-core since Zeek 6 — but
// portbridge emitted no join key at all, so correlating its conn log to the
// wire sensors meant matching on (src_ip, timestamp) and hoping. That is
// lossy exactly where it matters most: a scanner opening 200 connections from
// one IP inside one second collapses into a single bucket.
//
// Community ID is the join key every sensor in the stack already speaks, so
// this computes it here rather than inventing a portbridge-specific one.
//
// Spec: https://github.com/corelight/community-id-spec. The hashed buffer is
//
//	seed (2, big endian) ‖ saddr ‖ daddr ‖ proto (1) ‖ 0x00 ‖ sport (2, BE) ‖ dport (2, BE)
//
// base64'd SHA-1, prefixed "1:" for the version. Endpoints are ordered
// canonically first (lower address wins, ties broken by port) so both
// directions of one flow hash identically — that bidirectionality is the whole
// point, and it is what lets a portbridge row meet a Suricata record that saw
// the same packets from the other side.
//
// The seed must match Suricata's `community-id-seed: 0`; a different seed
// produces a well-formed hash that silently never matches anything.
package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"net"
)

// IANA protocol numbers for the two transports portbridge forwards.
const (
	protoTCP = 6
	protoUDP = 17
)

// communityIDSeed matches vps/suricata/suricata.yaml's community-id-seed.
// Suricata and Zeek both default to 0; this is pinned rather than left
// implicit because a mismatch is invisible — every value still looks like a
// valid Community ID, it just never equals the one the other sensor computed.
const communityIDSeed uint16 = 0

// protoNumber maps a rule's proto string to its IANA number. Returns 0 for
// anything else, which callers treat as "cannot compute".
func protoNumber(proto string) uint8 {
	switch proto {
	case "tcp":
		return protoTCP
	case "udp":
		return protoUDP
	}
	return 0
}

// communityID returns the Community ID v1 string for one 5-tuple, or "" if the
// tuple is not complete enough to hash. Returning "" rather than a
// best-effort value is deliberate: a Community ID computed from a wrong or
// placeholder address (a wildcard 0.0.0.0 bind, say) is worse than no field at
// all, because it looks joinable and never joins.
func communityID(proto uint8, srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) string {
	if proto == 0 || srcIP == nil || dstIP == nil {
		return ""
	}
	if srcPort < 0 || srcPort > 65535 || dstPort < 0 || dstPort > 65535 {
		return ""
	}
	// Pack to the address's own width. A v4 address carried in Go's 16-byte
	// IPv4-in-IPv6 form must hash as its 4 bytes, or the digest differs from
	// every other implementation's for the same flow.
	src, dst := canonicalIP(srcIP), canonicalIP(dstIP)
	if src == nil || dst == nil || len(src) != len(dst) {
		return ""
	}

	if !flowIsOrdered(src, srcPort, dst, dstPort) {
		src, dst = dst, src
		srcPort, dstPort = dstPort, srcPort
	}

	buf := make([]byte, 0, 2+len(src)+len(dst)+2+4)
	buf = binary.BigEndian.AppendUint16(buf, communityIDSeed)
	buf = append(buf, src...)
	buf = append(buf, dst...)
	buf = append(buf, proto, 0) // 0x00 pads the protocol byte to 2 bytes
	buf = binary.BigEndian.AppendUint16(buf, uint16(srcPort))
	buf = binary.BigEndian.AppendUint16(buf, uint16(dstPort))

	sum := sha1.Sum(buf)
	return "1:" + base64.StdEncoding.EncodeToString(sum[:])
}

// canonicalIP returns the 4-byte form for a v4 address and the 16-byte form
// for a v6 one.
func canonicalIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// flowIsOrdered reports whether (src, sport) already sorts ahead of
// (dst, dport) — lower address first, ties broken by the lower port. Both
// slices must already be the same width.
func flowIsOrdered(src net.IP, srcPort int, dst net.IP, dstPort int) bool {
	for i := range src {
		if src[i] != dst[i] {
			return src[i] < dst[i]
		}
	}
	return srcPort < dstPort
}

// communityIDFromAddrs is the net.Addr-shaped wrapper the connection logger
// uses. Either address being nil or unparseable yields "".
func communityIDFromAddrs(proto string, src, dst net.Addr) string {
	if src == nil || dst == nil {
		return ""
	}
	srcHost, srcPort := splitHostPort(src)
	dstHost, dstPort := splitHostPort(dst)
	return communityIDFromParts(proto, srcHost, srcPort, dstHost, dstPort)
}

// attackerCommunityID builds the Community ID for the public-interface side of
// a connection: the attacker's address and port against the address they
// actually reached us on.
//
// Determining "the address they reached us on" differs by transport. An
// accepted TCP connection knows it exactly — LocalAddr is the receiving
// address even behind a 0.0.0.0 bind — so that is preferred whenever it is
// available and specific. UDP has no equivalent: the listeners bind wildcard
// and ReadFromUDP reports only the peer, so the destination has to come from
// PUBLIC_IP. With neither, the field is omitted.
func (c *connLogger) attackerCommunityID(r rule, srcHost string, srcPort int, dst net.Addr, listenPort int) string {
	if dst != nil {
		if dstHost, dstPort := splitHostPort(dst); dstPort != 0 {
			if ip := net.ParseIP(dstHost); ip != nil && !ip.IsUnspecified() {
				return communityIDFromParts(r.proto, srcHost, srcPort, dstHost, dstPort)
			}
		}
	}
	if c.publicIP != "" && listenPort != 0 {
		return communityIDFromParts(r.proto, srcHost, srcPort, c.publicIP, listenPort)
	}
	return ""
}

// communityIDFromParts hashes an already-split tuple. A wildcard local address
// (0.0.0.0 / ::) is rejected rather than hashed: portbridge's UDP listeners
// bind wildcard, so the datagram's true destination address is not recoverable
// from the socket, and hashing the wildcard would produce an ID no other
// sensor can ever match.
func communityIDFromParts(proto, srcHost string, srcPort int, dstHost string, dstPort int) string {
	srcIP, dstIP := net.ParseIP(srcHost), net.ParseIP(dstHost)
	if srcIP == nil || dstIP == nil || srcIP.IsUnspecified() || dstIP.IsUnspecified() {
		return ""
	}
	return communityID(protoNumber(proto), srcIP, srcPort, dstIP, dstPort)
}
