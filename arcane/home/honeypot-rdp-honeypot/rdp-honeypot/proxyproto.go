package main

// PROXY-protocol decoding. When this honeypot sits behind portbridge (which
// terminates the attacker's TCP connection on the VPS and re-dials over
// WireGuard), every connection would otherwise appear to come from the tunnel
// peer 10.8.0.1. If portbridge is told to prepend a HAProxy PROXY header
// (rule flag ":pp") we parse it here and rewrite the connection's RemoteAddr
// to the real attacker address, so every logged event carries the true IP.
//
// Both v1 (text) and v2 (binary) headers are accepted; portbridge emits v1.
// Enabled by PROXY_PROTOCOL=1 (see main). Stdlib only.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n") // 12-byte v2 signature

// proxyConn wraps a net.Conn whose PROXY header has been consumed, buffering
// the bytes read past the header and reporting the real remote address.
type proxyConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (p *proxyConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p *proxyConn) RemoteAddr() net.Addr {
	if p.remote != nil {
		return p.remote
	}
	return p.Conn.RemoteAddr()
}

// decodeProxy consumes a PROXY header if one is present and returns a conn that
// reports the real client address. If enabled is false, or no header is found,
// the original conn is returned unchanged. A short read deadline guards against
// a client that connects but never sends the promised header.
func decodeProxy(c net.Conn, enabled bool) net.Conn {
	if !enabled {
		return c
	}
	r := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	remote := parseProxy(r)
	c.SetReadDeadline(time.Time{}) // clear; handlers set their own deadlines
	return &proxyConn{Conn: c, r: r, remote: remote}
}

// parseProxy peeks for a v1 or v2 header, consumes it if found, and returns the
// parsed source address (nil if absent or malformed — the caller then falls
// back to the transport address).
func parseProxy(r *bufio.Reader) net.Addr {
	if sig, err := r.Peek(12); err == nil && bytes.Equal(sig, proxyV2Sig) {
		return parseProxyV2(r)
	}
	if head, err := r.Peek(5); err == nil && string(head) == "PROXY" {
		return parseProxyV1(r)
	}
	return nil
}

// parseProxyV1 reads "PROXY TCP4 <src> <dst> <sport> <dport>\r\n".
func parseProxyV1(r *bufio.Reader) net.Addr {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil
	}
	f := strings.Fields(strings.TrimRight(line, "\r\n"))
	// f[0]=PROXY f[1]=TCP4/TCP6/UNKNOWN f[2]=src f[3]=dst f[4]=sport f[5]=dport
	if len(f) < 6 || f[1] == "UNKNOWN" {
		return nil
	}
	port, _ := strconv.Atoi(f[4])
	ip := net.ParseIP(f[2])
	if ip == nil {
		return nil
	}
	return &net.TCPAddr{IP: ip, Port: port}
}

// parseProxyV2 reads the 16-byte header + address block.
func parseProxyV2(r *bufio.Reader) net.Addr {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil
	}
	verCmd := hdr[12]
	fam := hdr[13]
	length := int(binary.BigEndian.Uint16(hdr[14:16]))
	addr := make([]byte, length)
	if _, err := io.ReadFull(r, addr); err != nil {
		return nil
	}
	// verCmd high nibble must be 2 (version); low nibble 1 = PROXY, 0 = LOCAL
	if verCmd>>4 != 2 || verCmd&0x0f != 1 {
		return nil // LOCAL / unknown — no real address to recover
	}
	switch fam >> 4 { // high nibble = address family
	case 0x1: // AF_INET
		if len(addr) < 12 {
			return nil
		}
		return &net.TCPAddr{IP: net.IP(addr[0:4]), Port: int(binary.BigEndian.Uint16(addr[8:10]))}
	case 0x2: // AF_INET6
		if len(addr) < 36 {
			return nil
		}
		return &net.TCPAddr{IP: net.IP(addr[0:16]), Port: int(binary.BigEndian.Uint16(addr[32:34]))}
	}
	return nil
}
