package main

// PROXY-protocol decoding. When this honeypot sits behind portbridge (which
// terminates the attacker's TCP connection on the VPS and re-dials over
// WireGuard), every connection would otherwise appear to come from the tunnel
// peer 10.8.0.1. If portbridge prepends a HAProxy PROXY header (rule flag
// ":pp") we wrap each accepted connection so its first Read or RemoteAddr
// call strips the header and rewrites the connection's RemoteAddr to the
// real attacker address. (#2099: the decode itself must never run on the
// shared accept-loop goroutine.)
//
// Both v1 (text) and v2 (binary) headers are accepted; portbridge emits v1.
// Enabled by PROXY_PROTOCOL=1 (see main). Stdlib only.
// Mirrors http-honeypot/proxyproto.go — keep the two in sync.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n") // 12-byte v2 signature

// proxyListener wraps each accepted connection so a PROXY header, if
// present, is decoded before the connection handler reads from it -- but
// not here in Accept(). main's own loop calls l.Accept() one connection at
// a time and only spawns the per-connection serve() goroutine after
// Accept() returns; decoding the PROXY header synchronously inside Accept()
// (the previous behavior) blocked that shared loop for up to the decode's
// own 5s deadline on every connection, including a slow/silent one -- a
// trivial, near-zero-bandwidth DoS against the whole listener (#1346 fixed
// this in cisco-asa; #2099 ports it here).
type proxyListener struct{ net.Listener }

func (l *proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &proxyConn{Conn: c, r: bufio.NewReader(c)}, nil
}

// proxyConn decodes the PROXY header (once, via sync.Once) on first use --
// triggered by either Read or RemoteAddr, whichever the handler calls
// first. It must be resolved by the time RemoteAddr() returns -- not
// deferred past it the way a lazy-Read-only peek would be -- or remote
// logging would report the tunnel peer address instead of the real
// attacker IP for the connection's entire lifetime. Either trigger point
// still runs in the per-connection serve() goroutine (spawned after
// Accept() returns), never the shared accept loop.
type proxyConn struct {
	net.Conn
	r      *bufio.Reader
	once   sync.Once
	remote net.Addr
}

func (p *proxyConn) decode() {
	p.once.Do(func() {
		p.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		p.remote = parseProxy(p.r)
		p.Conn.SetReadDeadline(time.Time{}) // clear; serve() sets its own deadline
	})
}

func (p *proxyConn) Read(b []byte) (int, error) {
	p.decode()
	return p.r.Read(b)
}

func (p *proxyConn) RemoteAddr() net.Addr {
	p.decode()
	if p.remote != nil {
		return p.remote
	}
	return p.Conn.RemoteAddr()
}

// parseProxy peeks for a v1 or v2 header, consumes it if found, and returns the
// parsed source address (nil if absent or malformed).
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
