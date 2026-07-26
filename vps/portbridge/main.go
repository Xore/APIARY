// portbridge — forward many TCP/UDP ports in a single container.
//
// It replaces a pile of one-per-port `socat` services. Rules are read from the
// RULES env var (one per line or space/comma separated):
//
//	proto:listenPort:targetHost:targetPort[:pp]
//
// e.g.  RULES="tcp:22:10.8.0.2:19022:pp tcp:3306:10.8.0.2:3306 udp:161:10.8.0.2:19161"
//
// The optional trailing ":pp" (or ":proxy") makes portbridge prepend a
// HAProxy PROXY-protocol v1 header to the upstream connection, so the honeypot
// behind the WireGuard tunnel sees the REAL attacker IP instead of the tunnel
// peer (10.8.0.1). Only enable it for targets that understand PROXY protocol
// (cowrie via a haproxy: endpoint, and the multipot / http-honeypot sensors
// with PROXY_PROTOCOL=1). Sensors that don't parse it (dionaea, conpot) must
// be left without the flag — they'd choke on the header bytes.
//
// Regardless of the flag, if CONN_LOG names a file portbridge appends one JSON
// line per accepted connection with the real source IP, so even the
// PROXY-unaware ports get attributed once the log is surfaced to the dashboard.
//
// LISTEN_IP (default 0.0.0.0) is the interface to bind. On the VPS raw-tunnel
// side run with network_mode: host so it can reach the WireGuard peer; set
// LISTEN_IP=0.0.0.0 to expose publicly. On the home side set LISTEN_IP to the
// WireGuard IP (10.8.0.2) and target 127.0.0.1.
//
// Stdlib only; compiles to a tiny static binary.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rule struct {
	proto      string
	listenPort string
	target     string // host:port
	proxy      bool   // prepend a PROXY-protocol v1 header to the upstream
}

func parseRules(raw string) []rule {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == ',' || r == '\r'
	})
	var out []rule
	for _, f := range fields {
		p := strings.Split(f, ":")
		var proxy bool
		// optional trailing pp/proxy flag → a 5th colon-field
		if len(p) == 5 && (p[4] == "pp" || p[4] == "proxy") {
			proxy = true
			p = p[:4]
		}
		if len(p) != 4 {
			fmt.Fprintf(os.Stderr, "portbridge: skipping bad rule %q (want proto:lport:thost:tport[:pp])\n", f)
			continue
		}
		out = append(out, rule{proto: strings.ToLower(p[0]), listenPort: p[1], target: p[2] + ":" + p[3], proxy: proxy})
	}
	return out
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// connLogger appends one JSON line per connection so the dashboard can attribute
// the real attacker IP to every port — including PROXY-unaware ones. nil / no
// file means connection logging is disabled.
type connLogger struct {
	mu sync.Mutex
	f  *os.File
}

func newConnLogger(path string) *connLogger {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: CONN_LOG %s: %v (connection logging off)\n", path, err)
		return nil
	}
	return &connLogger{f: f}
}

// log appends one JSON line per connection. via is portbridge's upstream local
// address — the port it dialed the honeypot FROM. For TCP that equals the
// src_port the honeypot observes over the tunnel (iptables DNAT preserves the
// source), so a honeypot that can only see the tunnel peer (cowrie: 10.8.0.1)
// can be joined back to the real src_ip recorded here via via_port. nil for UDP.
func (c *connLogger) log(r rule, src net.Addr, via net.Addr) {
	if c == nil || c.f == nil {
		return
	}
	host, port := splitHostPort(src)
	lport, _ := strconv.Atoi(r.listenPort)
	rec := map[string]any{
		"time":     time.Now().UTC().Format(time.RFC3339),
		"sensor":   "portbridge",
		"event":    "connect",
		"proto":    r.proto,
		"port":     lport,
		"src_ip":   host,
		"src_port": port,
		"target":   r.target,
	}
	if via != nil {
		if _, vp := splitHostPort(via); vp != 0 {
			rec["via_port"] = vp
		}
	}
	line, _ := json.Marshal(rec)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.f.Write(line)
	c.f.Write([]byte("\n"))
}

func splitHostPort(a net.Addr) (string, int) {
	h, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	port, _ := strconv.Atoi(p)
	return h, port
}

func main() {
	listenIP := getenv("LISTEN_IP", "0.0.0.0")
	rules := parseRules(os.Getenv("RULES"))
	if len(rules) == 0 {
		fmt.Fprintln(os.Stderr, "portbridge: no RULES given")
		os.Exit(1)
	}
	cl := newConnLogger(os.Getenv("CONN_LOG"))

	var wg sync.WaitGroup
	for _, r := range rules {
		wg.Add(1)
		go func(r rule) {
			defer wg.Done()
			switch r.proto {
			case "tcp":
				serveTCP(listenIP, r, cl)
			case "udp":
				if r.proxy {
					fmt.Fprintf(os.Stderr, "portbridge: PROXY protocol not supported for udp rule :%s — ignoring pp flag\n", r.listenPort)
				}
				serveUDP(listenIP, r, cl)
			default:
				fmt.Fprintf(os.Stderr, "portbridge: unknown proto %q\n", r.proto)
			}
		}(r)
	}
	fmt.Fprintf(os.Stderr, "portbridge: %d rules, bind %s\n", len(rules), listenIP)
	wg.Wait()
}

func serveTCP(ip string, r rule, cl *connLogger) {
	addr := net.JoinHostPort(ip, r.listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: listen tcp %s: %v\n", addr, err)
		return
	}
	fmt.Fprintf(os.Stderr, "portbridge: tcp %s -> %s (proxy=%v)\n", addr, r.target, r.proxy)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go pipeTCP(c, r, cl)
	}
}

func pipeTCP(client net.Conn, r rule, cl *connLogger) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", r.target, 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	// Log after dialing so we can record the upstream local port (via_port).
	// It equals the src_port the honeypot sees over the tunnel, letting the
	// dashboard join cowrie's tunnel-peer sessions back to the real attacker IP.
	cl.log(r, client.RemoteAddr(), up.LocalAddr())
	// The PROXY header must be the very first bytes the upstream reads.
	if r.proxy {
		if hdr := proxyV1Header(client); hdr != "" {
			if _, err := up.Write([]byte(hdr)); err != nil {
				return
			}
		}
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, client); done <- struct{}{} }()
	go func() { io.Copy(client, up); done <- struct{}{} }()
	<-done
}

// proxyV1Header builds a HAProxy PROXY-protocol v1 header line describing the
// real client → original-destination addresses of an accepted connection.
// Format:  "PROXY TCP4 <src> <dst> <sport> <dport>\r\n"  (spec: haproxy.org).
// Returns "PROXY UNKNOWN\r\n" if the addresses can't be represented, which
// receivers must accept and ignore.
func proxyV1Header(client net.Conn) string {
	src, ok1 := client.RemoteAddr().(*net.TCPAddr)
	dst, ok2 := client.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 || src.IP == nil || dst.IP == nil {
		return "PROXY UNKNOWN\r\n"
	}
	s4, d4 := src.IP.To4(), dst.IP.To4()
	if s4 != nil && d4 != nil {
		return fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", s4, d4, src.Port, dst.Port)
	}
	if s4 == nil && d4 == nil {
		return fmt.Sprintf("PROXY TCP6 %s %s %d %d\r\n", src.IP, dst.IP, src.Port, dst.Port)
	}
	// mixed families shouldn't happen on one connection; play it safe
	return "PROXY UNKNOWN\r\n"
}

// serveUDP forwards datagrams with a small per-client session table so replies
// find their way back.
func serveUDP(ip string, r rule, cl *connLogger) {
	listenNetwork := "udp4"
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		listenNetwork = "udp6"
	}
	laddr, err := net.ResolveUDPAddr(listenNetwork, net.JoinHostPort(ip, r.listenPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: resolve udp: %v\n", err)
		return
	}
	conn, err := net.ListenUDP(listenNetwork, laddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: listen udp %s: %v\n", laddr, err)
		return
	}
	target, err := net.ResolveUDPAddr("udp", r.target)
	if err != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "portbridge: udp %s -> %s\n", laddr, r.target)

	type udpSession struct {
		conn   *net.UDPConn
		mu     sync.RWMutex
		target *net.UDPAddr
	}
	var mu sync.Mutex
	sessions := map[string]*udpSession{}
	buf := make([]byte, 64*1024)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		key := client.String()
		mu.Lock()
		session, ok := sessions[key]
		if !ok {
			network := "udp4"
			bind := &net.UDPAddr{IP: net.IPv4zero}
			if target.IP.To4() == nil {
				network = "udp6"
				bind.IP = net.IPv6zero
			}
			up, listenErr := net.ListenUDP(network, bind)
			if listenErr != nil {
				mu.Unlock()
				continue
			}
			session = &udpSession{conn: up, target: target}
			sessions[key] = session
			cl.log(r, client, nil) // log once per new client session (UDP: no via_port)
			// Return path accepts a reply from any port on the target host. This is
			// required by TFTP, whose server selects a new transfer-ID port after
			// the request; subsequent client datagrams follow that selected port.
			go func(session *udpSession, client *net.UDPAddr, key string) {
				rbuf := make([]byte, 64*1024)
				for {
					session.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
					rn, from, err := session.conn.ReadFromUDP(rbuf)
					if err != nil {
						mu.Lock()
						delete(sessions, key)
						mu.Unlock()
						session.conn.Close()
						return
					}
					session.mu.Lock()
					session.target = from
					session.mu.Unlock()
					conn.WriteToUDP(rbuf[:rn], client)
				}
			}(session, client, key)
		}
		mu.Unlock()
		session.mu.RLock()
		upstream := session.target
		session.mu.RUnlock()
		if _, err := session.conn.WriteToUDP(buf[:n], upstream); err != nil {
			fmt.Fprintf(os.Stderr, "portbridge: udp write %s: %v\n", upstream, err)
		}
	}
}
