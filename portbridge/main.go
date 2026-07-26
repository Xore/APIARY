// portbridge — forward many TCP/UDP ports in a single container.
//
// It replaces a pile of one-per-port `socat` services. Rules are read from the
// RULES env var (one per line or space/comma separated):
//
//	proto:listenPort:targetHost:targetPort
//
// e.g.  RULES="tcp:22:10.8.0.2:22 tcp:3306:10.8.0.2:3306 udp:161:10.8.0.2:161"
//
// LISTEN_IP (default 0.0.0.0) is the interface to bind. On the VPS raw-tunnel
// side run with network_mode: host so it can reach the WireGuard peer; set
// LISTEN_IP=0.0.0.0 to expose publicly. On the home side set LISTEN_IP to the
// WireGuard IP (10.8.0.2) and target 127.0.0.1.
//
// Stdlib only; compiles to a tiny static binary.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type rule struct {
	proto      string
	listenPort string
	target     string // host:port
}

func parseRules(raw string) []rule {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == ',' || r == '\r'
	})
	var out []rule
	for _, f := range fields {
		p := strings.Split(f, ":")
		if len(p) != 4 {
			fmt.Fprintf(os.Stderr, "portbridge: skipping bad rule %q (want proto:lport:thost:tport)\n", f)
			continue
		}
		out = append(out, rule{proto: strings.ToLower(p[0]), listenPort: p[1], target: p[2] + ":" + p[3]})
	}
	return out
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	listenIP := getenv("LISTEN_IP", "0.0.0.0")
	rules := parseRules(os.Getenv("RULES"))
	if len(rules) == 0 {
		fmt.Fprintln(os.Stderr, "portbridge: no RULES given")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for _, r := range rules {
		wg.Add(1)
		go func(r rule) {
			defer wg.Done()
			switch r.proto {
			case "tcp":
				serveTCP(listenIP, r)
			case "udp":
				serveUDP(listenIP, r)
			default:
				fmt.Fprintf(os.Stderr, "portbridge: unknown proto %q\n", r.proto)
			}
		}(r)
	}
	fmt.Fprintf(os.Stderr, "portbridge: %d rules, bind %s\n", len(rules), listenIP)
	wg.Wait()
}

func serveTCP(ip string, r rule) {
	addr := net.JoinHostPort(ip, r.listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: listen tcp %s: %v\n", addr, err)
		return
	}
	fmt.Fprintf(os.Stderr, "portbridge: tcp %s -> %s\n", addr, r.target)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go pipeTCP(c, r.target)
	}
}

func pipeTCP(client net.Conn, target string) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, client); done <- struct{}{} }()
	go func() { io.Copy(client, up); done <- struct{}{} }()
	<-done
}

// serveUDP forwards datagrams with a small per-client session table so replies
// find their way back.
func serveUDP(ip string, r rule) {
	laddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, r.listenPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: resolve udp: %v\n", err)
		return
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: listen udp %s: %v\n", laddr, err)
		return
	}
	target, err := net.ResolveUDPAddr("udp", r.target)
	if err != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "portbridge: udp %s -> %s\n", laddr, r.target)

	var mu sync.Mutex
	sessions := map[string]*net.UDPConn{}
	buf := make([]byte, 64*1024)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		key := client.String()
		mu.Lock()
		up, ok := sessions[key]
		if !ok {
			up, err = net.DialUDP("udp", nil, target)
			if err != nil {
				mu.Unlock()
				continue
			}
			sessions[key] = up
			// Return path: copy replies from target back to this client.
			go func(up *net.UDPConn, client *net.UDPAddr, key string) {
				rbuf := make([]byte, 64*1024)
				for {
					up.SetReadDeadline(time.Now().Add(30 * time.Second))
					rn, err := up.Read(rbuf)
					if err != nil {
						mu.Lock()
						delete(sessions, key)
						mu.Unlock()
						up.Close()
						return
					}
					conn.WriteToUDP(rbuf[:rn], client)
				}
			}(up, client, key)
		}
		mu.Unlock()
		up.Write(buf[:n])
	}
}
