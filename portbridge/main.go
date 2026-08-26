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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// errOut stands in for os.Stderr so tests can capture diagnostics (#2240).
var errOut io.Writer = os.Stderr

type rule struct {
	proto      string
	listenPort string
	target     string // host:port
}

// defaultIdleTimeout bounds how long a forwarded TCP connection may sit with
// no data flowing in either direction before it's closed. Without this, an
// attacker opening a connection and sending nothing holds two fds and two
// goroutines open forever on the single process that fronts every forwarded
// port, and enough idle connections against one rule starve every other
// rule sharing this binary.
const defaultIdleTimeout = 5 * time.Minute

func idleTimeout() time.Duration {
	if v := os.Getenv("IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultIdleTimeout
}

// deadlineConn refreshes the connection's read/write deadline on every
// operation, so io.Copy stops (and the connection closes) once the peer has
// been silent for longer than timeout, instead of blocking indefinitely.
type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (d *deadlineConn) Read(p []byte) (int, error) {
	d.Conn.SetReadDeadline(time.Now().Add(d.timeout))
	return d.Conn.Read(p)
}

func (d *deadlineConn) Write(p []byte) (int, error) {
	d.Conn.SetWriteDeadline(time.Now().Add(d.timeout))
	return d.Conn.Write(p)
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
	acceptLoop(ln, addr, func(c net.Conn) { go pipeTCP(c, r.target, idleTimeout()) },
		acceptOptions{backoffMin: defaultAcceptBackoffMin, backoffMax: defaultAcceptBackoffMax})
}

// #2240 tuneables for the accept loop and UDP session table. The accept
// backoff starts small so a transient blip costs almost nothing, but caps at
// a value that keeps a persistently failing listener from spinning (the old
// bare `continue` pegged one core per affected rule while producing zero
// diagnostics -- most acute exactly when the process is already at its fd
// limit, which is when Accept fails every call). The session cap bounds the
// per-client socket table; the churn that needs it is slow by design
// (10 fresh ports/s against an open UDP rule), so even 512 buys hours of
// legitimate steady state before shedding ever engages.
const (
	defaultAcceptBackoffMin = 5 * time.Millisecond
	defaultAcceptBackoffMax = time.Second
	defaultUDPMaxSessions   = 512
	logThrottleInterval     = 10 * time.Second
)

type acceptOptions struct {
	backoffMin time.Duration
	backoffMax time.Duration
	// logEvery picks how often a persistent failure re-logs its progress;
	// 0 selects the default cadence. Exposed for tests.
	logEvery int
}

func acceptLoop(ln net.Listener, addr string, spawn func(net.Conn), opts acceptOptions) {
	backoff := opts.backoffMin
	failures := 0
	logEvery := opts.logEvery
	if logEvery == 0 {
		logEvery = 50
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			// A closed listener is the only clean way out -- anything else
			// gets backoff-and-retry, not bail-out (see below).
			if errors.Is(err, net.ErrClosed) {
				return
			}
			failures++
			// Never bail out of the loop entirely: exiting here would take
			// this rule's forwarding down until the whole process restarted,
			// which turns a transient EMFILE burst into a manual outage. A
			// capped backoff is "restart" semantics at negligible cost.
			if failures == 1 || failures%logEvery == 0 {
				fmt.Fprintf(errOut,
					"portbridge: tcp %s accept failed %d times in a row (still retrying): %v\n",
					addr, failures, err)
			}
			time.Sleep(backoff)
			backoff *= 2
			if backoff > opts.backoffMax {
				backoff = opts.backoffMax
			}
			continue
		}
		failures = 0
		backoff = opts.backoffMin
		spawn(c)
	}
}

// rateLimitedLog lets a pathological path (a full table shedding every fresh
// datagram, say) complain loudly without the complaining itself becoming a
// new CPU or stderr-flooding problem: at most one line per interval.
type rateLimitedLog struct {
	interval time.Duration
	mu       sync.Mutex
	last     time.Time
}

func (l *rateLimitedLog) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.last) >= l.interval {
		l.last = now
		return true
	}
	return false
}

func udpMaxSessions() int {
	if v := os.Getenv("UDP_MAX_SESSIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultUDPMaxSessions
}

func pipeTCP(client net.Conn, target string, idle time.Duration) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	dc := &deadlineConn{Conn: client, timeout: idle}
	du := &deadlineConn{Conn: up, timeout: idle}
	done := make(chan struct{}, 2)
	go func() { io.Copy(du, dc); done <- struct{}{} }()
	go func() { io.Copy(dc, du); done <- struct{}{} }()
	<-done
}

// udpReplyWindow is how long a per-client session sits idle before its
// return goroutine's read deadline evicts it -- unchanged from the original
// design; #2240 only adds a ceiling the forward path participates in, so a
// scanner cycling source ports cannot walk fd count to the wall faster than
// silence can expire sessions (which it previously could: a held session
// only needed one datagram per 30s window to live forever).
const udpReplyWindow = 30 * time.Second

type udpSession struct {
	up      *net.UDPConn
	lastUse time.Time // guarded by serveUDP's mu; consulted for LRU eviction
}

// udpForwarder is serveUDP's per-rule state: one front listener, the capped
// per-client session table, and the upstream target every session dials to.
type udpForwarder struct {
	label   string // listen addr, for log lines
	conn    *net.UDPConn
	target  *net.UDPAddr
	max     int
	shedLog *rateLimitedLog

	mu       sync.Mutex
	sessions map[string]*udpSession

	// now is injectable so tests can fast-forward session ages instead of
	// waiting out the real reply window.
	now func() time.Time
}

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
	f := &udpForwarder{
		label:    laddr.String(),
		conn:     conn,
		target:   target,
		max:      udpMaxSessions(),
		shedLog:  &rateLimitedLog{interval: logThrottleInterval},
		sessions: map[string]*udpSession{},
		now:      time.Now,
	}
	fmt.Fprintf(os.Stderr, "portbridge: udp %s -> %s (max %d sessions)\n",
		laddr, r.target, f.max)
	f.run()
}

func (f *udpForwarder) run() {
	buf := make([]byte, 64*1024)
	for {
		n, client, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		f.forward(client, buf[:n]) // forwarded or deliberately dropped (#2240)
	}
}

// forward routes one datagram, enforcing the session ceiling (#2240). Returns
// the number of bytes sent upstream -- dropped datagrams return 0.
func (f *udpForwarder) forward(client *net.UDPAddr, payload []byte) int {
	key := client.String()

	f.mu.Lock()

	// Enforce the ceiling before minting a new socket. First let genuinely-
	// expired sessions go (their reply goroutine is usually about to reap
	// them anyway); if the table is still full of flows seen inside the last
	// reply window, shed the NEW client rather than evicting established
	// ones -- replies must keep working for live flows, and a shed here is
	// exactly the signal that someone is cycling source ports.
	for len(f.sessions) >= f.max {
		victimKey, victimAge := f.oldestSessionLocked()
		if victimAge < udpReplyWindow {
			break
		}
		f.sessions[victimKey].up.Close()
		delete(f.sessions, victimKey)
		if f.shedLog.allow(f.now()) {
			fmt.Fprintf(errOut,
				"portbridge: udp %s evicted stale session %q (%ds idle, cap %d)\n",
				f.label, victimKey, int(victimAge.Seconds()), f.max)
		}
	}

	s, ok := f.sessions[key]
	if !ok && len(f.sessions) >= f.max {
		if f.shedLog.allow(f.now()) {
			fmt.Fprintf(errOut,
				"portbridge: udp %s session table full (%d), dropping datagram from fresh client %q -- if this repeats, something is cycling source ports\n",
				f.label, len(f.sessions), key)
		}
		f.mu.Unlock()
		return 0
	}
	if !ok {
		up, derr := net.DialUDP("udp", nil, f.target)
		if derr != nil {
			if f.shedLog.allow(f.now()) {
				fmt.Fprintf(errOut, "portbridge: udp %s dial upstream for %q failed: %v\n",
					f.label, key, derr)
			}
			f.mu.Unlock()
			return 0
		}
		s = &udpSession{up: up, lastUse: f.now()}
		f.sessions[key] = s
		// Return path: copy replies from target back to this client.
		go udpReplyLoop(f.conn, up, client, key, &f.mu, f.sessions)
	}
	s.lastUse = f.now()
	up := s.up
	f.mu.Unlock()

	// Deliberate fire-and-forget on the data write itself (#2240): a UDP
	// write fails transiently whenever the peer's socket queue is momentarily
	// full and that carries no operational meaning worth a log line; what
	// WOULD be meaningful (dial failures, cap pressure) logs above.
	up.Write(payload)
	return len(payload)
}

// oldestSessionLocked finds the least-recently-used entry and its age.
// Called with the mutex held; O(n) over a table capped at
// defaultUDPMaxSessions is cheap.
func (f *udpForwarder) oldestSessionLocked() (string, time.Duration) {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, s := range f.sessions {
		if first || s.lastUse.Before(oldest) {
			oldestKey, oldest, first = k, s.lastUse, false
		}
	}
	return oldestKey, f.now().Sub(oldest)
}

func udpReplyLoop(conn *net.UDPConn, up *net.UDPConn, client *net.UDPAddr,
	key string, mu *sync.Mutex, sessions map[string]*udpSession) {
	rbuf := make([]byte, 64*1024)
	for {
		up.SetReadDeadline(time.Now().Add(udpReplyWindow))
		rn, err := up.Read(rbuf)
		if err != nil {
			mu.Lock()
			// Only reap the session this loop actually owns: if the same
			// client tuple reconnected after eviction, sessions[key] now
			// points at a live replacement that must survive.
			if cur, ok := sessions[key]; ok && cur.up == up {
				delete(sessions, key)
			}
			mu.Unlock()
			up.Close()
			return
		}
		conn.WriteToUDP(rbuf[:rn], client)
	}
}
