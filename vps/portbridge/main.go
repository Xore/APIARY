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
// Each line carries via_port — the local port of the upstream socket, which is
// the src_port the honeypot sees — for UDP sessions as well as TCP. UDP has no
// PROXY-protocol equivalent, so that join is its only route to a real source.
//
// LISTEN_IP (default 0.0.0.0) is the interface to bind. On the VPS raw-tunnel
// side run with network_mode: host so it can reach the WireGuard peer; set
// LISTEN_IP=0.0.0.0 to expose publicly. On the home side set LISTEN_IP to the
// WireGuard IP (10.8.0.2) and target 127.0.0.1.
//
// BLACKHOLE_LIST (#268), if set, names a local file of known mass-scanner IPv4
// addresses (one per line, stamparm/maltrail's mass_scanner.txt format);
// portbridge closes a matching source's connection immediately instead of
// dialing the target, so it never reaches a honeypot listener, while Suricata
// (which sniffs the interface independently) still sees and logs it. See
// blackhole.go. Empty/unset disables the feature; nothing here ever fetches
// the list itself over the network — that's portbridge-blackhole-refresh.sh's
// job, gated behind the "blackhole" compose profile.
//
// BLACKHOLE_MANUAL_LIST (#914), if set, names a second such file for
// operator-triggered blocks made from the dashboard, unioned with
// BLACKHOLE_LIST above. Kept fresh by a separate sidecar,
// portbridge-manual-blackhole-refresh.sh — see blackhole.go's own doc
// comment for why this is two files, not one.
//
// Stdlib only; compiles to a tiny static binary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// errOut stands in for os.Stderr so tests can capture the resource-pressure
// diagnostics added in #2255. Pre-existing startup messages keep writing to
// os.Stderr directly; only the new lines need to be observable.
var errOut io.Writer = os.Stderr

// #2255 tuneables for the accept loop and the UDP session table, mirroring
// #2240's for the home-side portbridge. The accept backoff starts small so a
// transient blip costs almost nothing, but caps at a value that keeps a
// persistently failing listener from spinning (the old bare `continue`
// pegged one core per affected rule while producing zero diagnostics -- most
// acute exactly when the process is already at its fd limit, which is when
// Accept fails every call). The session cap bounds the per-client socket
// table; this binary fronts raw internet traffic on the VPS, so the
// source-port churn that needs it is not hypothetical.
const (
	defaultAcceptBackoffMin = 5 * time.Millisecond
	defaultAcceptBackoffMax = time.Second
	defaultUDPMaxSessions   = 512
	logThrottleInterval     = 10 * time.Second
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
	mu      sync.Mutex
	f       *os.File
	path    string
	size    int64
	max     int64
	p0fSock string // #241: empty disables the p0f query entirely
	// #1728: the VPS's own public address, used as the Community ID
	// destination when the socket cannot report it. TCP never needs this —
	// an accepted connection's LocalAddr is the real receiving address — but
	// the UDP listeners bind wildcard, so a datagram's true destination is
	// not recoverable from the socket alone. Empty simply omits the field
	// for UDP rather than hashing a wildcard nothing else could match.
	publicIP string
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
	c := &connLogger{
		f:        f,
		path:     path,
		max:      getenvInt64("LOG_MAX_BYTES", 67108864),
		p0fSock:  os.Getenv("P0F_API_SOCK"),
		publicIP: os.Getenv("PUBLIC_IP"),
	}
	if st, err := f.Stat(); err == nil {
		c.size = st.Size()
	}
	return c
}

// rotate closes the current file, renames it aside with a timestamp suffix,
// and reopens a fresh file at the original path -- same fix and same
// reasoning as #79's Suricata rotate-interval and #120's multipot/
// http-honeypot loggers: this file has no external rotation (it's shipped
// to the home stack over a read-only sshfs mount, so nothing on that side
// can rotate it either -- see #120's portbridge-log-maintenance service for
// pruning the renamed files), and Filebeat's inode-based file_identity
// keeps its harvester attached through the rename regardless. Callers must
// hold c.mu.
func (c *connLogger) rotate() {
	if c.f == nil || c.path == "" {
		return
	}
	c.f.Close()
	stamp := time.Now().UTC().Format("20060102-150405")
	os.Rename(c.path, c.path+"."+stamp)
	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		c.f = nil
		return
	}
	c.f = f
	c.size = 0
}

func getenvInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// log appends one JSON line per connection. via is portbridge's upstream local
// address — the port it dialed the honeypot FROM. That equals the src_port the
// honeypot observes over the tunnel (iptables DNAT preserves the source), so a
// honeypot that can only see the tunnel peer (cowrie: 10.8.0.1) can be joined
// back to the real src_ip recorded here via via_port. UDP has one such socket
// per client session, so it carries a via_port too; nil only if a caller has
// no upstream address to report.
// dst is the address the client actually reached us on — an accepted TCP
// connection's LocalAddr. It is nil for UDP, whose listeners bind wildcard and
// so cannot report which of our addresses a datagram was sent to; PUBLIC_IP
// fills that gap when configured. Only used to build the Community ID.
func (c *connLogger) log(r rule, src net.Addr, dst net.Addr, via net.Addr) {
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
	// #241: p0f sniffs the same public interface ahead of everything else on
	// the VPS, so host here is already the real attacker IP p0f fingerprinted
	// -- no port/session correlation needed, just ask it about this IP.
	// Best-effort: queryP0f never blocks noticeably or errors out to the
	// caller, so a down/undeployed p0f only ever costs a missing "os" field.
	if osGuess := queryP0f(c.p0fSock, host); osGuess != "" {
		rec["os"] = osGuess
	}
	if via != nil {
		if _, vp := splitHostPort(via); vp != 0 {
			rec["via_port"] = vp
		}
	}
	// #1728: the join key. community_id hashes the tuple as it appeared on the
	// public interface, so it equals the value Suricata stamped on the same
	// flow (and the one Zeek computes in-core) — the attacker-facing side is
	// the one worth joining, because it is the only place the real source IP
	// exists. community_id_relayed hashes the tunnel-side tuple instead, so
	// sensors on the homeserver, which only ever see the tunnel peer, can be
	// joined too. Both are omitted rather than approximated when the tuple
	// isn't fully known; see communityIDFromParts.
	if id := c.attackerCommunityID(r, host, port, dst, lport); id != "" {
		rec["community_id"] = id
	}
	if via != nil {
		viaHost, viaPort := splitHostPort(via)
		targetHost, targetPort, err := net.SplitHostPort(r.target)
		if err == nil {
			if tp, convErr := strconv.Atoi(targetPort); convErr == nil {
				if id := communityIDFromParts(r.proto, viaHost, viaPort, targetHost, tp); id != "" {
					rec["community_id_relayed"] = id
				}
			}
		}
	}
	line, _ := json.Marshal(rec)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max > 0 && c.size >= c.max {
		c.rotate()
	}
	if c.f == nil {
		return
	}
	n1, _ := c.f.Write(line)
	n2, _ := c.f.Write([]byte("\n"))
	c.size += int64(n1 + n2)
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
	bh := newBlackhole(os.Getenv("BLACKHOLE_LIST"), os.Getenv("BLACKHOLE_MANUAL_LIST"))

	var wg sync.WaitGroup
	for _, r := range rules {
		wg.Add(1)
		go func(r rule) {
			defer wg.Done()
			switch r.proto {
			case "tcp":
				serveTCP(listenIP, r, cl, bh)
			case "udp":
				if r.proxy {
					fmt.Fprintf(os.Stderr, "portbridge: PROXY protocol not supported for udp rule :%s — ignoring pp flag\n", r.listenPort)
				}
				serveUDP(listenIP, r, cl, bh)
			default:
				fmt.Fprintf(os.Stderr, "portbridge: unknown proto %q\n", r.proto)
			}
		}(r)
	}
	fmt.Fprintf(os.Stderr, "portbridge: %d rules, bind %s\n", len(rules), listenIP)
	wg.Wait()
}

func serveTCP(ip string, r rule, cl *connLogger, bh *blackhole) {
	addr := net.JoinHostPort(ip, r.listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: listen tcp %s: %v\n", addr, err)
		return
	}
	fmt.Fprintf(os.Stderr, "portbridge: tcp %s -> %s (proxy=%v)\n", addr, r.target, r.proxy)
	acceptLoop(ln, addr, func(c net.Conn) {
		// #268: the TCP handshake already completed by the time Accept returns
		// (Suricata, sniffing the interface independently, already saw it) —
		// closing here without dialing upstream still keeps the connection from
		// ever reaching the honeypot listener, which is the actual goal. No
		// connLogger entry either: a blackholed mass-scanner hit is exactly the
		// noise this feature exists to keep off the dashboard.
		if host, _ := splitHostPort(c.RemoteAddr()); bh.blocked(host) {
			c.Close()
			return
		}
		go pipeTCP(c, r, cl)
	}, acceptOptions{backoffMin: defaultAcceptBackoffMin, backoffMax: defaultAcceptBackoffMax})
}

type acceptOptions struct {
	backoffMin time.Duration
	backoffMax time.Duration
	// logEvery picks how often a persistent failure re-logs its progress;
	// 0 selects the default cadence. Exposed for tests.
	logEvery int
}

// acceptLoop runs a listener's accept loop, answering failures with a capped
// exponential backoff instead of the bare `continue` this file used to carry
// (#2255). spawn is handed each accepted connection.
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
			// which turns a transient EMFILE burst into a manual outage on a
			// host that is deliberately exposed to the internet. A capped
			// backoff is "restart" semantics at negligible cost.
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
	cl.log(r, client.RemoteAddr(), client.LocalAddr(), up.LocalAddr())
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

// udpReplyWindow is how long a per-client session may sit without hearing
// from upstream before its return goroutine's read deadline evicts it --
// unchanged from the original design (TFTP transfers and SNMP walks both
// need generous slack). #2255 only adds a ceiling the forward path
// participates in, so a scanner cycling source ports cannot walk fd count to
// the wall faster than silence can expire sessions -- which it previously
// could, since nothing but that deadline ever removed an entry.
const udpReplyWindow = 2 * time.Minute

type udpSession struct {
	conn *net.UDPConn
	mu   sync.RWMutex
	// target is the address replies were last seen from, so subsequent
	// client datagrams follow a TFTP server's freshly selected transfer-ID
	// port. Guarded by mu.
	target *net.UDPAddr
	// lastUse is the last time this session forwarded a client datagram.
	// Guarded by udpForwarder.mu; consulted for LRU eviction.
	lastUse time.Time
}

// udpForwarder is serveUDP's per-rule state: one front listener, the capped
// per-client session table, and everything the forward path needs to gate
// (blackhole), attribute (connLogger) and reach (target) a datagram.
type udpForwarder struct {
	label  string // listen addr, for log lines
	conn   *net.UDPConn
	rule   rule
	target *net.UDPAddr
	cl     *connLogger
	bh     *blackhole
	max    int

	// Two independent limiters: a shed storm must not starve write-failure
	// diagnostics of their slot, or vice versa.
	shedLog  *rateLimitedLog
	writeLog *rateLimitedLog

	mu       sync.Mutex
	sessions map[string]*udpSession

	// now is injectable so tests can fast-forward session ages instead of
	// waiting out the real reply window.
	now func() time.Time
}

// serveUDP forwards datagrams with a per-client session table, capped since
// #2255 so replies find their way back without the table growing unbounded.
func serveUDP(ip string, r rule, cl *connLogger, bh *blackhole) {
	listenNetwork := "udp4"
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		listenNetwork = "udp6"
	}
	laddr, err := net.ResolveUDPAddr(listenNetwork, net.JoinHostPort(ip, r.listenPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: resolve udp: %v\n", err)
		return
	}
	// SO_REUSEADDR: a wildcard 0.0.0.0 bind otherwise conflicts with any
	// existing more-specific bind on the same port (e.g. systemd-resolved's
	// stub listener on 127.0.0.53/127.0.0.54:53 -- confirmed live on the
	// VPS: bind(0.0.0.0:53) failed with EADDRINUSE despite nothing showing
	// up on 0.0.0.0:53 itself in `ss`, and setting this option is what
	// actually fixed it, tested directly before applying here). Harmless
	// for every other rule, which never had a competing bind to begin with.
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return setErr
	}}
	pc, err := lc.ListenPacket(context.Background(), listenNetwork, laddr.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: listen udp %s: %v\n", laddr, err)
		return
	}
	conn := pc.(*net.UDPConn)
	target, err := net.ResolveUDPAddr("udp", r.target)
	if err != nil {
		return
	}
	f := &udpForwarder{
		label:    laddr.String(),
		conn:     conn,
		rule:     r,
		target:   target,
		cl:       cl,
		bh:       bh,
		max:      udpMaxSessions(),
		shedLog:  &rateLimitedLog{interval: logThrottleInterval},
		writeLog: &rateLimitedLog{interval: logThrottleInterval},
		sessions: map[string]*udpSession{},
		now:      time.Now,
	}
	fmt.Fprintf(os.Stderr, "portbridge: udp %s -> %s (max %d sessions)\n", laddr, r.target, f.max)
	f.run()
}

func (f *udpForwarder) run() {
	buf := make([]byte, 64*1024)
	for {
		n, client, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		f.forward(client, buf[:n]) // forwarded, gated or deliberately shed (#2255)
	}
}

// forward routes one client datagram, enforcing the session ceiling (#2255).
// Returns the number of bytes actually sent upstream -- blackholed, shed and
// failed datagrams return 0.
func (f *udpForwarder) forward(client *net.UDPAddr, payload []byte) int {
	key := client.String()

	f.mu.Lock()
	s, ok := f.sessions[key]
	if !ok {
		// #268: only gate new sessions, same reasoning as serveTCP's
		// Accept-time check -- a session already forwarding isn't worth
		// tearing down mid-stream. Checked before the cap is enforced, so a
		// blackholed scanner can never evict a legitimate session on its way
		// to being dropped.
		if host, _ := splitHostPort(client); f.bh.blocked(host) {
			f.mu.Unlock()
			return 0
		}
		if !f.admitLocked(key) {
			f.mu.Unlock()
			return 0
		}
		network := "udp4"
		bind := &net.UDPAddr{IP: net.IPv4zero}
		if f.target.IP.To4() == nil {
			network = "udp6"
			bind.IP = net.IPv6zero
		}
		up, listenErr := net.ListenUDP(network, bind)
		if listenErr != nil {
			if f.shedLog.allow(f.now()) {
				fmt.Fprintf(errOut, "portbridge: udp %s session socket for %q failed: %v\n",
					f.label, key, listenErr)
			}
			f.mu.Unlock()
			return 0
		}
		s = &udpSession{conn: up, target: f.target, lastUse: f.now()}
		f.sessions[key] = s
		// Log once per new client session. The per-session socket is bound
		// before the first datagram leaves, so its local port is already
		// assigned — and it is the src_port the honeypot sees for every
		// datagram of this session, exactly like the TCP via_port. Without
		// it the UDP sensors (conpot SNMP/BACnet/IPMI, dionaea tftp/upnp/
		// sip) have no recovery path at all: conpot's PROXY shim is TCP-only
		// by construction, so nothing else can carry the real source across
		// the tunnel. See issue #75.
		// nil destination: this socket is wildcard-bound, so the address
		// the datagram was actually sent to is not recoverable here.
		// PUBLIC_IP supplies it when set (#1728).
		f.cl.log(f.rule, client, nil, up.LocalAddr())
		// Return path accepts a reply from any port on the target host. This is
		// required by TFTP, whose server selects a new transfer-ID port after
		// the request; subsequent client datagrams follow that selected port.
		go f.replyLoop(s, client, key)
	}
	s.lastUse = f.now()
	f.mu.Unlock()

	s.mu.RLock()
	upstream := s.target
	s.mu.RUnlock()
	if _, err := s.conn.WriteToUDP(payload, upstream); err != nil {
		// Rate-limited (#2255): the pre-existing unthrottled line turned a
		// persistently unreachable target into its own stderr flood, which
		// is the same failure class this issue is about.
		if f.writeLog.allow(f.now()) {
			fmt.Fprintf(errOut, "portbridge: udp write %s: %v\n", upstream, err)
		}
		return 0
	}
	return len(payload)
}

// admitLocked makes room for one new session, or reports that there is none.
// Called with f.mu held, only on the new-session path -- an established
// client's datagrams cost no scan.
//
// Genuinely expired sessions go first, LRU-first (their reply goroutine is
// usually about to reap them anyway). If the table is still full of flows
// seen inside the reply window, the NEW client is shed rather than an
// established one evicted: replies must keep working for live flows, and a
// shed here is exactly the signal that someone is cycling source ports.
func (f *udpForwarder) admitLocked(key string) bool {
	for len(f.sessions) >= f.max {
		victimKey, victimAge := f.oldestSessionLocked()
		if victimAge < udpReplyWindow {
			break
		}
		f.sessions[victimKey].conn.Close()
		delete(f.sessions, victimKey)
		if f.shedLog.allow(f.now()) {
			fmt.Fprintf(errOut,
				"portbridge: udp %s evicted stale session %q (%ds idle, cap %d)\n",
				f.label, victimKey, int(victimAge.Seconds()), f.max)
		}
	}
	if len(f.sessions) >= f.max {
		if f.shedLog.allow(f.now()) {
			fmt.Fprintf(errOut,
				"portbridge: udp %s session table full (%d), dropping datagram from fresh client %q -- if this repeats, something is cycling source ports\n",
				f.label, len(f.sessions), key)
		}
		return false
	}
	return true
}

// oldestSessionLocked finds the least-recently-used entry and its age.
// Called with f.mu held; O(n) over a table capped at defaultUDPMaxSessions is
// cheap, and only paid when a new session is being admitted.
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

func (f *udpForwarder) replyLoop(s *udpSession, client *net.UDPAddr, key string) {
	rbuf := make([]byte, 64*1024)
	for {
		s.conn.SetReadDeadline(time.Now().Add(udpReplyWindow))
		rn, from, err := s.conn.ReadFromUDP(rbuf)
		if err != nil {
			f.mu.Lock()
			// Only reap the session this loop actually owns: if the same
			// client tuple reconnected after eviction, f.sessions[key] now
			// points at a live replacement that must survive (#2255).
			if cur, ok := f.sessions[key]; ok && cur == s {
				delete(f.sessions, key)
			}
			f.mu.Unlock()
			s.conn.Close()
			return
		}
		s.mu.Lock()
		s.target = from
		s.mu.Unlock()
		f.conn.WriteToUDP(rbuf[:rn], client)
	}
}
