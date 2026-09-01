// cisco-asa-honeypot — Go port of t3chn0m4g3/ciscoasa_honeypot (#238, #414):
// a Cisco ASA WebVPN decoy for CVE-2018-0101, matching T-Pot's own
// two-port exposure (8443/tcp WebVPN + 500/udp IKE) exactly. See webvpn.go
// for the HTTP side and ike.go for why the IKE side is scoped the way it
// is -- both confirmed directly against upstream's actual source, not
// just the issue's line-count summary, before porting.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// healthcheckNoiseFilter drops the one specific log line the -healthcheck
// flag's raw connect-and-close self-probe generates every cycle (#725):
// net/http logs "http: TLS handshake error from 127.0.0.1:<port>: EOF" for
// any TLS listener whose peer closes before sending ClientHello, which is
// exactly what the loopback healthcheck does. That's 100% self-inflicted --
// never a real client -- but at the log-message level it's indistinguishable
// from a genuine malformed-TLS-client attempt, permanently drowning real
// errors in this stream. Everything else still reaches stderr unfiltered.
type healthcheckNoiseFilter struct{}

func (healthcheckNoiseFilter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if strings.Contains(msg, "TLS handshake error from 127.0.0.1:") && strings.HasSuffix(msg, "EOF") {
		return len(p), nil
	}
	return os.Stderr.Write(p)
}

type event struct {
	Time      string            `json:"time"`
	Sensor    string            `json:"sensor"`
	Persona   string            `json:"persona_id"`
	Site      string            `json:"site_id"`
	Asset     string            `json:"asset_id"`
	Org       string            `json:"organization"`
	Proto     string            `json:"proto"`
	Port      int               `json:"port"`
	SrcIP     string            `json:"src_ip"`
	SrcPort   int               `json:"src_port"`
	Event     string            `json:"event"`
	Path      string            `json:"path,omitempty"`
	Data      string            `json:"data,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

type logger struct {
	mu   sync.Mutex
	out  *os.File
	path string
	size int64
	max  int64
}

func newLogger(path string) *logger {
	l := &logger{path: path, max: getenvInt64("LOG_MAX_BYTES", 67108864)}
	if path == "" {
		return l
	}
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
		l.out = f
		if st, err := f.Stat(); err == nil {
			l.size = st.Size()
		}
	} else {
		stdlog.Printf("cisco-asa-honeypot: log file %q unavailable, continuing with stdout only: %v", path, err)
	}
	return l
}

// rotate closes the current file, renames it aside with a timestamp suffix,
// and reopens a fresh file at the original path -- #120's contract, ported
// from multipot's logger (see that package's rotate() for the full
// reasoning). Callers must hold l.mu.
func (l *logger) rotate() {
	if l.out == nil || l.path == "" {
		return
	}
	l.out.Close()
	target := l.path + "." + time.Now().UTC().Format("20060102-150405")
	if _, err := os.Stat(target); err == nil {
		for n := 2; ; n++ {
			candidate := fmt.Sprintf("%s.%d", target, n)
			if _, err := os.Stat(candidate); err != nil {
				target = candidate
				break
			}
		}
	}
	os.Rename(l.path, target)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		l.out = nil
		stdlog.Printf("cisco-asa-honeypot: log file %q unavailable after rotation, continuing with stdout only: %v", l.path, err)
		return
	}
	l.out = f
	l.size = 0
}

func (l *logger) emit(e event) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.Sensor = "cisco-asa-honeypot"
	e.Persona = "nexusai-asa-vpn"
	e.Site = "nexusai-eu-edge"
	e.Asset = "asagw01"
	e.Org = "NexusAI Research GmbH"
	// This sensor covers two distinct protocols on two ports; every event
	// kind is prefixed "ike_" for the UDP side, so that alone is enough to
	// pick the right proto without threading it through every call site.
	if strings.HasPrefix(e.Event, "ike_") {
		e.Proto = "ike"
	} else {
		e.Proto = "https"
	}
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	os.Stdout.Write(line)
	os.Stdout.Write([]byte("\n"))
	if l.out != nil {
		if l.max > 0 && l.size >= l.max {
			l.rotate()
		}
		if l.out != nil {
			n1, _ := l.out.Write(line)
			n2, _ := l.out.Write([]byte("\n"))
			l.size += int64(n1 + n2)
		}
	}
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func getenvInt64(k string, def int64) int64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// waitForMarker blocks until markerPath exists, polling every 3s. See #128.
func waitForMarker(markerPath string) {
	for {
		if _, err := os.Stat(markerPath); err == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

// ikeState tracks, per source address, whether this session has already
// received its one bogus IKE_SA_INIT reply. See ike.go's package doc
// comment for exactly why there is only ever one.
type ikeState int

const (
	ikeStarting ikeState = iota
	ikeReplied
)

// ikeSession pairs a session's state with when it was created. A one-shot
// scanner (masscan-style, one datagram per source port) only ever sends the
// IKE_SA_INIT that moves a session to ikeReplied -- it never sends the
// second datagram that would delete it -- so without a bound, sessions left
// this way accumulate forever (#2324). seen backs the cap-and-evict below.
type ikeSession struct {
	state ikeState
	seen  time.Time
}

func runIKEResponder(addr string, log *logger, port int, maxSessions int) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}
	log.emit(event{Port: port, Event: "ike_listening"})

	var mu sync.Mutex
	sessions := map[string]ikeSession{}

	buf := make([]byte, 4096)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go handleIKEPacket(conn, raddr, data, log, port, &mu, sessions, maxSessions)
	}
}

// evictOldestIKESessionLocked drops the least-recently-created session to
// make room for a new one once the map is at maxSessions. Caller must hold
// mu. Unlike a plain drop-when-full cap, this never permanently stops the
// honeypot from replying to (and logging) newly seen sources once the cap
// is first reached -- it just ages out the oldest scanner residue instead,
// mirroring tftp-relay's TFTP_MAX_SESSIONS admission control (#1960) while
// still bounding the map the way an idle-timeout sweep would.
func evictOldestIKESessionLocked(sessions map[string]ikeSession) {
	var oldestKey string
	var oldestSeen time.Time
	found := false
	for k, v := range sessions {
		if !found || v.seen.Before(oldestSeen) {
			oldestKey, oldestSeen, found = k, v.seen, true
		}
	}
	if found {
		delete(sessions, oldestKey)
	}
}

func handleIKEPacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte, log *logger, port int, mu *sync.Mutex, sessions map[string]ikeSession, maxSessions int) {
	key := addr.String()
	exchangeType, ok := parseIKEHeader(data)

	mu.Lock()
	state := sessions[key].state
	mu.Unlock()

	if !ok {
		// #619: length of what actually arrived is real signal too --
		// packets this short (<28 bytes) could be a probe/scanner testing
		// whether anything answers on 500/udp at all, not necessarily a
		// truncated real IKE datagram.
		log.emit(event{Port: port, SrcIP: addr.IP.String(), SrcPort: addr.Port, Event: "ike_malformed",
			Data: strconv.Itoa(len(data))})
		return
	}

	switch {
	case state == ikeStarting && exchangeType == exchangeInit:
		reply, _, err := buildBogusInitReply()
		if err != nil {
			log.emit(event{Port: port, SrcIP: addr.IP.String(), SrcPort: addr.Port, Event: "ike_error", Data: err.Error()})
			return
		}
		conn.WriteToUDP(reply, addr)
		mu.Lock()
		if _, exists := sessions[key]; !exists && len(sessions) >= maxSessions {
			evictOldestIKESessionLocked(sessions)
		}
		sessions[key] = ikeSession{state: ikeReplied, seen: time.Now()}
		mu.Unlock()
		// #619: the attacker's real SA proposal/KE group/nonce length in
		// their own IKE_SA_INIT is computed by parseIKESAInitBody using the
		// same wire format buildBogusInitReply's own encoders produce, but
		// was previously discarded entirely -- read-only, does not
		// influence the bogus reply already sent above.
		log.emit(event{Port: port, SrcIP: addr.IP.String(), SrcPort: addr.Port, Event: "ike_sa_init",
			Data: parseIKESAInitBody(data)})

	case state == ikeReplied:
		// Matches upstream's real deployed behavior for anything past the
		// first exchange (see ike.go's package doc comment): no further
		// reply is ever sent, and the session is dropped so a later
		// IKE_SA_INIT from the same address starts over at ikeStarting,
		// same as upstream's own except-Exception-then-delete path.
		mu.Lock()
		delete(sessions, key)
		mu.Unlock()
		log.emit(event{Port: port, SrcIP: addr.IP.String(), SrcPort: addr.Port, Event: "ike_no_further_reply"})

	default:
		// Which exchange type an attacker sent out-of-sequence (e.g.
		// AGGRESSIVE mode probing straight past SA_INIT) is real recon
		// signal that was computed by parseIKEHeader and then dropped --
		// only the fact that *something* unexpected happened reached ES.
		log.emit(event{Port: port, SrcIP: addr.IP.String(), SrcPort: addr.Port, Event: "ike_unexpected_exchange",
			Data: strconv.Itoa(int(exchangeType))})
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		// A plain TCP connect is enough to prove the WebVPN listener is up
		// -- completing a full TLS handshake would need InsecureSkipVerify
		// (correctly flagged as unsafe in general) for no real benefit,
		// since this only ever dials itself on loopback.
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8443", 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		conn.Close()
		return
	}

	waitForMarker("/markers/log-init.done")

	log := newLogger(getenv("LOG_FILE", "/var/log/honeypot/cisco-asa-honeypot.json"))

	httpsAddr := getenv("HTTPS_LISTEN_ADDR", ":8443")
	_, portStr, _ := net.SplitHostPort(httpsAddr)
	httpsPort, err := strconv.Atoi(portStr)
	if err != nil {
		httpsPort = 8443
	}

	ikeAddr := getenv("IKE_LISTEN_ADDR", ":500")
	_, ikePortStr, _ := net.SplitHostPort(ikeAddr)
	ikePort, err := strconv.Atoi(ikePortStr)
	if err != nil {
		ikePort = 500
	}

	// #2324: bounds the IKE session map against one-shot scanners that
	// never send the second datagram that would otherwise clear an entry.
	ikeMaxSessions := getenvInt("IKE_MAX_SESSIONS", 4096)

	go runIKEResponder(ikeAddr, log, ikePort, ikeMaxSessions)

	cert, err := selfSignedCert()
	if err != nil {
		panic(err)
	}
	ln, err := net.Listen("tcp", httpsAddr)
	if err != nil {
		panic(err)
	}
	if getenv("PROXY_PROTOCOL", "") == "1" {
		ln = &proxyListener{ln}
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})

	srv := &http.Server{
		Handler:  &webvpnHandler{log: log, port: httpsPort},
		ErrorLog: stdlog.New(healthcheckNoiseFilter{}, "", 0),
		// #878: unset (zero-value) timeouts left every phase of a connection
		// unbounded -- a slow-dripped request line/headers/body, or an idle
		// keep-alive connection, pinned a goroutine and file descriptor
		// indefinitely. Nothing here holds a response open on purpose (no
		// tarpit, unlike http-honeypot), so all four can be bounded tightly.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.emit(event{Port: httpsPort, Event: "https_listening"})
	if err := srv.Serve(tlsLn); err != nil {
		panic(err)
	}
}
