// multipot — a multi-protocol low-interaction honeypot in a single Go binary.
//
// It opens a listener per service (FTP, SMTP, Redis, MySQL, PostgreSQL, VNC,
// Elasticsearch, …), answers with a realistic banner/handshake for each, and
// records every connection, command and credential as one JSON line per event.
//
// Nothing it emulates is real — no data, no execution. Keep it on an isolated
// network (see docker-compose.yml) so it can only ever be a sensor.
package main

import (
	"crypto/rand"
	"encoding/hex"
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

// event is one JSON log line. Fields are omitempty so each protocol only emits
// what's relevant.
type event struct {
	Time     string `json:"time"`
	Sensor   string `json:"sensor"`
	Persona  string `json:"persona_id"`
	Site     string `json:"site_id"`
	Asset    string `json:"asset_id"`
	Org      string `json:"organization"`
	Proto    string `json:"proto"`
	Port     int    `json:"port"`
	SrcIP    string `json:"src_ip"`
	Event    string `json:"event"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Command  string `json:"command,omitempty"`
	Data     string `json:"data,omitempty"`
	Client   string `json:"client,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	Session  string `json:"session,omitempty"`
}

type logger struct {
	mu   sync.Mutex
	out  io.Writer
	f    *os.File
	path string
	size int64
	max  int64
}

func newLogger(path string) *logger {
	// #120: this file has no external rotation (JSON event streams are
	// intentionally exempt from analysis/log-maintenance.sh's copytruncate,
	// same reasoning as #79 -- Filebeat tracks by inode/offset, and an
	// in-place truncate under an open harvester loses data). Suricata's own
	// fix for eve.json was rotate-interval: close, rename, reopen at the
	// same path. This is that same pattern for a writer that can just check
	// its own byte count on every write instead of a wall-clock interval.
	l := &logger{out: os.Stdout, path: path, max: getenvInt64("LOG_MAX_BYTES", 67108864)}
	if path != "" {
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
			l.f = f
			if st, err := f.Stat(); err == nil {
				l.size = st.Size()
			}
		} else {
			fmt.Fprintf(os.Stderr, "multipot: log file %q unavailable, continuing with stdout only: %v\n", path, err)
		}
	}
	return l
}

// rotate closes the current file, renames it aside with a timestamp suffix,
// and reopens a fresh file at the original path. Filebeat's file_identity
// defaults to inode/device, not path, so its harvester stays attached to the
// renamed file through EOF; the fresh file is picked up by the same glob
// that already covers the original name. Callers must hold l.mu.
func (l *logger) rotate() {
	if l.f == nil || l.path == "" {
		return
	}
	l.f.Close()
	// Second-granularity timestamps collide when two rotations happen within
	// the same wall-clock second (#1403 -- the same pattern this file
	// originated already caught the same bug once copied into
	// ip-enrichment-worker/rotate.go and dionaea/log_rotation_patch.py, both
	// fixed with a counter suffix; applying the identical fix back here).
	// Disambiguate with a counter suffix instead of trusting the clock alone.
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
	if err := os.Rename(l.path, target); err != nil {
		// Rename failing (e.g. path already gone) shouldn't stop logging --
		// reopening O_APPEND on the original path either resumes the same
		// file or creates a new one, either of which beats losing the fd.
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		l.f = nil
		fmt.Fprintf(os.Stderr, "multipot: log file %q unavailable after rotation, continuing with stdout only: %v\n", l.path, err)
		return
	}
	l.f = f
	l.size = 0
}

func (l *logger) emit(e event) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.Sensor = "multipot"
	e.Persona = "nexusai-core"
	e.Site = "nexusai-berlin-core"
	e.Org = "NexusAI Research GmbH"
	if e.Asset == "" {
		e.Asset = assetForProto(e.Proto)
	}
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Write(line)
	l.out.Write([]byte("\n"))
	if l.f != nil {
		if l.max > 0 && l.size >= l.max {
			l.rotate()
		}
		if l.f != nil {
			n1, _ := l.f.Write(line)
			n2, _ := l.f.Write([]byte("\n"))
			l.size += int64(n1 + n2)
		}
	}
}

// sessionLogger scopes every emitted event to one connection, mirroring
// cowrie's "session" field (#608) -- every one of the eleven protocol
// handlers already calls log.emit(event{...}) by field name, so shadowing
// emit here (Go resolves it statically, not virtually) stamps the session
// id on every call site with zero changes to protocols.go itself.
type sessionLogger struct {
	*logger
	id string
}

func (s *sessionLogger) emit(e event) {
	e.Session = s.id
	s.logger.emit(e)
}

// newSessionID returns a random 12-hex-char id, the same shape as cowrie's
// own transport id, so both sensors' session values look interchangeable in
// the dashboard/ES.
func newSessionID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is effectively unrecoverable on any real
		// platform; a timestamp-derived fallback still uniquely tags this
		// connection's events even in that case.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func assetForProto(proto string) string {
	return map[string]string{
		"smtp": "mail01", "postgres": "pg-db-02", "redis": "cache01",
		"vnc": "ops-vnc-01", "elasticsearch": "es-logs-01", "docker": "build01",
		"ftp": "legacy-files-01", "mysql": "mysql-legacy-01",
		"mssql": "erp-sql-01", "mongodb": "catalog-doc-01",
		// #238
		"pop3": "mail01", "imap": "mail01", "socks5": "edge-proxy01",
		"hl7": "his-interface-01", "adb": "android-build-node01",
	}[proto]
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

const maxAcceptBackoff = time.Second

// nextAcceptBackoff returns the next Accept() retry delay given the
// previous one: start small, double each consecutive failure, cap at
// maxAcceptBackoff. Ported verbatim from endlessh-honeypot/main.go (#2328).
func nextAcceptBackoff(prev time.Duration) time.Duration {
	if prev == 0 {
		return 5 * time.Millisecond
	}
	next := prev * 2
	if next > maxAcceptBackoff {
		return maxAcceptBackoff
	}
	return next
}

// waitForMarker blocks until path exists, polling every 3s. See #128.
func waitForMarker(path string) {
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

func srcIP(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

// service ties a protocol name + port to its connection handler.
type service struct {
	proto   string
	port    int
	handler func(net.Conn, *sessionLogger, int)
}

// The default fleet. Ports are the container-internal ports; docker-compose
// maps them to the matching host ports.
//
// Protocols listed in MULTIPOT_DISABLE (comma-separated) are skipped — use this
// to cede ports to a higher-interaction honeypot in the same stack, e.g.
// MULTIPOT_DISABLE=ftp,mysql,mssql,mongodb when Dionaea owns 21/3306/1433/27017.
func services() []service {
	all := []service{
		{"ftp", 21, handleFTP},
		{"smtp", 25, handleSMTP},
		{"mysql", 3306, handleMySQL},
		{"postgres", 5432, handlePostgres},
		{"redis", 6379, handleRedis},
		{"vnc", 5900, handleVNC},
		{"elasticsearch", 9200, handleElastic},
		// Binary/complex protocols we don't fully emulate still get logged raw:
		{"mssql", 1433, handleGeneric},
		{"mongodb", 27017, handleGeneric},
		{"docker", 2375, handleDocker},
		// #238: T-Pot protocol coverage gaps, ported into multipot rather
		// than vendoring heralding (pop3/imap/socks5) or medpot (hl7) --
		// see that issue's research comments for why each of these is
		// multipot's exact shape (accept, read, pattern-match, canned
		// response, log) rather than a real reimplementation project.
		{"pop3", 110, handlePOP3},
		{"imap", 143, handleIMAP},
		{"socks5", 1080, handleSOCKS5},
		{"hl7", 2575, handleHL7},
		{"adb", 5555, handleADB},
	}
	disabled := map[string]bool{}
	for _, p := range strings.Split(os.Getenv("MULTIPOT_DISABLE"), ",") {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
			disabled[p] = true
		}
	}
	var out []service
	for _, s := range all {
		if !disabled[s.proto] {
			out = append(out, s)
		}
	}
	return out
}

// serve runs one protocol's accept loop. sem is shared across every
// protocol's serve() goroutine (#2328): the fd ulimit and CPU quota it
// guards against are process-wide, not per-listener, so one protocol under
// scan pressure must draw down the same budget as the rest.
func serve(s service, log *logger, proxy bool, sem chan struct{}) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(s.port))
	if err != nil {
		log.emit(event{Proto: s.proto, Port: s.port, Event: "listen_error", Data: err.Error()})
		return
	}
	log.emit(event{Proto: s.proto, Port: s.port, Event: "listening"})
	// acceptBackoff mirrors net/http.Server.Serve's own tempDelay handling
	// (and endlessh-honeypot's port of it): a bare
	// `if err != nil { continue }` retries an EMFILE-class Accept() error
	// unconditionally, spinning a CPU core at 100% accepting nothing once a
	// botnet holds enough connections to exhaust this container's fd
	// ulimit. Back off (and log) instead.
	var acceptBackoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			acceptBackoff = nextAcceptBackoff(acceptBackoff)
			log.emit(event{Proto: s.proto, Port: s.port, Event: "accept_error", Data: err.Error() + "; retrying in " + acceptBackoff.String()})
			time.Sleep(acceptBackoff)
			continue
		}
		acceptBackoff = 0
		select {
		case sem <- struct{}{}:
		default:
			// At capacity -- close immediately rather than queueing
			// indefinitely, the same choice endlessh-honeypot makes.
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			// #2186: protocol handlers parse attacker bytes directly on this
			// goroutine with no recover underneath, and in Go one unrecovered
			// panic kills the whole binary -- every listener with it, while
			// restart: unless-stopped hands the attacker their kill switch
			// back. http-honeypot gets this boundary per request from
			// net/http; multipot carries it itself, at the top of the
			// per-connection goroutine before any parsing runs: one
			// panicking connection collapses into one handler_panic event
			// plus a closed socket while this serve()'s accept loop (and the
			// other protocols' listeners) keep serving.
			defer func() {
				if r := recover(); r != nil {
					log.emit(event{Proto: s.proto, Port: s.port, SrcIP: srcIP(conn), Event: "handler_panic", Data: fmt.Sprint(r)})
				}
			}()
			// If fronted by portbridge with PROXY protocol, recover the real
			// attacker address before anything reads/logs the connection.
			conn = decodeProxy(conn, proxy)
			defer conn.Close()
			// #1677: main()'s -healthcheck dials 127.0.0.1:6379 directly,
			// and that connection is accepted by this same listener as real
			// traffic -- a real external connection can never present that
			// address (it always arrives as either a real attacker IP via
			// the ":pp" portbridge rule or the tunnel peer otherwise), so
			// this can only be the container's own healthcheck. Close it
			// without logging a fake sensor event.
			if ip := srcIP(conn); ip == "127.0.0.1" || ip == "::1" {
				return
			}
			// Hard cap on how long any single attacker can hold a connection.
			conn.SetDeadline(time.Now().Add(45 * time.Second))
			sl := &sessionLogger{logger: log, id: newSessionID()}
			sl.emit(event{Proto: s.proto, Port: s.port, SrcIP: srcIP(conn), Event: "connect"})
			s.handler(conn, sl, s.port)
		}()
	}
}

func main() {
	// -healthcheck: succeeds if any one listener is up (used by the scratch
	// image's Docker HEALTHCHECK). We probe the Redis port.
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		c, err := net.DialTimeout("tcp", "127.0.0.1:6379", 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		c.Close()
		os.Exit(0)
	}

	// #128: same-project depends_on: condition: service_completed_successfully
	// against a shim can't reach honeypot-init (different Compose project),
	// so every other service in this stack waits on honeypot-init's
	// completion marker directly instead -- normally via an entrypoint:
	// wrapper, but this image is FROM scratch with no shell to wrap with,
	// so the wait lives here instead.
	waitForMarker("/markers/log-init.done")

	log := newLogger(getenv("LOG_FILE", "/var/log/honeypot/multipot.json"))
	proxy := getenv("PROXY_PROTOCOL", "") == "1"

	// maxClients bounds concurrent held connections across ALL of
	// multipot's protocols combined, mirroring endlessh-honeypot's own
	// default (4096): a botnet opening far more connections than this
	// host has file descriptors for would otherwise turn the honeypot
	// into a self-inflicted resource problem instead of the scanner's
	// (#2328). Shared, not per-protocol, because the fd ulimit and CPU
	// quota it guards are process-wide.
	sem := make(chan struct{}, getenvInt("MAX_CLIENTS", 4096))

	var wg sync.WaitGroup
	for _, s := range services() {
		wg.Add(1)
		go func(s service) {
			defer wg.Done()
			serve(s, log, proxy, sem)
		}(s)
	}
	log.emit(event{Proto: "-", Event: "multipot_started", Data: strconv.Itoa(len(services())) + " listeners"})
	wg.Wait()
}
