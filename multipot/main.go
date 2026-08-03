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
	"encoding/json"
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
	stamp := time.Now().UTC().Format("20060102-150405")
	if err := os.Rename(l.path, l.path+"."+stamp); err != nil {
		// Rename failing (e.g. path already gone) shouldn't stop logging --
		// reopening O_APPEND on the original path either resumes the same
		// file or creates a new one, either of which beats losing the fd.
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		l.f = nil
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

func assetForProto(proto string) string {
	return map[string]string{
		"smtp": "mail01", "postgres": "pg-db-02", "redis": "cache01",
		"vnc": "ops-vnc-01", "elasticsearch": "es-logs-01", "docker": "build01",
		"ftp": "legacy-files-01", "mysql": "mysql-legacy-01",
		"mssql": "erp-sql-01", "mongodb": "catalog-doc-01",
		// #238
		"pop3": "mail01", "imap": "mail01", "socks5": "edge-proxy01",
		"hl7": "his-interface-01",
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
	handler func(net.Conn, *logger, int)
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

func serve(s service, log *logger, proxy bool) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(s.port))
	if err != nil {
		log.emit(event{Proto: s.proto, Port: s.port, Event: "listen_error", Data: err.Error()})
		return
	}
	log.emit(event{Proto: s.proto, Port: s.port, Event: "listening"})
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			// If fronted by portbridge with PROXY protocol, recover the real
			// attacker address before anything reads/logs the connection.
			conn = decodeProxy(conn, proxy)
			defer conn.Close()
			// Hard cap on how long any single attacker can hold a connection.
			conn.SetDeadline(time.Now().Add(45 * time.Second))
			log.emit(event{Proto: s.proto, Port: s.port, SrcIP: srcIP(conn), Event: "connect"})
			s.handler(conn, log, s.port)
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

	var wg sync.WaitGroup
	for _, s := range services() {
		wg.Add(1)
		go func(s service) {
			defer wg.Done()
			serve(s, log, proxy)
		}(s)
	}
	log.emit(event{Proto: "-", Event: "multipot_started", Data: strconv.Itoa(len(services())) + " listeners"})
	wg.Wait()
}
