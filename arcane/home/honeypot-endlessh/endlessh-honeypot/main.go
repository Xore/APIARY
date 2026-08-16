// endlessh-honeypot (#246) is a from-scratch Go port of skeeto/endlessh's
// core trick: hold an SSH client's pre-auth connection open forever by
// trickling out random banner-shaped lines, one at a time, and never
// sending the real "SSH-2.0-..." identification string the handshake
// actually needs. RFC4253 §4.2 permits a server to send any number of
// lines not starting with "SSH-" before its real version string, and says
// the client MUST ignore them -- real SSH clients wait it out rather than
// give up, which is exactly the point: near-zero cost on this side (one
// blocked goroutine, no crypto, the handshake never begins) for real
// connection-time cost on the scanner's.
//
// Deliberately NOT sharing a port with cowrie (the full-capture SSH
// honeypot): diverting an attacker into an endless pre-auth stall instead
// of cowrie's real fake-shell interaction would trade capture depth for a
// cheap time-waste on exactly the traffic cowrie most wants to see. This
// binds its own port; which external port (if any) an operator points at
// it is a portbridge/firewall decision made separately, not baked in here.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type event struct {
	Time    string `json:"time"`
	Sensor  string `json:"sensor"`
	Persona string `json:"persona_id"`
	Site    string `json:"site_id"`
	Asset   string `json:"asset_id"`
	Org     string `json:"organization"`
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	SrcIP   string `json:"src_ip"`
	SrcPort int    `json:"src_port"`
	Event   string `json:"event"`
	Lines   int    `json:"lines,omitempty"`
	HeldMS  int64  `json:"held_ms,omitempty"`
}

type logger struct {
	mu  sync.Mutex
	out io.Writer // stdout in production; swapped in tests
	f   *os.File
}

func newLogger(path string) *logger {
	l := &logger{out: os.Stdout}
	if path == "" {
		return l
	}
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
		l.f = f
	} else {
		fmt.Fprintf(os.Stderr, "endlessh: log file %q unavailable, continuing with stdout only: %v\n", path, err)
	}
	return l
}

func (l *logger) emit(e event) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	// "endlessh" (not "endlessh-honeypot") to match this sensor's log
	// directory name (docker-compose.endlessh.yml mounts logs/endlessh) --
	// event.sensor in Elasticsearch is populated from this field, and
	// loadSensorEventsES's query is keyed off the directory-derived
	// dirSensor. A mismatch here would make ES-preferred reads for this
	// sensor silently return zero results forever, same failure shape as
	// #549's conpot persona-extraction bug found this same session.
	e.Sensor = "endlessh"
	e.Persona = getenv("PERSONA_ID", "nexusai-ssh-edge")
	e.Site = getenv("SITE_ID", "nexusai-eu-edge")
	e.Asset = getenv("ASSET_ID", "sshgw02")
	e.Org = getenv("ORGANIZATION", "NexusAI Research GmbH")
	e.Proto = "ssh"
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.out != nil {
		l.out.Write(line)
		l.out.Write([]byte("\n"))
	}
	if l.f != nil {
		l.f.Write(line)
		l.f.Write([]byte("\n"))
	}
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// waitForMarker blocks until path exists, polling every 3s. See #128 --
// same wait dnp3-honeypot/dicompot/rdp-honeypot use.
func waitForMarker(path string) {
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

// randomBannerLine returns a random printable, non-"SSH-"-prefixed line
// endlessh's own README describes as "random data" -- printable ASCII here
// (not raw binary) so a packet capture of it doesn't look like a parsing
// bug when someone's reading it later. 3-30 characters, matching the
// original project's own default range.
func randomBannerLine() string {
	n := 3 + int(randByte()%28)
	buf := make([]byte, n)
	for i := range buf {
		// Printable ASCII, excluding '-' as the very first character so a
		// short line can never accidentally start with "SSH-".
		buf[i] = 0x20 + randByte()%(0x7e-0x20+1)
	}
	if buf[0] == '-' {
		buf[0] = 'x'
	}
	return string(buf)
}

func randByte() byte {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0x41
	}
	return b[0]
}

func serve(c net.Conn, log *logger, port int, delay time.Duration) {
	defer c.Close()
	host, portText, _ := net.SplitHostPort(c.RemoteAddr().String())
	srcPort, _ := strconv.Atoi(portText)
	log.emit(event{Port: port, SrcIP: host, SrcPort: srcPort, Event: "connect"})

	start := time.Now()
	lines := 0
	ticker := time.NewTicker(delay)
	defer ticker.Stop()
	for range ticker.C {
		c.SetWriteDeadline(time.Now().Add(delay))
		if _, err := io.WriteString(c, randomBannerLine()+"\r\n"); err != nil {
			break
		}
		lines++
	}
	log.emit(event{
		Port: port, SrcIP: host, SrcPort: srcPort, Event: "disconnect",
		Lines: lines, HeldMS: time.Since(start).Milliseconds(),
	})
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		c, err := net.DialTimeout("tcp", "127.0.0.1"+getenv("LISTEN_ADDR", ":2222"), time.Second)
		if err != nil {
			os.Exit(1)
		}
		c.Close()
		return
	}

	waitForMarker("/markers/log-init.done")

	addr := getenv("LISTEN_ADDR", ":2222")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	// PROXY_PROTOCOL=1: fronted by portbridge with a ":pp" rule, which
	// prepends a PROXY header carrying the real attacker IP. Mirrors every
	// other tunnelled sensor's own opt-in (see proxyproto.go).
	if getenv("PROXY_PROTOCOL", "") == "1" {
		ln = &proxyListener{ln}
	}

	evLog := newLogger(getenv("LOG_PATH", ""))
	// serve's time.NewTicker(delay) panics for any non-positive duration
	// (Go's own documented behavior), and that call runs inside a
	// per-connection goroutine with no recover -- so a bad DELAY_MS (e.g.
	// "0" from a misconfigured compose override) would otherwise crash
	// the whole process on the first accepted connection instead of
	// failing loudly at startup.
	delay, err := resolveDelay(getenvInt("DELAY_MS", 10000))
	if err != nil {
		log.Fatalf("endlessh-honeypot: %v", err)
	}
	// maxClients bounds concurrent held connections -- endlessh's own
	// default (4096), matched here for the same reason: unbounded holds
	// are the whole point per-connection, but a large scanning botnet
	// opening far more connections than this host has file descriptors
	// for would turn the honeypot into a self-inflicted resource problem
	// instead of the scanner's.
	maxClients := getenvInt("MAX_CLIENTS", 4096)
	sem := make(chan struct{}, maxClients)

	evLog.emit(event{Port: portOf(addr), Event: "listening"})
	// acceptBackoff mirrors net/http.Server.Serve's own tempDelay
	// handling: MAX_CLIENTS defaults to 4096 but common container/host fd
	// limits (e.g. ulimit -n 1024) are lower, so under real scanning load
	// Accept() can start returning a persistent error (EMFILE) on every
	// call. Retrying that unconditionally with no backoff spins a CPU
	// core at 100% accepting nothing; back off (and log) instead.
	var acceptBackoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			acceptBackoff = nextAcceptBackoff(acceptBackoff)
			log.Printf("endlessh-honeypot: accept: %v; retrying in %s", err, acceptBackoff)
			time.Sleep(acceptBackoff)
			continue
		}
		acceptBackoff = 0
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				serve(c, evLog, portOf(addr), delay)
			}()
		default:
			// At capacity -- close immediately rather than queueing
			// indefinitely; a real endlessh does the same (accept, see
			// it's over --max-clients, close without ceremony).
			c.Close()
		}
	}
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// resolveDelay converts DELAY_MS into a validated ticker interval.
// time.NewTicker panics for any non-positive duration, so a bad env var
// (0, negative) must be rejected here at startup rather than reaching
// serve's per-connection ticker.
func resolveDelay(ms int) (time.Duration, error) {
	d := time.Duration(ms) * time.Millisecond
	if d <= 0 {
		return 0, fmt.Errorf("DELAY_MS must be a positive duration in milliseconds, got %dms", ms)
	}
	return d, nil
}

const maxAcceptBackoff = time.Second

// nextAcceptBackoff returns the next Accept() retry delay given the
// previous one, mirroring net/http.Server.Serve's own tempDelay pattern:
// start small, double each consecutive failure, cap at maxAcceptBackoff.
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
