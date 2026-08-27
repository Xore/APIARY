// rdp-honeypot — Go port of CommunityHoneyNetwork/rdphoney (#238, #412),
// the RDP (3389/tcp) decoy T-Pot itself actually runs. Confirmed directly
// against its real source before porting: despite RDP's reputation as a
// heavy protocol (X.224/MCS/security-layer negotiation, TLS, CredSSP),
// this honeypot does none of that. It's a bare TCP accept loop that reads
// one packet (the client's initial X.224 Connection Request, which is
// always sent in cleartext before any negotiation begins), regex-extracts
// a username from the optional "Cookie: mstshash=<user>" token real RDP
// clients send at this stage, logs it, sends back a single fixed string,
// and closes. Not a "weekend project" scale item as #238's original
// research summary assumed (that assessment was based on citronneur/rdpy,
// a much larger vendored protocol library with its own bundled honeypot
// script -- unmaintained since 2021, Python 2 only, and needing
// pre-recorded fake-desktop session files) -- rdphoney is what real
// deployments actually use, and it's this simple.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mstshashRe extracts the username from the RDP cookie token real clients
// send in the X.224 Connection Request: "Cookie: mstshash=<username>\r\n".
// Matches upstream's own regex exactly.
var mstshashRe = regexp.MustCompile(`mstshash=([a-zA-Z0-9\-_@]+)`)

// negFailure is the literal response upstream sends back to every
// connection -- an ASCII string, not an actual RDP_Neg_Failure PDU
// (RFC/MS-RDPBCGR's real wire format is binary, not text). Reproduced
// byte-for-byte rather than "fixed" into a technically correct PDU: this
// is what the real, currently-deployed honeypot this stack ports actually
// sends, and inventing a more protocol-correct response wasn't asked for.
const negFailure = "0x00000004 RDP_NEG_FAILURE"

type event struct {
	Time      string `json:"time"`
	Sensor    string `json:"sensor"`
	Persona   string `json:"persona_id"`
	Site      string `json:"site_id"`
	Asset     string `json:"asset_id"`
	Org       string `json:"organization"`
	Proto     string `json:"proto"`
	Port      int    `json:"port"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	Event     string `json:"event"`
	Username  string `json:"username,omitempty"`
	Data      string `json:"data,omitempty"`
	Protocols string `json:"requested_protocols,omitempty"`
}

type logger struct {
	mu  sync.Mutex
	out *os.File
}

func newLogger(path string) *logger {
	l := &logger{}
	if path == "" {
		return l
	}
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
		l.out = f
	} else {
		fmt.Fprintf(os.Stderr, "rdp-honeypot: log file %q unavailable, continuing with stdout only: %v\n", path, err)
	}
	return l
}

func (l *logger) emit(e event) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.Sensor = "rdp-honeypot"
	e.Persona = "nexusai-rdp-jump"
	e.Site = "nexusai-eu-edge"
	e.Asset = "rdpgw01"
	e.Org = "NexusAI Research GmbH"
	e.Proto = "rdp"
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	os.Stdout.Write(line)
	os.Stdout.Write([]byte("\n"))
	if l.out != nil {
		l.out.Write(line)
		l.out.Write([]byte("\n"))
	}
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
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

func extractUsername(data []byte) string {
	m := mstshashRe.FindSubmatch(data)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// requestedProtocolNames maps MS-RDPBCGR 2.2.1.1.1's RDP_NEG_REQ
// requestedProtocols bitmask to readable names -- which security layer a
// client offers (plain RDP vs. TLS vs. CredSSP/NLA) is a real client
// fingerprint (e.g. legacy/scripted clients that never offer CredSSP) that
// was present in the raw packet this file already logs verbatim as base64,
// but never broken out into its own filterable field.
var requestedProtocolNames = []struct {
	bit  uint32
	name string
}{
	{0x01, "TLS"},
	{0x02, "CredSSP"},
	{0x04, "RDSTLS"},
	{0x08, "CredSSP-EarlyUserAuth"},
}

// extractNegotiationProtocols reads the RDP_NEG_REQ structure, which
// MS-RDPBCGR fixes as exactly the last 8 bytes of the X.224 Connection
// Request PDU when present: type(1)=0x01, flags(1), length(2)=8,
// requestedProtocols(4), all little-endian.
func extractNegotiationProtocols(data []byte) (string, bool) {
	if len(data) < 8 {
		return "", false
	}
	tail := data[len(data)-8:]
	const typeRDPNegReq = 0x01
	if tail[0] != typeRDPNegReq {
		return "", false
	}
	if binary.LittleEndian.Uint16(tail[2:4]) != 8 {
		return "", false
	}
	flags := binary.LittleEndian.Uint32(tail[4:8])
	if flags == 0 {
		return "RDP", true
	}
	var names []string
	for _, p := range requestedProtocolNames {
		if flags&p.bit != 0 {
			names = append(names, p.name)
		}
	}
	if len(names) == 0 {
		return "RDP", true
	}
	return strings.Join(names, "+"), true
}

// handleConn is the whole world past Accept: PROXY/X.224 attacker bytes are
// decoded straight off the socket inside the spawned goroutine (#2099 moved
// that work out of the accept loop) with no recover anywhere underneath, and
// in Go one unrecovered panic kills the entire sensor while restart:
// unless-stopped hands the attacker the same replayable bytes right back.
// http-honeypot gets this shield per request from net/http; this
// low-interaction listener carries it itself, at the top of the
// per-connection entrypoint so it covers BOTH stages the goroutine runs --
// the decodeProxy leg and the serve body. A panicking connection is closed
// and lands in the normal JSON pipeline as one attributable handler_panic
// event while the accept loop and every other live connection keep running.
// Attribution comes from the RAW accepted conn because it is the one address
// guaranteed valid even if the panic fired before decodeProxy ever returned;
// behind portbridge that is the tunnel peer, not the PROXY-decoded attacker
// IP -- worth one honest field over inventing two-stage bookkeeping for a
// path future edits are expected to trip far more often than production is.
func handleConn(c net.Conn, proxy bool, log *logger, port int) {
	defer func() {
		if r := recover(); r != nil {
			host, portText, _ := net.SplitHostPort(c.RemoteAddr().String())
			srcPort, _ := strconv.Atoi(portText)
			log.emit(event{Port: port, SrcIP: host, SrcPort: srcPort, Event: "handler_panic", Data: fmt.Sprint(r)})
		}
	}()
	serve(decodeProxy(c, proxy), log, port)
}

func serve(c net.Conn, log *logger, port int) {
	defer c.Close()
	host, portText, _ := net.SplitHostPort(c.RemoteAddr().String())
	srcPort, _ := strconv.Atoi(portText)

	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		return
	}
	data := buf[:n]

	e := event{
		Port:     port,
		SrcIP:    host,
		SrcPort:  srcPort,
		Event:    "connect",
		Username: extractUsername(data),
		Data:     base64.StdEncoding.EncodeToString(data),
	}
	if protocols, ok := extractNegotiationProtocols(data); ok {
		e.Protocols = protocols
	}
	log.emit(e)

	c.Write([]byte(negFailure))
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:3389", 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		conn.Close()
		return
	}

	waitForMarker("/markers/log-init.done")

	addr := getenv("LISTEN_ADDR", ":3389")
	_, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 3389
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	// PROXY_PROTOCOL=1: fronted by portbridge with a ":pp" rule, which
	// prepends a PROXY header carrying the real attacker IP.
	proxy := getenv("PROXY_PROTOCOL", "") == "1"

	log := newLogger(getenv("LOG_FILE", "/var/log/honeypot/rdp-honeypot.json"))
	log.emit(event{Port: port, Event: "listening"})

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		spawnServe(c, proxy, log, port)
	}
}

// spawnServe launches the per-connection handler with the PROXY-header
// decode INSIDE the spawned goroutine (#2099). A go statement's arguments
// are evaluated synchronously on the calling goroutine, so the previous
// `go serve(decodeProxy(c, proxy), log, port)` form ran the 5s-bounded
// decode on the shared accept loop before serve ever started -- one
// silent connection stalled admission of every other connection for up
// to 5s each (the same defect #1346 fixed in cisco-asa and #2099 ports
// into citrix/endlessh/http/dnp3).
func spawnServe(c net.Conn, proxy bool, log *logger, port int) {
	go handleConn(c, proxy, log, port)
}
