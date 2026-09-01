// dicompot — wiring layer around the vendored github.com/nsmfoo/dicompot
// package (#238, #413): that package (imported unmodified, pinned via
// go.mod/go.sum) implements the actual DICOM PDU/DIMSE state machine
// (association negotiation, C-FIND/C-STORE/C-GET) -- the genuinely complex,
// not-worth-reimplementing part. This file only replaces upstream's own
// server/dicompot.go entrypoint, and only to fix its logging integration:
//
//   - Upstream writes connection-level events via logrus + a rotatefilehook
//     file hook. Verified directly (see this repo's own testing, not
//     assumed) that the file hook never actually writes -- hook.Fire()
//     discards lumberjack's Write() error silently, and no file ever
//     appears on disk even though the same event reaches stdout fine. Not
//     safe to depend on for evidence.
//   - dicompot.ConnectionState is an empty struct: none of the DIMSE
//     callbacks (CFind/CStore/CMove/CGet) receive the attacker's address at
//     all. Building ServiceProviderParams fresh inside each connection's own
//     goroutine (closing over that connection's ip, rather than one shared
//     package-level params value reused for every connection) is what
//     attributes a callback firing back to which attacker triggered it.
//
// Every event this file emits follows multipot/main.go's own JSON shape
// exactly (same field names, same Filebeat honeypot-json parsing, same
// dashboard classify() pipeline) rather than inventing a second convention
// for one more sensor. proxyproto.go is copied from multipot verbatim
// (stdlib-only, no multipot-specific deps) so PROXY_PROTOCOL=1 behaves
// identically behind portbridge's ":pp" rule flag.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	dicom "github.com/grailbio/go-dicom"
	"github.com/grailbio/go-dicom/dicomtag"
	"github.com/nsmfoo/dicompot"
	"github.com/nsmfoo/dicompot/dimse"
)

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
	Event     string `json:"event"`
	Data      string `json:"data,omitempty"`
	Bytes     int    `json:"bytes,omitempty"`
	CalledAE  string `json:"called_ae,omitempty"`
	CallingAE string `json:"calling_ae,omitempty"`
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
		fmt.Fprintf(os.Stderr, "dicompot: log file %q unavailable, continuing with stdout only: %v\n", path, err)
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
		fmt.Fprintf(os.Stderr, "dicompot: log file %q unavailable after rotation, continuing with stdout only: %v\n", l.path, err)
		return
	}
	l.out = f
	l.size = 0
}

func (l *logger) emit(e event) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.Sensor = "dicompot"
	e.Persona = "nexusai-imaging"
	e.Site = "nexusai-radiology-archive"
	// Fixed asset id like every sibling decoy ships (dns01, rdpgw01,
	// asagw01, citrixgw01): the dashboard joins attacker traffic to the
	// deployed asset on this field, so it must be stable and non-empty.
	e.Asset = "pacs01"
	e.Org = "NexusAI Research GmbH"
	e.Proto = "dicom"
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

// waitForMarker blocks until path exists, polling every 3s. See #128 --
// same wait multipot/http-honeypot/dnp3 use, so the log-init job (which
// chowns /var/log/honeypot to this container's own uid) has definitely run
// before the logger below ever opens LOG_FILE.
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

// joinNonEmpty joins sopClassUID and filter with " | ", skipping either side
// when empty rather than leaving a dangling separator.
func joinNonEmpty(sopClassUID, filter string) string {
	if filter == "" {
		return sopClassUID
	}
	if sopClassUID == "" {
		return filter
	}
	return sopClassUID + " | " + filter
}

// formatQueryFilter renders a C-FIND/C-MOVE/C-GET query dataset as a
// printable "(tag)[Name]=value, ..." summary -- which PatientName/PatientID/
// StudyDate an attacker searched for is real recon signal (probing for a
// specific patient's imaging) that the elements slice previously carried
// into these callbacks and then discarded entirely.
func formatQueryFilter(elements []*dicom.Element) string {
	parts := make([]string, 0, len(elements))
	for _, el := range elements {
		if el == nil || len(el.Value) == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%v", dicomtag.DebugString(el.Tag), el.Value))
	}
	s := strings.Join(parts, ", ")
	if len(s) > 512 {
		s = s[:512] + "(...)"
	}
	return s
}

// paramsFor builds a fresh ServiceProviderParams per connection so its
// callbacks close over this connection's own ip -- see the package doc
// comment above for why that's necessary (ConnectionState carries nothing).
func paramsFor(log *logger, aeTitle string, port int, ip string) dicompot.ServiceProviderParams {
	return dicompot.ServiceProviderParams{
		AETitle: aeTitle,
		Enforce: "no",
		CEcho: func(dicompot.ConnectionState) dimse.Status {
			log.emit(event{Port: port, SrcIP: ip, Event: "c_echo"})
			return dimse.Success
		},
		CFind: func(_ dicompot.ConnectionState, _ string, sopClassUID string, elements []*dicom.Element, _ string, ch chan dicompot.CFindResult) {
			log.emit(event{Port: port, SrcIP: ip, Event: "c_find", Data: joinNonEmpty(sopClassUID, formatQueryFilter(elements))})
			// No dataset behind this honeypot (#413): every C-FIND
			// legitimately matches nothing. The attempt itself, not a
			// realistic result set, is the signal worth capturing.
			close(ch)
		},
		CMove: func(_ dicompot.ConnectionState, _ string, sopClassUID string, elements []*dicom.Element, _ string, ch chan dicompot.CMoveResult) {
			log.emit(event{Port: port, SrcIP: ip, Event: "c_move", Data: joinNonEmpty(sopClassUID, formatQueryFilter(elements))})
			close(ch)
		},
		CGet: func(_ dicompot.ConnectionState, _ string, sopClassUID string, elements []*dicom.Element, _ string, ch chan dicompot.CMoveResult) {
			log.emit(event{Port: port, SrcIP: ip, Event: "c_get", Data: joinNonEmpty(sopClassUID, formatQueryFilter(elements))})
			close(ch)
		},
		// CStore deliberately blocked-but-logged: rejecting with
		// StatusUnrecognizedOperation and never accepting the payload
		// matches upstream's own default behavior for a nil CStore
		// callback (confirmed directly against source, see #413) -- this
		// just replaces the broken logging path, not the decision to
		// reject.
		CStore: func(_ dicompot.ConnectionState, _ string, sopClassUID string, sopInstanceUID string, data []byte) dimse.Status {
			log.emit(event{Port: port, SrcIP: ip, Event: "c_store", Data: sopClassUID + " " + sopInstanceUID,
				Bytes: len(data)})
			return dimse.Status{Status: dimse.StatusUnrecognizedOperation}
		},
	}
}

func main() {
	bindIP := getenv("BIND_IP", "0.0.0.0")
	portStr := getenv("PORT", "11112")
	aeTitle := getenv("AE_TITLE", "RADIANT")
	logPath := getenv("LOG_FILE", "/var/log/honeypot/dicompot.json")
	proxy := getenv("PROXY_PROTOCOL", "") == "1"

	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 11112
	}
	waitForMarker("/markers/log-init.done")
	log := newLogger(logPath)

	ln, err := net.Listen("tcp", bindIP+":"+portStr)
	if err != nil {
		log.emit(event{Port: port, Event: "listen_error", Data: err.Error()})
		os.Exit(1)
	}
	log.emit(event{Port: port, Event: "listening"})

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, log, proxy, aeTitle, port)
	}
}

// handleConn serves one accepted connection end to end: PROXY-protocol
// decode, the #1677 healthcheck guard, the A-ASSOCIATE peek, then the
// vendored ServiceProvider owns the wire until the association ends.
func handleConn(conn net.Conn, log *logger, proxy bool, aeTitle string, port int) {
	// #2186: this goroutine is the only boundary between untrusted input and
	// process death. Everything below parses attacker bytes without a
	// recover of its own -- decodeProxy on a crafted ":pp" header,
	// peekAETitles, the vendored state machine's DIMSE callbacks, and
	// grailbio/go-dicom decoding C-FIND/C-MOVE/C-GET datasets on this very
	// call stack (and vendored parsing may panic from goroutines we don't
	// spawn) -- and in Go one unrecovered panic kills the whole sensor
	// while restart: unless-stopped hands the same replayable bytes right
	// back. http-honeypot gets this shield per request from net/http;
	// dicompot carries it itself at the top of the per-connection
	// goroutine: a panicking connection costs exactly one handler_panic
	// event plus a closed socket, never the accept loop or the other
	// in-flight associations.
	var ip string
	defer func() {
		if r := recover(); r != nil {
			log.emit(event{Port: port, SrcIP: ip, Event: "handler_panic", Data: fmt.Sprint(r)})
		}
	}()
	conn = decodeProxy(conn, proxy)
	defer conn.Close()
	ip = srcIP(conn)
	// #1677: the image's own Docker HEALTHCHECK is `nc -z
	// 127.0.0.1 <port>`, a real TCP connect accepted by this same
	// listener -- a real external connection can never present
	// that address (it always arrives as either a real attacker
	// IP via the ":pp" portbridge rule or the tunnel peer
	// otherwise), so this can only be the healthcheck probe.
	// Close it without logging a fake sensor event.
	if ip == "127.0.0.1" || ip == "::1" {
		return
	}
	log.emit(event{Port: port, SrcIP: ip, Event: "connect"})
	conn, calledAE, callingAE := peekAETitles(conn)
	if calledAE != "" || callingAE != "" {
		log.emit(event{Port: port, SrcIP: ip, Event: "associate", CalledAE: calledAE, CallingAE: callingAE})
	}
	dicompot.RunProviderForConn(conn, paramsFor(log, aeTitle, port, ip))
}
