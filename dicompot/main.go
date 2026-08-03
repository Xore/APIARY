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
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	dicom "github.com/grailbio/go-dicom"
	"github.com/nsmfoo/dicompot"
	"github.com/nsmfoo/dicompot/dimse"
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
	Event   string `json:"event"`
	Data    string `json:"data,omitempty"`
	Bytes   int    `json:"bytes,omitempty"`
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
	}
	return l
}

func (l *logger) emit(e event) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.Sensor = "dicompot"
	e.Persona = "nexusai-imaging"
	e.Site = "nexusai-radiology-archive"
	e.Org = "NexusAI Research GmbH"
	e.Proto = "dicom"
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
	if v := os.Getenv(k); v != "" {
		return v
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
		CFind: func(_ dicompot.ConnectionState, _ string, sopClassUID string, _ []*dicom.Element, _ string, ch chan dicompot.CFindResult) {
			log.emit(event{Port: port, SrcIP: ip, Event: "c_find", Data: sopClassUID})
			// No dataset behind this honeypot (#413): every C-FIND
			// legitimately matches nothing. The attempt itself, not a
			// realistic result set, is the signal worth capturing.
			close(ch)
		},
		CMove: func(_ dicompot.ConnectionState, _ string, sopClassUID string, _ []*dicom.Element, _ string, ch chan dicompot.CMoveResult) {
			log.emit(event{Port: port, SrcIP: ip, Event: "c_move", Data: sopClassUID})
			close(ch)
		},
		CGet: func(_ dicompot.ConnectionState, _ string, sopClassUID string, _ []*dicom.Element, _ string, ch chan dicompot.CMoveResult) {
			log.emit(event{Port: port, SrcIP: ip, Event: "c_get", Data: sopClassUID})
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
		go func() {
			conn := decodeProxy(conn, proxy)
			defer conn.Close()
			ip := srcIP(conn)
			log.emit(event{Port: port, SrcIP: ip, Event: "connect"})
			dicompot.RunProviderForConn(conn, paramsFor(log, aeTitle, port, ip))
		}()
	}
}
