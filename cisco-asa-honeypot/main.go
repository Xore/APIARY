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
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

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

// ikeState tracks, per source address, whether this session has already
// received its one bogus IKE_SA_INIT reply. See ike.go's package doc
// comment for exactly why there is only ever one.
type ikeState int

const (
	ikeStarting ikeState = iota
	ikeReplied
)

func runIKEResponder(addr string, log *logger, port int) {
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
	sessions := map[string]ikeState{}

	buf := make([]byte, 4096)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go handleIKEPacket(conn, raddr, data, log, port, &mu, sessions)
	}
}

func handleIKEPacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte, log *logger, port int, mu *sync.Mutex, sessions map[string]ikeState) {
	key := addr.String()
	exchangeType, ok := parseIKEHeader(data)

	mu.Lock()
	state := sessions[key]
	mu.Unlock()

	if !ok {
		log.emit(event{Port: port, SrcIP: addr.IP.String(), SrcPort: addr.Port, Event: "ike_malformed"})
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
		sessions[key] = ikeReplied
		mu.Unlock()
		log.emit(event{Port: port, SrcIP: addr.IP.String(), SrcPort: addr.Port, Event: "ike_sa_init"})

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

	go runIKEResponder(ikeAddr, log, ikePort)

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

	srv := &http.Server{Handler: &webvpnHandler{log: log, port: httpsPort}}
	log.emit(event{Port: httpsPort, Event: "https_listening"})
	if err := srv.Serve(tlsLn); err != nil {
		panic(err)
	}
}
