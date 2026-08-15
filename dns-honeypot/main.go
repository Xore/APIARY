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
	SrcPort   int    `json:"src_port"`
	Event     string `json:"event"`
	Query     string `json:"query,omitempty"`
	QType     int    `json:"qtype,omitempty"`
	Opcode    int    `json:"opcode,omitempty"`
	Recursion bool   `json:"rd,omitempty"`
	ReqBytes  int    `json:"req_bytes,omitempty"`
	RespBytes int    `json:"resp_bytes,omitempty"`
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
		fmt.Fprintf(os.Stderr, "dns-honeypot: log file %q unavailable, continuing with stdout only: %v\n", path, err)
	}
	return l
}

func (l *logger) emit(e event) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.Sensor = "dns-honeypot"
	e.Persona = "nexusai-dns"
	e.Site = "nexusai-eu-edge"
	e.Asset = "dns01"
	e.Org = "NexusAI Research GmbH"
	e.Proto = "dns"
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

// waitForMarker blocks until path exists, polling every 3s. See #128 --
// same wait multipot/dnp3/dicompot use, so the log-init job (which chowns
// this container's log directory) has definitely run first.
func waitForMarker(path string) {
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

func handlePacket(conn *net.UDPConn, addr *net.UDPAddr, req []byte, log *logger, port int) {
	resp := buildCappedResponse(req)
	if resp != nil {
		conn.WriteToUDP(resp, addr)
	}
	// Docker's healthcheck sends a real, well-formed query every 30s from
	// loopback -- respond to it like any other query (proves the listener
	// actually works), but don't let it show up as decoy traffic.
	if addr.IP.IsLoopback() {
		return
	}
	e := event{Port: port, SrcIP: addr.IP.String(), SrcPort: addr.Port, Event: "query", ReqBytes: len(req)}
	if opcode, rd, ok := parseHeaderFlags(req); ok {
		e.Opcode = int(opcode)
		e.Recursion = rd
	}
	if q, ok := parseQuestion(req); ok {
		e.Query = q.name
		e.QType = int(q.qtype)
	} else {
		e.Event = "malformed_query"
	}
	if resp != nil {
		e.RespBytes = len(resp)
	} else {
		e.Event += "_dropped"
	}
	log.emit(e)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		// UDP has no connect-time handshake to fail, so Dial alone proves
		// nothing about whether anything is actually listening -- send a
		// real minimal query and require an actual reply.
		c, err := net.DialTimeout("udp", "127.0.0.1:53", 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		// 12-byte header (arbitrary ID, standard query flags) + a single
		// "a." A/IN question -- the smallest legitimate DNS query.
		probe := []byte{
			0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 'a', 0x00, 0x00, 0x01, 0x00, 0x01,
		}
		if _, err := c.Write(probe); err != nil {
			os.Exit(1)
		}
		buf := make([]byte, 512)
		if _, err := c.Read(buf); err != nil {
			os.Exit(1)
		}
		return
	}

	waitForMarker("/markers/log-init.done")

	addr := getenv("LISTEN_ADDR", ":53")
	portStr := addr[strings.LastIndex(addr, ":")+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 53
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}

	log := newLogger(getenv("LOG_FILE", "/var/log/honeypot/dns-honeypot.json"))
	log.emit(event{Port: port, Event: "listening"})

	buf := make([]byte, 4096)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		go handlePacket(conn, raddr, req, log, port)
	}
}
