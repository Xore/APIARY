package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type event struct {
	Time, Sensor, Persona, Site, Asset, Organization string
	SrcIP, Event, FrameHex, Function                 string
	SrcPort, Port, DNP3Source, DNP3Destination       int
}

func (e event) MarshalJSON() ([]byte, error) {
	type record struct {
		Time            string `json:"time"`
		Sensor          string `json:"sensor"`
		Persona         string `json:"persona_id"`
		Site            string `json:"site_id"`
		Asset           string `json:"asset_id"`
		Organization    string `json:"organization"`
		SrcIP           string `json:"src_ip"`
		SrcPort         int    `json:"src_port"`
		Port            int    `json:"port"`
		Event           string `json:"event"`
		Frame           string `json:"frame_hex,omitempty"`
		Function        string `json:"function,omitempty"`
		DNP3Source      int    `json:"dnp3_source,omitempty"`
		DNP3Destination int    `json:"dnp3_destination,omitempty"`
	}
	return json.Marshal(record{e.Time, e.Sensor, e.Persona, e.Site, e.Asset, e.Organization, e.SrcIP, e.SrcPort, e.Port, e.Event, e.FrameHex, e.Function, e.DNP3Source, e.DNP3Destination})
}

type logger struct {
	out  io.Writer
	file *os.File
	mu   sync.Mutex
}

func newLogger(path string) *logger {
	l := &logger{out: os.Stdout}
	if path != "" {
		l.file, _ = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	}
	return l
}
func (l *logger) emit(e event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	e.Sensor = "dnp3"
	e.Persona = "elbegrid-dnp3"
	e.Site = "elbegrid-substation-23"
	e.Asset = "rtu-sub23-b"
	e.Organization = "ElbeGrid Distribution"
	b, _ := json.Marshal(e)
	l.out.Write(append(b, '\n'))
	if l.file != nil {
		l.file.Write(append(b, '\n'))
	}
}

func crcDNP(data []byte) uint16 {
	crc := uint16(0)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}
func statusResponse(dst, src uint16) []byte {
	h := []byte{0x05, 0x64, 0x05, 0x8b, byte(dst), byte(dst >> 8), byte(src), byte(src >> 8)}
	c := crcDNP(h)
	return append(h, byte(c), byte(c>>8))
}
func linkFunction(control byte) string {
	return map[byte]string{0: "reset_link_states", 1: "reset_user_process", 2: "test_link_states", 3: "confirmed_user_data", 4: "unconfirmed_user_data", 9: "request_link_status"}[control&0x0f]
}

func serve(c net.Conn, log *logger) {
	defer c.Close()
	host, portText, _ := net.SplitHostPort(c.RemoteAddr().String())
	var port int
	fmt.Sscanf(portText, "%d", &port)
	c.SetReadDeadline(time.Now().Add(12 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		// Docker's healthcheck opens and immediately closes a loopback socket.
		// Keep real banner-only scans, but do not turn health probes into attacks.
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			log.emit(event{SrcIP: host, SrcPort: port, Port: 20000, Event: "connect"})
		}
		return
	}
	data := buf[:n]
	e := event{SrcIP: host, SrcPort: port, Port: 20000, Event: "frame", FrameHex: hex.EncodeToString(data)}
	if len(data) >= 8 && data[0] == 0x05 && data[1] == 0x64 {
		dst := uint16(data[4]) | uint16(data[5])<<8
		src := uint16(data[6]) | uint16(data[7])<<8
		e.DNP3Source = int(src)
		e.DNP3Destination = int(dst)
		e.Function = linkFunction(data[3])
		if e.Function == "" {
			e.Function = fmt.Sprintf("link_function_%d", data[3]&0x0f)
		}
		c.Write(statusResponse(src, dst))
	} else {
		e.Event = "malformed_frame"
	}
	log.emit(e)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		c, err := net.DialTimeout("tcp", "127.0.0.1:20000", time.Second)
		if err != nil {
			os.Exit(1)
		}
		c.Close()
		return
	}
	addr := os.Getenv("LISTEN_ADDR")
	if strings.TrimSpace(addr) == "" {
		addr = ":20000"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	// PROXY_PROTOCOL=1: fronted by portbridge with a ":pp" rule, which prepends
	// a PROXY header carrying the real attacker IP. Without it every session
	// would be logged from the WireGuard tunnel peer 10.8.0.1.
	if os.Getenv("PROXY_PROTOCOL") == "1" {
		ln = &proxyListener{ln}
	}
	log := newLogger(os.Getenv("LOG_PATH"))
	for {
		c, err := ln.Accept()
		if err == nil {
			go serve(c, log)
		}
	}
}
