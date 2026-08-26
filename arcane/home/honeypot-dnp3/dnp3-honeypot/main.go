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
	SrcIP, Event, FrameHex, Function, AppFunction    string
	Data                                             string
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
		AppFunction     string `json:"app_function,omitempty"`
		Data            string `json:"data,omitempty"`
		DNP3Source      int    `json:"dnp3_source,omitempty"`
		DNP3Destination int    `json:"dnp3_destination,omitempty"`
	}
	return json.Marshal(record{e.Time, e.Sensor, e.Persona, e.Site, e.Asset, e.Organization, e.SrcIP, e.SrcPort, e.Port, e.Event, e.FrameHex, e.Function, e.AppFunction, e.Data, e.DNP3Source, e.DNP3Destination})
}

type logger struct {
	out  io.Writer
	file *os.File
	mu   sync.Mutex
}

func newLogger(path string) *logger {
	l := &logger{out: os.Stdout}
	if path != "" {
		var err error
		l.file, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnp3-honeypot: log file %q unavailable, continuing with stdout only: %v\n", path, err)
		}
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

// applicationFunctionCodes maps DNP3 application-layer function codes
// (IEEE 1815 Table 4-1) to names -- the request codes an operator most
// wants surfaced (READ/WRITE/SELECT/OPERATE/DIRECT_OPERATE and the restart
// family) alongside the two response codes, so a reply frame this honeypot
// never actually sends still decodes sensibly if ever fed one in a test.
var applicationFunctionCodes = map[byte]string{
	0x00: "confirm", 0x01: "read", 0x02: "write", 0x03: "select", 0x04: "operate",
	0x05: "direct_operate", 0x06: "direct_operate_no_ack",
	0x07: "immed_freeze", 0x08: "immed_freeze_no_ack",
	0x09: "freeze_clear", 0x0a: "freeze_clear_no_ack",
	0x0b: "freeze_at_time", 0x0c: "freeze_at_time_no_ack",
	0x0d: "cold_restart", 0x0e: "warm_restart",
	0x0f: "initialize_data", 0x10: "initialize_application",
	0x11: "start_application", 0x12: "stop_application",
	0x13: "save_configuration",
	0x14: "enable_unsolicited", 0x15: "disable_unsolicited",
	0x16: "assign_class", 0x17: "delay_measure", 0x18: "record_current_time",
	0x19: "open_file", 0x1a: "close_file", 0x1b: "delete_file",
	0x1c: "get_file_info", 0x1d: "authenticate_file", 0x1e: "abort_file",
	0x1f: "activate_config",
	0x20: "authenticate_req", 0x21: "authenticate_req_no_ack",
	0x81: "response", 0x82: "unsolicited_response", 0x83: "authenticate_resp",
}

// appFunctionCode extracts the application-layer function code from a DNP3
// frame, if present. Beyond the 10-byte link header (start bytes, length,
// control, destination, source, CRC) comes a 1-byte transport header then
// a 2-byte application control header, then the 1-byte function code --
// offset 12. Frames without a full transport+app segment (link-layer-only
// traffic, which is most of what this low-interaction honeypot's static
// reply provokes -- see #610) simply have nothing to decode here.
func appFunctionCode(data []byte) (string, bool) {
	if len(data) <= 12 {
		return "", false
	}
	code := data[12]
	if name, ok := applicationFunctionCodes[code]; ok {
		return name, true
	}
	return fmt.Sprintf("app_function_%d", code), true
}

func serve(c net.Conn, log *logger) {
	host, portText, _ := net.SplitHostPort(c.RemoteAddr().String())
	var port int
	fmt.Sscanf(portText, "%d", &port)
	// #2186: serve() is the whole world past Accept -- raw link/application
	// frames are decoded straight off the socket here with no recover
	// anywhere downstream, and in Go one unrecovered panic kills the entire
	// sensor while restart: unless-stopped hands the attacker the same
	// replayable bytes right back. http-honeypot gets this shield per
	// request from net/http; the low-interaction listener carries it itself,
	// at the top of the per-connection entrypoint: a panicking connection is
	// closed and lands in the normal JSON pipeline as one handler_panic
	// event while the accept loop and every other live connection keep
	// running.
	defer func() {
		if r := recover(); r != nil {
			log.emit(event{SrcIP: host, SrcPort: port, Port: 20000, Event: "handler_panic", Data: fmt.Sprint(r)})
		}
	}()
	defer c.Close()
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
		if app, ok := appFunctionCode(data); ok {
			e.AppFunction = app
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

	// #128: same-project depends_on: condition: service_completed_successfully
	// against a shim can't reach honeypot-init (different Compose project),
	// so every other service in this stack waits on honeypot-init's
	// completion marker directly instead -- normally via an entrypoint:
	// wrapper, but this image is FROM scratch with no shell to wrap with,
	// so the wait lives here instead.
	waitForMarker("/markers/log-init.done")

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

// waitForMarker blocks until path exists, polling every 3s. See #128.
func waitForMarker(path string) {
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}
