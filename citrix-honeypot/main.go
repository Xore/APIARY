// citrix-honeypot — Go port of t3chn0m4g3/CitrixHoneypot (#238, #414): a
// Citrix ADC/NetScaler Gateway decoy for CVE-2019-19781 (path traversal ->
// arbitrary file read / RCE via newbm.pl). Confirmed directly against
// upstream's CitrixHoneypot.py (160 lines) before porting -- genuinely
// simple, no third-party protocol library involved, unlike the Cisco ASA
// IKE side of this same issue.
//
// Presents its own self-signed TLS certificate (generated fresh at
// startup, not baked into the image) rather than terminating TLS at
// Traefik/portbridge: a real vulnerable Gateway appliance does the same,
// and a certificate handed out by a shared front proxy would itself be a
// fingerprinting tell that this isn't a real edge device.
package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
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
	Path    string `json:"path,omitempty"`
	Data    string `json:"data,omitempty"`
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
	e.Sensor = "citrix-honeypot"
	e.Persona = "nexusai-citrix-gw"
	e.Site = "nexusai-eu-edge"
	e.Asset = "citrixgw01"
	e.Org = "NexusAI Research GmbH"
	e.Proto = "https"
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

func srcIP(r *http.Request) (string, int) {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// handler ports CitrixHandler.do_GET / do_POST. url_path/collapsed_path
// terminology matches upstream's own variable names in comments below so
// the two can be compared side by side.
type handler struct {
	log  *logger
	port int
}

func (h *handler) log2(r *http.Request, kind, reqPath, data string) {
	ip, port := srcIP(r)
	h.log.emit(event{Port: h.port, SrcIP: ip, SrcPort: port, Event: kind, Path: reqPath, Data: data})
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// http.Request.URL.Path is already unescaped by net/http, matching
	// upstream's urllib.parse.unquote(self.path).
	reqPath := r.URL.Path

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.serveGET(w, r, reqPath)
	case http.MethodPost:
		h.servePOST(w, r, reqPath)
	default:
		w.Header().Set("Server", "Apache")
		w.WriteHeader(http.StatusOK)
	}
}

func (h *handler) serveGET(w http.ResponseWriter, r *http.Request, reqPath string) {
	h.log2(r, "get", reqPath, "")

	urlParts := splitNonEmpty(reqPath)
	if len(urlParts) == 0 || (len(urlParts) == 1 && urlParts[0] == "vpn") {
		writeApache(w, http.StatusOK, citrixLoginPage)
		return
	}

	// Only proceed if a directory traversal was attempted -- literal
	// "/../ ", checked on the already-unescaped path, exactly like upstream.
	if strings.Contains(reqPath, "/../") {
		collapsed := path.Clean(reqPath)
		collapsedParts := splitNonEmpty(collapsed)

		if len(collapsedParts) >= 1 && collapsedParts[0] == "vpns" {
			switch {
			case len(collapsedParts) == 1:
				h.log2(r, "cve_2019_19781_scan_type1", collapsed, "")
				body := strings.ReplaceAll(citrix403Page, "{url}", collapsed)
				writeApache(w, http.StatusForbidden, body)
				return
			case len(collapsedParts) >= 2 && collapsedParts[1] == "portal":
				h.log2(r, "cve_2019_19781_completion", collapsed, "")
				writeApache(w, http.StatusOK, "")
				return
			case collapsed == "/vpns/cfg/smb.conf":
				h.log2(r, "cve_2019_19781_scan_type2", collapsed, "")
				writeApache(w, http.StatusOK, citrixSmbConf)
				return
			default:
				h.log2(r, "cve_2019_19781_scan_unhandled", collapsed, "")
				writeApache(w, http.StatusOK, "")
				return
			}
		}
	}

	writeApache(w, http.StatusOK, "")
}

func (h *handler) servePOST(w http.ResponseWriter, r *http.Request, reqPath string) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	h.log2(r, "post", reqPath, string(body))

	if len(body) > 0 && path.Clean(reqPath) == "/vpns/portal/scripts/newbm.pl" {
		if form, err := url.ParseQuery(string(body)); err == nil {
			if title := form.Get("title"); title != "" {
				h.log2(r, "cve_2019_19781_payload", reqPath, title)
			}
		}
	}

	writeApache(w, http.StatusOK, "")
}

// splitNonEmpty mirrors Python's `filter(None, path.split('/'))`.
func splitNonEmpty(p string) []string {
	var out []string
	for _, part := range strings.Split(p, "/") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// writeApache matches upstream's send_response(): a bare "Server: Apache"
// header and nothing else Go's http.Server would normally add.
func writeApache(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Server", "Apache")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(code)
	if body != "" {
		w.Write([]byte(body))
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		conn, err := tls.Dial("tcp", "127.0.0.1:443", &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			os.Exit(1)
		}
		conn.Close()
		return
	}

	addr := getenv("LISTEN_ADDR", ":443")
	_, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 443
	}

	waitForMarker("/markers/log-init.done")

	log := newLogger(getenv("LOG_FILE", "/var/log/honeypot/citrix-honeypot.json"))

	cert, err := selfSignedCert()
	if err != nil {
		panic(err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	// PROXY_PROTOCOL=1: fronted by portbridge with a ":pp" rule, which
	// prepends a PROXY header carrying the real attacker IP.
	if getenv("PROXY_PROTOCOL", "") == "1" {
		ln = &proxyListener{ln}
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})

	srv := &http.Server{Handler: &handler{log: log, port: port}}
	log.emit(event{Port: port, Event: "listening"})
	if err := srv.Serve(tlsLn); err != nil {
		panic(err)
	}
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
