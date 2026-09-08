// sonicwall-sma-honeypot — decoy for the SonicWall SMA1000 Work Place ->
// AMC SSRF+RCE chain (CVE-2026-83548 SSRF, CVE-2026-83549 AMC OS command
// injection), #3033. Same shape as citrix-honeypot and cisco-asa-honeypot:
// self-signed TLS generated fresh at startup, PROXY-protocol fronted,
// unconditional per-request logging.
//
// No vendor IOC or public PoC exists for either CVE
// (docs/research/3011-sonicwall-cve.md) -- there is no literal Work Place
// relay path or AMC command-injection parameter to match against. What is
// confirmed, and what this decoy classifies on, is the *shape* of the
// chain: a Work Place pre-auth request under /cgi-bin/ (the relay's own
// convention, matching the generic HTTP decoy's existing rce-probe bucket
// at http-honeypot/main.go:676-678) is the SSRF-shaped entry probe: stage
// one. This decoy answers it with a synthetic internal-AMC surface
// (amcHopPage) rather than an empty 200, and additionally performs one
// fixed, non-attacker-steerable outbound hop toward api-honeypot's cloud
// metadata surface (relayToAMC) so the SSRF itself is observable in this
// fleet for the first time, not just its intended destination shape. A
// follow-up request against that synthetic surface's own AMC action route
// is stage two, classified as the CVE-2026-83549 probe.
//
// This decoy never fetches an attacker-supplied URL: relayToAMC's target
// is a fixed internal address (AMC_RELAY_URL), never read from the
// request. Treating attacker input as a URL to fetch would turn this
// decoy into a real open SSRF/reflection primitive against the open
// internet -- the opposite of what a decoy is for.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

type healthcheckNoiseFilter struct{}

func (healthcheckNoiseFilter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if strings.Contains(msg, "TLS handshake error from 127.0.0.1:") && strings.HasSuffix(msg, "EOF") {
		return len(p), nil
	}
	return os.Stderr.Write(p)
}

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
	Query     string            `json:"query,omitempty"`
	Data      string            `json:"data,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
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
		stdlog.Printf("sonicwall-sma-honeypot: log file %q unavailable, continuing with stdout only: %v", path, err)
	}
	return l
}

// rotate ports multipot's/citrix-honeypot's rotate() contract -- see
// citrix-honeypot/main.go's rotate() for the full reasoning. Callers must
// hold l.mu.
func (l *logger) rotate() {
	if l.out == nil || l.path == "" {
		return
	}
	l.out.Close()
	target := l.path + "." + time.Now().UTC().Format("20060102-150405")
	if _, err := os.Stat(target); err == nil {
		for n := 2; ; n++ {
			candidate := target + "." + strconv.Itoa(n)
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
		stdlog.Printf("sonicwall-sma-honeypot: log file %q unavailable after rotation, continuing with stdout only: %v", l.path, err)
		return
	}
	l.out = f
	l.size = 0
}

func (l *logger) emit(e event) {
	e.Time = time.Now().UTC().Format(time.RFC3339)
	e.Sensor = "sonicwall-sma-honeypot"
	e.Persona = "nexusai-sonicwall-sma"
	e.Site = "nexusai-eu-edge"
	e.Asset = "smagw01"
	e.Org = "NexusAI Research GmbH"
	e.Proto = "https"
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

func getenvInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
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

type ja3ContextKey struct{}

type handler struct {
	log       *logger
	port      int
	relayURL  string
	relayHTTP *http.Client

	relayedMu sync.Mutex
	relayed   map[string]struct{}
}

// relayMarkerHeader is set on every outbound relayToAMC request so the
// resulting event in api-honeypot's own log carries evidence of its true
// origin (api-honeypot logs headers unconditionally for every request),
// making it excludable from attack-facing figures downstream without a
// fleet-wide pipeline change -- the same role LOOPBACK_IPS-based
// internal_probe marking plays for loopback health checks
// (ip_enrichment/sensors.rs), applied here at the one place that has
// certain knowledge this is a synthetic, decoy-generated hop.
const relayMarkerHeader = "X-Apiary-Relay-Source"

func (h *handler) log2(r *http.Request, kind, reqPath, data string) {
	ip, port := srcIP(r)
	hdr := headerMap(r)
	if jc, ok := r.Context().Value(ja3ContextKey{}).(*ja3Conn); ok {
		if fp := jc.JA3(); fp != "" {
			hdr["x-ja3"] = fp
		}
		if fp := jc.JA4(); fp != "" {
			hdr["x-ja4"] = fp
		}
	}
	h.log.emit(event{Port: h.port, SrcIP: ip, SrcPort: port, Event: kind, Path: reqPath, Query: r.URL.RawQuery, Data: data,
		UserAgent: r.UserAgent(), Headers: hdr})
}

func headerMap(r *http.Request) map[string]string {
	m := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		m[k] = strings.Join(v, ", ")
	}
	return m
}

// welcomeCGIPath is the Work Place login page's own form target
// (pages.go's workPlaceLoginPage). A GET here is still SSRF-shaped scanning
// (ssrfRelayPath below applies as normal), but a POST here is just an
// ordinary credential-stuffing bot submitting the decoy's own login form --
// servePOST excludes exactly that case so it doesn't misclassify as
// CVE-2026-83548 and fire the AMC relay on every login attempt.
func welcomeCGIPath(reqPath string) bool {
	return strings.ToLower(path.Clean(reqPath)) == "/cgi-bin/welcome/welcome.cgi"
}

// ssrfRelayPath recognizes the Work Place -> AMC relay's own path
// convention: a request under /cgi-bin/. This is the same substring the
// generic HTTP decoy's rce-probe bucket already matches
// (http-honeypot/main.go:676-678); a dedicated SMA decoy needs no further
// disambiguation against unrelated cgi-bin scanners the way that shared
// bucket does, because everything reaching this decoy at all is already
// presumptively SMA1000-shaped traffic.
func ssrfRelayPath(reqPath string) bool {
	return strings.HasPrefix(strings.ToLower(reqPath), "/cgi-bin/")
}

// amcActionPath recognizes a follow-up request against the synthetic AMC
// surface's own action route (amcHopPage) -- the decoy-controlled target
// stage two is expected to hit, not a guessed vendor default.
func amcActionPath(reqPath string) bool {
	return strings.ToLower(path.Clean(reqPath)) == "/cgi-bin/amc/rollbackconfirm.action"
}

// relayToAMC performs the one fixed, non-attacker-steerable outbound hop
// toward api-honeypot's cloud-metadata surface (h.relayURL), making the
// SSRF itself observable rather than only its intended destination shape.
// Best-effort: a failed hop (e.g. api-honeypot not reachable in a given
// deployment) still lets the entry probe classify and the synthetic AMC
// page serve.
//
// Limited to one hop per source IP (h.relayed): otherwise an attacker
// looping the entry probe turns this decoy into a 1:1 request amplifier
// against api-honeypot. The probe itself still classifies and responds on
// every request -- only the actual outbound relay call is capped.
func (h *handler) relayToAMC(ip string) (status int, alreadyRelayed bool, err error) {
	h.relayedMu.Lock()
	if _, done := h.relayed[ip]; done {
		h.relayedMu.Unlock()
		return 0, true, nil
	}
	h.relayed[ip] = struct{}{}
	h.relayedMu.Unlock()

	req, err := http.NewRequest(http.MethodGet, h.relayURL, nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set(relayMarkerHeader, "sonicwall-sma-honeypot")
	resp, err := h.relayHTTP.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, false, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Path

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.serveGET(w, r, reqPath)
	case http.MethodPost:
		h.servePOST(w, r, reqPath)
	default:
		h.log2(r, "method_"+strings.ToLower(r.Method), reqPath, "")
		w.Header().Set("Server", "Apache")
		w.WriteHeader(http.StatusOK)
	}
}

func (h *handler) serveGET(w http.ResponseWriter, r *http.Request, reqPath string) {
	h.log2(r, "get", reqPath, "")

	if amcActionPath(reqPath) {
		h.log2(r, "cve_2026_83549_amc_command_injection_probe", reqPath, "")
		writeApache(w, http.StatusOK, "")
		return
	}

	if ssrfRelayPath(reqPath) {
		h.log2(r, "cve_2026_83548_ssrf_probe", reqPath, "")
		ip, _ := srcIP(r)
		status, skipped, err := h.relayToAMC(ip)
		switch {
		case skipped:
			h.log2(r, "cve_2026_83548_ssrf_relay_skipped", reqPath, "relay already performed for this source, rate-limited to one hop per source IP")
		case err != nil:
			h.log2(r, "cve_2026_83548_ssrf_relay", reqPath, "relay failed: "+err.Error())
		default:
			h.log2(r, "cve_2026_83548_ssrf_relay", reqPath, "relay reached "+h.relayURL+" status="+strconv.Itoa(status))
		}
		writeApache(w, http.StatusOK, amcHopPage)
		return
	}

	writeApache(w, http.StatusOK, workPlaceLoginPage)
}

func (h *handler) servePOST(w http.ResponseWriter, r *http.Request, reqPath string) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	h.log2(r, "post", reqPath, string(body))

	if amcActionPath(reqPath) {
		h.log2(r, "cve_2026_83549_amc_command_injection_probe", reqPath, string(body))
		writeApache(w, http.StatusOK, "")
		return
	}

	if welcomeCGIPath(reqPath) {
		writeApache(w, http.StatusOK, "")
		return
	}

	if ssrfRelayPath(reqPath) {
		h.log2(r, "cve_2026_83548_ssrf_probe", reqPath, string(body))
		ip, _ := srcIP(r)
		status, skipped, err := h.relayToAMC(ip)
		switch {
		case skipped:
			h.log2(r, "cve_2026_83548_ssrf_relay_skipped", reqPath, "relay already performed for this source, rate-limited to one hop per source IP")
		case err != nil:
			h.log2(r, "cve_2026_83548_ssrf_relay", reqPath, "relay failed: "+err.Error())
		default:
			h.log2(r, "cve_2026_83548_ssrf_relay", reqPath, "relay reached "+h.relayURL+" status="+strconv.Itoa(status))
		}
		writeApache(w, http.StatusOK, amcHopPage)
		return
	}

	writeApache(w, http.StatusOK, "")
}

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
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8443", 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		conn.Close()
		return
	}

	addr := getenv("LISTEN_ADDR", ":8443")
	_, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 8443
	}

	waitForMarker("/markers/log-init.done")

	log := newLogger(getenv("LOG_FILE", "/var/log/honeypot/sonicwall-sma-honeypot.json"))

	cert, err := selfSignedCert()
	if err != nil {
		panic(err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	if getenv("PROXY_PROTOCOL", "") == "1" {
		ln = &proxyListener{ln}
	}
	ln = &ja3Listener{ln}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})

	h := &handler{
		log:      log,
		port:     port,
		relayURL: getenv("AMC_RELAY_URL", "http://10.8.0.2:18083/latest/meta-data/iam/security-credentials/worker-node"),
		relayHTTP: &http.Client{
			Timeout: 3 * time.Second,
		},
		relayed: make(map[string]struct{}),
	}

	srv := &http.Server{
		Handler:           h,
		ErrorLog:          stdlog.New(healthcheckNoiseFilter{}, "", 0),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if jc, ok := tc.NetConn().(*ja3Conn); ok {
					return context.WithValue(ctx, ja3ContextKey{}, jc)
				}
			}
			return ctx
		},
	}
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
