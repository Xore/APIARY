// http-honeypot — a low-interaction web honeypot that presents as a plain
// nginx server and logs everything an attacker throws at it.
//
// Design goals:
//   - Look like a boring, real box: default nginx landing page, an nginx
//     Server header, realistic 404s. Nothing says "honeypot".
//   - Bait the paths scanners always try (/.env, /.git/config, wp-login,
//     phpMyAdmin, Tomcat manager, …) with plausible responses so the attacker
//     keeps going and we capture more of their playbook.
//   - Record every request as one JSON line: method, path, query, headers,
//     body, and any submitted / basic-auth credentials.
//
// It never executes anything and holds no real data. Keep it on an isolated
// Docker network (see docker-compose.yml) so it can only ever be a sensor.
package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
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
	SrcIP     string            `json:"src_ip"`
	Method    string            `json:"method"`
	Host      string            `json:"host"`
	Path      string            `json:"path"`
	Query     string            `json:"query,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
	Username  string            `json:"username,omitempty"`
	Password  string            `json:"password,omitempty"`
	AuthType  string            `json:"auth_type,omitempty"`
	Status    int               `json:"status"`
	Category  string            `json:"category"`
}

type logger struct {
	mu   sync.Mutex
	out  io.Writer
	f    *os.File
	path string
	size int64
	max  int64
}

func newLogger(path string) *logger {
	// #120: same fix as multipot's logger -- this file is exempt from
	// analysis/log-maintenance.sh's copytruncate (JSON event streams need
	// Filebeat's inode/offset tracking to stay intact, per #79), so nothing
	// else bounds its size. Rotate the way Suricata's rotate-interval does:
	// close, rename aside, reopen fresh at the same path.
	l := &logger{out: os.Stdout, path: path, max: getenvInt64("LOG_MAX_BYTES", 67108864)}
	if path != "" {
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
			l.f = f
			if st, err := f.Stat(); err == nil {
				l.size = st.Size()
			}
		}
	}
	return l
}

// rotate closes the current file, renames it aside with a timestamp suffix,
// and reopens a fresh file at the original path. Filebeat's file_identity
// defaults to inode/device, not path, so its harvester stays attached to the
// renamed file through EOF; the fresh file is picked up by the same glob
// that already covers the original name. Callers must hold l.mu.
func (l *logger) rotate() {
	if l.f == nil || l.path == "" {
		return
	}
	l.f.Close()
	stamp := time.Now().UTC().Format("20060102-150405")
	os.Rename(l.path, l.path+"."+stamp)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		l.f = nil
		return
	}
	l.f = f
	l.size = 0
}

func (l *logger) log(e event) {
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Write(line)
	l.out.Write([]byte("\n"))
	if l.f != nil {
		if l.max > 0 && l.size >= l.max {
			l.rotate()
		}
		if l.f != nil {
			n1, _ := l.f.Write(line)
			n2, _ := l.f.Write([]byte("\n"))
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

// waitForMarker blocks until path exists, polling every 3s. See #128.
func waitForMarker(path string) {
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

// tunnelPeerIP is the WireGuard address of the VPS edge. Requests arriving
// from it came through Traefik -> socat (Traefik sets X-Forwarded-For) or
// through a raw portbridge rule without ":pp". Only from that peer may
// X-Forwarded-For be consulted; everywhere else it is attacker-controlled.
const tunnelPeerIP = "10.8.0.1"

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// Behind a ":pp" portbridge rule the PROXY-aware listener has already
	// rewritten RemoteAddr to the real attacker address — it wins over any
	// header. Traefik-routed requests still show the tunnel peer, so take the
	// first XFF hop Traefik recorded.
	if host == tunnelPeerIP {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	return host
}

func headerMap(r *http.Request) map[string]string {
	m := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		m[k] = strings.Join(v, ", ")
	}
	return m
}

// classify guesses the intent of a request path so logs are easy to triage.
func classify(path string) string {
	p := strings.ToLower(path)
	switch {
	case p == "/" || p == "/index.html":
		return "landing"
	case strings.Contains(p, ".env"), strings.Contains(p, ".git"),
		strings.Contains(p, ".aws"), strings.Contains(p, "config"),
		strings.Contains(p, "credential"), strings.Contains(p, "secret"):
		return "secret-hunt"
	case strings.Contains(p, "wp-login"), strings.Contains(p, "wp-admin"),
		strings.Contains(p, "xmlrpc"), strings.Contains(p, "wp-content"),
		strings.Contains(p, "/readme.html"):
		return "wordpress"
	case strings.Contains(p, "phpmyadmin"), strings.Contains(p, "pma"),
		strings.Contains(p, "adminer"):
		return "db-admin"
	case strings.Contains(p, "manager/html"), strings.Contains(p, "jmx"):
		return "tomcat"
	case strings.Contains(p, "login"), strings.Contains(p, "admin"),
		strings.Contains(p, "signin"):
		return "login-probe"
	case strings.Contains(p, "cgi-bin"), strings.Contains(p, "shell"),
		strings.Contains(p, "boaform"), strings.Contains(p, "hnap"):
		return "rce-probe"
	case strings.Contains(p, "latest/meta-data"), strings.Contains(p, "computemetadata"),
		strings.Contains(p, "metadata/instance"):
		return "cloud-metadata"
	case strings.HasPrefix(p, "/api/v1/"), strings.HasPrefix(p, "/apis/"), p == "/version":
		return "kubernetes-api"
	case strings.HasPrefix(p, "/v1/models"), strings.HasPrefix(p, "/v1/chat"),
		strings.Contains(p, "openai"):
		return "llm-api"
	case p == "/v2/" || strings.Contains(p, "docker"):
		return "container-registry"
	case strings.Contains(p, "jenkins"), strings.Contains(p, "grafana"),
		strings.Contains(p, "actuator"):
		return "devops-admin"
	default:
		return "scan"
	}
}

type server struct {
	log       *logger
	sensor    string
	serverHdr string
	persona   string
	site      string
	asset     string
	org       string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10)) // cap at 64 KiB
	r.Body.Close()

	e := event{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Sensor:    s.sensor,
		Persona:   s.persona,
		Site:      s.site,
		Asset:     s.asset,
		Org:       s.org,
		SrcIP:     clientIP(r),
		Method:    r.Method,
		Host:      r.Host,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		UserAgent: r.UserAgent(),
		Headers:   headerMap(r),
		Body:      string(body),
		Category:  classify(r.URL.Path),
	}

	// Pull credentials from HTTP Basic auth …
	if u, p, ok := r.BasicAuth(); ok {
		e.Username, e.Password, e.AuthType = u, p, "basic"
	} else if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Basic ") {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a, "Basic ")); err == nil {
			if u, p, found := strings.Cut(string(raw), ":"); found {
				e.Username, e.Password, e.AuthType = u, p, "basic"
			}
		}
	}
	if e.AuthType == "" {
		if scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok &&
			strings.EqualFold(scheme, "Bearer") && token != "" {
			e.Username, e.Password, e.AuthType = "bearer", token, "bearer"
		}
	}
	// … or from a submitted login form.
	if e.Username == "" && len(body) > 0 && strings.Contains(r.Header.Get("Content-Type"), "form-urlencoded") {
		if vals, err := parseForm(string(body)); err == nil {
			e.Username = firstNonEmpty(vals, "username", "user", "login", "email", "name", "uname")
			e.Password = firstNonEmpty(vals, "password", "pass", "passwd", "pwd")
			if e.Username != "" || e.Password != "" {
				e.AuthType = "form"
			}
		}
	}

	s.serve(w, r, &e)
	s.log.log(e)
}

// serve writes a plausible response and records the status code onto e.
func (s *server) serve(w http.ResponseWriter, r *http.Request, e *event) {
	w.Header().Set("Server", s.serverHdr)
	p := strings.ToLower(r.URL.Path)

	switch {
	case p == "/" || p == "/index.html":
		e.Status = http.StatusOK
		if s.sensor == "api-honeypot" {
			writeJSON(w, http.StatusOK, `{"service":"nexusai-platform-gateway","environment":"production","region":"europe-west3","status":"ok"}`)
		} else {
			writeHTML(w, http.StatusOK, nginxWelcome)
		}

	case p == "/robots.txt":
		e.Status = http.StatusOK
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "User-agent: *\nDisallow:\n")

	case strings.HasPrefix(p, "/latest/meta-data/iam/security-credentials/worker-node"):
		e.Status = http.StatusOK
		writeJSON(w, http.StatusOK, `{"Code":"Success","LastUpdated":"2026-07-20T16:00:00Z","Type":"AWS-HMAC","AccessKeyId":"ASIAFAKEDECOY000000","SecretAccessKey":"fake-honeypot-secret-not-valid","Token":"fake-decoy-session-token","Expiration":"2026-07-21T00:00:00Z"}`)

	case strings.HasPrefix(p, "/latest/meta-data/iam/security-credentials"):
		e.Status = http.StatusOK
		writeText(w, http.StatusOK, "worker-node\n")

	case strings.HasPrefix(p, "/latest/meta-data"):
		e.Status = http.StatusOK
		writeText(w, http.StatusOK, "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\nplacement/\n")

	case strings.HasPrefix(p, "/computeMetadata/v1"), strings.HasPrefix(p, "/metadata/instance"):
		e.Status = http.StatusOK
		writeJSON(w, http.StatusOK, `{"instance":{"id":"7842391029384756","name":"platform-gw-03","zone":"europe-west3-a","machineType":"e2-standard-8"},"project":{"projectId":"nexusai-production"}}`)

	case p == "/version":
		e.Status = http.StatusOK
		writeJSON(w, http.StatusOK, `{"major":"1","minor":"29","gitVersion":"v1.29.6-gke.1326000","gitCommit":"a3c1f7d83bbf","platform":"linux/amd64"}`)

	case strings.HasPrefix(p, "/api/v1/"), strings.HasPrefix(p, "/apis/"):
		e.Status = http.StatusForbidden
		writeJSON(w, http.StatusForbidden, `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"forbidden: User system:anonymous cannot access this resource","reason":"Forbidden","code":403}`)

	case p == "/v2/":
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.registry.nexusai.internal/token",service="registry.nexusai.internal"`)
		e.Status = http.StatusUnauthorized
		writeJSON(w, http.StatusUnauthorized, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`)

	case strings.HasPrefix(p, "/v1/models"), strings.HasPrefix(p, "/v1/chat/completions"):
		if e.AuthType != "bearer" {
			e.Status = http.StatusUnauthorized
			writeJSON(w, http.StatusUnauthorized, `{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","code":"invalid_api_key"}}`)
		} else {
			e.Status = http.StatusOK
			writeJSON(w, http.StatusOK, `{"object":"list","data":[{"id":"nexusai-chat-70b-v3","object":"model","owned_by":"nexusai-mlops"},{"id":"nexusai-embed-bge-v1","object":"model","owned_by":"nexusai-mlops"}]}`)
		}

	case strings.HasPrefix(p, "/manager/html") || strings.Contains(p, "jmx-console"):
		// Tomcat manager — challenge for Basic auth so scanners submit creds.
		if e.AuthType == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			e.Status = http.StatusUnauthorized
			writeHTML(w, http.StatusUnauthorized, tomcat401)
		} else {
			e.Status = http.StatusForbidden
			writeHTML(w, http.StatusForbidden, tomcat403)
		}

	case strings.Contains(p, "wp-login") || strings.Contains(p, "wp-admin"):
		e.Status = http.StatusOK
		writeHTML(w, http.StatusOK, wpLogin)

	case strings.HasSuffix(p, "/readme.html") || p == "/readme.html":
		e.Status = http.StatusOK
		writeHTML(w, http.StatusOK, wpReadme)

	case strings.Contains(p, "xmlrpc.php"):
		if r.Method != http.MethodPost {
			e.Status = http.StatusOK
			writeText(w, http.StatusOK, "XML-RPC server accepts POST requests only.")
			break
		}
		// The request body (already captured onto e.Body by ServeHTTP) is
		// where a real system.multicall/pingback exploitation attempt shows
		// up -- this only needs to look like a real XML-RPC endpoint that
		// rejected the call, not actually parse or dispatch one.
		e.Status = http.StatusOK
		w.Header().Set("Content-Type", "text/xml; charset=UTF-8")
		writeHTML(w, http.StatusOK, wpXMLRPCFault)

	case strings.Contains(p, "/wp-content/plugins/duplicator/") && strings.HasSuffix(p, "readme.txt"):
		// CVE-2020-11738 (Duplicator arbitrary file read/RCE via installer.php)
		// -- a real mass-scanned plugin, version deliberately pre-fix.
		e.Status = http.StatusOK
		writeText(w, http.StatusOK, wpPluginReadme("Duplicator", "1.3.26"))

	case strings.Contains(p, "/wp-content/plugins/wp-file-manager/") && strings.HasSuffix(p, "readme.txt"):
		// CVE-2020-25213 (File Manager unauthenticated arbitrary file
		// upload/RCE) -- another real mass-scanned plugin, version
		// deliberately pre-fix.
		e.Status = http.StatusOK
		writeText(w, http.StatusOK, wpPluginReadme("WP File Manager", "6.0"))

	case strings.HasPrefix(p, "/wp-content/"):
		// Any other plugin/theme/upload path: a real WordPress install
		// serves its own 404 here (Apache/nginx directory listing is
		// normally disabled), not the generic landing 404 below -- kept
		// distinct in case a future plugin gets its own case above.
		e.Status = http.StatusNotFound
		writeHTML(w, http.StatusNotFound, nginx404)

	case strings.Contains(p, "phpmyadmin") || strings.Contains(p, "/pma") || strings.Contains(p, "adminer"):
		e.Status = http.StatusOK
		writeHTML(w, http.StatusOK, phpMyAdmin)

	case strings.Contains(p, "login") || strings.Contains(p, "admin") || strings.Contains(p, "signin"):
		// Generic login page. Posted creds are already captured above.
		e.Status = http.StatusOK
		writeHTML(w, http.StatusOK, genericLogin)

	case strings.HasSuffix(p, ".env") || strings.Contains(p, ".git/") ||
		strings.Contains(p, ".aws") || strings.HasSuffix(p, ".yml") ||
		strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".bak"):
		// Pretend these secrets simply aren't there.
		e.Status = http.StatusNotFound
		writeHTML(w, http.StatusNotFound, nginx404)

	default:
		e.Status = http.StatusNotFound
		writeHTML(w, http.StatusNotFound, nginx404)
	}
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func parseForm(body string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(body, "&") {
		k, v, _ := strings.Cut(pair, "=")
		out[strings.ToLower(urlDecode(k))] = urlDecode(v)
	}
	return out, nil
}

func urlDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			var hi, lo byte
			if unhex(s[i+1], &hi) && unhex(s[i+2], &lo) {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte, out *byte) bool {
	switch {
	case c >= '0' && c <= '9':
		*out = c - '0'
	case c >= 'a' && c <= 'f':
		*out = c - 'a' + 10
	case c >= 'A' && c <= 'F':
		*out = c - 'A' + 10
	default:
		return false
	}
	return true
}

func firstNonEmpty(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func main() {
	// -healthcheck: used by the scratch image's Docker HEALTHCHECK.
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		addr := getenv("LISTEN_ADDR", ":8080")
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		client := http.Client{Timeout: 3 * time.Second}
		// / always answers 200; any error means we are unhealthy.
		if resp, err := client.Get("http://" + addr + "/"); err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// #128: same-project depends_on: condition: service_completed_successfully
	// against a shim can't reach honeypot-init (different Compose project),
	// so every other service in this stack waits on honeypot-init's
	// completion marker directly instead -- normally via an entrypoint:
	// wrapper, but this image is FROM scratch with no shell to wrap with,
	// so the wait lives here instead.
	waitForMarker("/markers/log-init.done")

	// PROXY_PROTOCOL=1: fronted by portbridge with a ":pp" rule, which prepends
	// a PROXY header carrying the real attacker IP. The listener sniffs the
	// header, so Traefik-routed requests (no PROXY header, peer 10.8.0.1) keep
	// working too; clientIP decides per request whether XFF may be trusted.
	proxy := getenv("PROXY_PROTOCOL", "") == "1"

	s := &server{
		log:       newLogger(getenv("LOG_FILE", "/var/log/honeypot/http.json")),
		sensor:    getenv("SENSOR_NAME", "http-honeypot"),
		serverHdr: getenv("SERVER_HEADER", "nginx/1.24.0 (Ubuntu)"),
		persona:   getenv("PERSONA_ID", "nexusai-edge"),
		site:      getenv("SITE_ID", "nexusai-eu-edge"),
		asset:     getenv("ASSET_ID", "web-edge-01"),
		org:       getenv("ORGANIZATION", "NexusAI Research GmbH"),
	}

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		os.Exit(1)
	}
	if proxy {
		ln = &proxyListener{ln}
	}
	s.log.log(event{
		Time:     time.Now().UTC().Format(time.RFC3339),
		Sensor:   s.sensor,
		Persona:  s.persona,
		Site:     s.site,
		Asset:    s.asset,
		Org:      s.org,
		Category: "startup",
		Status:   0,
		Path:     "listening on " + addr,
	})
	if err := srv.Serve(ln); err != nil {
		os.Exit(1)
	}
}
