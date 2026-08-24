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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type event struct {
	Time    string `json:"time"`
	Sensor  string `json:"sensor"`
	Persona string `json:"persona_id"`
	Site    string `json:"site_id"`
	Asset   string `json:"asset_id"`
	Org     string `json:"organization"`
	SrcIP   string `json:"src_ip"`
	// #1889: the connection's ports, so the event can be joined to the
	// flow every other sensor's can. Without them Community ID cannot be
	// computed -- it needs (src_ip, src_port, dst_ip, dst_port, proto) --
	// and measured over seven days 0 of 174,384 events here carried one.
	// That closes off correlation with Suricata's alert for the same
	// request, with Zeek and huginn's records of the same connection, and
	// the flow pivot in #1783, for the highest-volume HTTP sensor there is.
	//
	// SrcPort is omitted rather than guessed when the peer is a relay: see
	// clientPort. A wrong port is worse than an absent one, because a
	// Community ID computed from it is a confident hash of the wrong tuple.
	SrcPort   int               `json:"src_port,omitempty"`
	DstPort   int               `json:"dst_port,omitempty"`
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
	// What the request *carried*, as opposed to what it asked for (#1888).
	// Separate from Category on purpose: a POST of an SQL injection to a
	// WordPress bait path is both a "wordpress" request and an "sqli"
	// payload, and collapsing them into one field loses whichever was
	// written second.
	PayloadClass string `json:"payload_class,omitempty"`
	// Tarpitted (#246) marks a request that got the slow Markov-drip
	// response (tarpit.go) instead of a normal reply. TarpitBytes/
	// TarpitMS are only meaningful when this is true.
	Tarpitted   bool  `json:"tarpitted,omitempty"`
	TarpitBytes int   `json:"tarpit_bytes,omitempty"`
	TarpitMS    int64 `json:"tarpit_ms,omitempty"`
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
		} else {
			fmt.Fprintf(os.Stderr, "http-honeypot: log file %q unavailable, continuing with stdout only: %v\n", path, err)
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
		fmt.Fprintf(os.Stderr, "http-honeypot: log file %q unavailable after rotation, continuing with stdout only: %v\n", l.path, err)
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
	// header. Traefik-routed requests still show the tunnel peer, so fall
	// back to the forwarding chain there.
	//
	// That fallback used to take the chain's last hop, reasoning that
	// Cloudflare APPENDS the real client to any XFF the client already
	// sent rather than replacing it, so an attacker's own value stays
	// leftmost and spoofable while the rightmost is Cloudflare's. The
	// first half is right; the conclusion is not. Traefik sits between
	// Cloudflare and this sensor and appends the peer *it* saw, which is a
	// Cloudflare edge node -- so the chain ends one hop past the answer.
	// Measured on a live request through the fleet's own subdomain:
	// `X-Forwarded-For: <client>, 172.69.150.126`. Every proxied request
	// was being filed against Cloudflare (#1908).
	//
	// CF-Connecting-IP is the direct answer where Cloudflare set it: one
	// value, the client, with no chain to index into. Otherwise take the
	// second-to-last hop, the entry Cloudflare itself appended. Both stay
	// sound against a pre-seeded header, since whatever the client writes
	// remains to the left of what Cloudflare appends.
	//
	// Unlike galah, wordpot and hellpot, the guard above is a real
	// discriminator here rather than a guess: this sensor's raw port is a
	// ":pp" rule, so RemoteAddr is the attacker on that path and being the
	// tunnel peer genuinely does mean "came through Traefik". #1908 split
	// the others onto separate ports to earn the same property.
	if host == tunnelPeerIP {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			return cf
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			hops := strings.Split(xff, ",")
			idx := len(hops) - 1
			if len(hops) >= 2 {
				idx = len(hops) - 2
			}
			return strings.TrimSpace(hops[idx])
		}
	}
	return host
}

// clientPort is the attacker's own source port, or 0 when this request
// reached us through a relay that replaced it (#1889).
//
// The distinction is the same one clientIP makes. Behind a ":pp"
// portbridge rule the PROXY-aware listener has rewritten RemoteAddr to the
// real client, address and port together, so the port is genuinely theirs.
// On the Traefik path RemoteAddr is the tunnel peer and the port belongs
// to socat's outbound connection -- reporting that as the attacker's port
// would produce a Community ID that hashes a tuple no packet ever had, and
// would join this event to somebody else's flow.
//
// Absent is the honest answer there, so 0 and `omitempty`.
func clientPort(r *http.Request) int {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == tunnelPeerIP {
		return 0
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return value
}

// listenPort is the port this sensor was reached on -- the destination
// half of the tuple. Read from the address the server was configured with
// rather than from the request, which does not carry it.
func listenPort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return value
}

func headerMap(r *http.Request) map[string]string {
	m := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		m[k] = strings.Join(v, ", ")
	}
	return m
}

// classifyPayload names what a request carried, from its query string and
// body. Empty when nothing recognisable is there, which is most traffic.
//
// Patterns rather than a model, and that is a measurement rather than a
// preference (#1809, #1888). Over 30 days the fleet saw 11,139 requests
// carrying a body or a query and 583 distinct values between them -- and
// that count is itself inflated, because ~19 events each of an otherwise
// identical multipart probe differ only by their random
// WebKitFormBoundary. One payload, CVE-2017-9841's PHPUnit probe, is a
// quarter of the corpus by itself. A corpus that small and that repetitive
// is a lookup table; the model argument only becomes real if a month ever
// starts yielding thousands of genuinely new payloads instead of a
// handful.
//
// The order is specific-to-generic, and the first match wins. Real
// payloads nest -- the second most common body here is a <?php wrapper
// around a base64 blob that decodes to a wget|sh chain, which is three of
// these classes at once -- so the outermost, most identifying shape is
// checked first. The raw body is stored regardless, so nothing is lost by
// naming only one.
//
// Counts in the comments come from running this function over that whole
// window rather than over examples, which is also how the one surprising
// result was checked rather than assumed: command-injection labels 4,273
// events across 270 distinct bodies, far more than anything else except
// the PHPUnit probe. Sampling them showed it is right -- they are 5 KB
// multipart bodies whose padding hides a `id; hostname; pwd` passed to a
// Node child_process, so the class is one campaign rather than a leaky
// pattern.
//
// A pattern that fires on ordinary traffic is worse than no pattern, since
// it makes every event look interesting. The classes are deliberately
// narrow and the tail is left unlabelled: 92.5% of the window is named,
// and what remains is scanner cache-busting like "v=GyJrG" and "id=3",
// which has no class worth giving it.
func classifyPayload(query, body string) string {
	// Query strings arrive percent-encoded, and attackers vary the
	// encoding of the same probe to slip signatures -- the PHP-CGI probe
	// below appears as %ADd, %25ADd and plain -d in the same window. Match
	// on the decoded form, falling back to the raw one when it will not
	// decode, so a deliberately malformed escape cannot hide a payload.
	decoded := query
	if unescaped, err := url.QueryUnescape(query); err == nil {
		decoded = unescaped
	}
	q := strings.ToLower(decoded)
	b := strings.ToLower(body)
	both := q + "\n" + b

	switch {
	// --- named exploit chains, most identifying first ---

	// 390 events. CVE-2012-1823 / CVE-2024-4577: turns php-cgi's argument
	// handling into "execute the request body as PHP".
	case strings.Contains(q, "allow_url_include") && strings.Contains(q, "auto_prepend_file"):
		return "php-cgi-argument-injection"

	// 162 events. ThinkPHP's invokefunction routing gadget: the callable
	// and its arguments are both in the query.
	case strings.Contains(q, "invokefunction") && strings.Contains(q, "call_user_func_array"):
		return "thinkphp-rce"

	// 81 events. Traversal to PEAR's CLI, which is then told to write a
	// PHP file -- local file inclusion escalated to code execution.
	case strings.Contains(q, "pearcmd") && strings.Contains(q, "config-create"):
		return "pearcmd-rce"

	// Log4Shell and its JNDI relatives; the lookup syntax is unambiguous.
	case strings.Contains(both, "${jndi:"):
		return "jndi-lookup"

	// --- code the request wants run ---

	// 390 events across two variants, both wrapping a base64 blob in a
	// shell call. Checked before the bare <?php case, which would
	// otherwise swallow it.
	case containsAny(b, "shell_exec", "system(", "passthru", "popen(", "proc_open") &&
		strings.Contains(b, "base64_decode"):
		return "php-base64-shell"

	// 2,918 events -- CVE-2017-9841's eval-stdin.php probe is a quarter of
	// the whole corpus on its own, and it is simply PHP source in a body.
	case strings.Contains(b, "<?php"), strings.Contains(b, "<?="):
		return "php-code"

	// 58 events. Fetch a stage-two script and pipe it straight to a shell.
	case containsAny(both, "wget ", "curl ") && containsAny(both, "|sh", "| sh", "|bash", "| bash", "-qo-", "-so-"):
		return "downloader"

	// 45 events. A shell command reachable from the request, which needs
	// both a way to start one and something to run -- see shellCommand.
	case shellCommand(both):
		return "command-injection"

	// --- what the request wants to read or become ---

	// 26 events. Straight to the credential files, no execution needed.
	case containsAny(both, "/root/.aws/credentials", "/etc/passwd", "/etc/shadow", ".ssh/id_rsa", "/.env"):
		return "secret-read"

	// 81 events. Traversal on its own, once the escalations above have had
	// their turn.
	case strings.Contains(both, "../../"), strings.Contains(both, "..%2f"), strings.Contains(both, `..\..\`):
		return "path-traversal"

	// 171 events. Creating an administrator through an API that should not
	// allow it -- persistence rather than a smash-and-grab.
	case strings.Contains(b, "roleid") && strings.Contains(b, "administrator"):
		return "admin-account-create"

	// --- injection into an interpreter that is already running ---

	case containsAny(b, "union select", "or 1=1", "' or '", "sleep(", "benchmark(", "waitfor delay"):
		return "sqli"

	// 19 events. React/Next.js server actions reached through a multipart
	// body; the marker is the polluted key, not the transport.
	case containsAny(b, "__proto__", "constructor.prototype"):
		return "prototype-pollution"

	case containsAny(b, "<!entity") && strings.Contains(b, "system"):
		return "xxe"

	// Template expression syntax paired with something worth evaluating.
	// Deliberately narrow: braces alone are ordinary in JSON, and "{{name}}"
	// in a template field is not an attack.
	case containsAny(b, "{{", "${", "#{") &&
		containsAny(b, "7*7", "runtime.", "getruntime", "class.forname", "__import__", "self.__", "process.env"):
		return "template-injection"

	// --- probes that carry a payload without exploiting anything ---

	// 50 events. ONVIF device discovery -- cameras and recorders.
	case strings.Contains(b, "soap-envelope"), strings.Contains(b, "onvif.org"):
		return "soap-probe"

	// 19 events. Cisco AnyConnect's initial exchange, aimed at a web port
	// to find VPN concentrators.
	case strings.Contains(b, "<config-auth"):
		return "vpn-handshake"

	// 38 events. JSON-RPC "initialize" carrying a protocolVersion is the
	// Model Context Protocol handshake -- scanners looking for exposed MCP
	// servers, which is new traffic rather than a legacy exploit.
	case strings.Contains(b, `"jsonrpc"`) && strings.Contains(b, `"initialize"`) &&
		strings.Contains(b, "protocolversion"):
		return "mcp-probe"

	// 38 events. getwork / eth_getWork -- looking for an unauthenticated
	// miner or pool to hijack.
	case strings.Contains(b, `"method"`) && containsAny(b, `"getwork"`, `"eth_getwork"`, `"eth_submitwork"`):
		return "mining-rpc-probe"

	// 137 events. WordPress's /batch/v1 multiplexer: one request that asks
	// the server to make several more, including to itself.
	case strings.Contains(b, `"requests"`) && strings.Contains(b, "["):
		return "batch-request-probe"

	// 178 events. version.bind is a DNS CHAOS query, aimed at a web port
	// by scanners that fan the same probe across every protocol.
	case q == "version.bind":
		return "dns-version-probe"

	// ~200 events. A query that is nothing but a hostname -- the shape of
	// an open-resolver or open-proxy test, where the value names the thing
	// the server is being asked to fetch or resolve on the caller's behalf.
	case bareHostname(q):
		return "open-resolver-probe"

	// 35 events, and the name is the payload.
	case strings.Contains(both, "androxgh0st"):
		return "androxgh0st"

	// 372 events. WordPress's REST surface, enumerated for something
	// exploitable rather than exploited yet.
	case strings.Contains(q, "rest_route="):
		return "wordpress-rest-probe"

	case strings.Contains(q, "phpinfo"):
		return "info-disclosure"

	// 401 events. Kilobytes of "A" behind a random boundary: a size or
	// parser limit being tested, not an exploit. This is also why the
	// distinct-body count reads higher than the number of real payloads.
	case strings.Contains(b, "webkitformboundary") && strings.Contains(body, strings.Repeat("A", 64)):
		return "multipart-padding"

	// Java and PHP serialised objects, by their headers rather than their
	// contents. rO0AB is base64 for the Java stream magic.
	case strings.HasPrefix(body, "rO0AB"), strings.Contains(body, "\xac\xed\x00\x05"), phpSerializedObject(b):
		return "serialized-object"

	// 38 events. Anything speaking a binary protocol at an HTTP port.
	// Checked last: it is a statement about the bytes rather than about
	// intent, and any pattern above is more informative.
	case binaryPayload(body):
		return "binary-protocol"
	}

	return ""
}

// containsAny reports whether s contains any of the needles.
func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// shellCommand reports whether s looks like it is trying to start a shell
// command, rather than merely containing characters a shell would use.
//
// The distinction matters because both halves are ordinary on their own:
// "$(" is everyday JavaScript, ";" is everyday in a header, and "uname"
// sits inside "username". So the binary has to appear *at* a command
// position -- immediately after a separator or a substitution opener, and
// followed by a boundary rather than more letters.
//
// The payloads this actually catches in the live window are Node
// child_process calls smuggled into multipart bodies, where the command is
// `id; hostname; pwd` and the rest is padding.
func shellCommand(s string) bool {
	binaries := []string{
		"cat ", "ls ", "id;", "id ", "id\n", "pwd", "whoami", "uname ", "uname -",
		"wget ", "curl ", "nc ", "sh ", "bash ", "chmod ", "busybox", "python", "perl ",
	}
	starters := []string{"$(", "`", ";", "|", "&&", "\n", "%0a"}

	for _, start := range starters {
		rest := s
		for {
			i := strings.Index(rest, start)
			if i < 0 {
				break
			}
			rest = rest[i+len(start):]
			trimmed := strings.TrimLeft(rest, " \t'\"")
			for _, bin := range binaries {
				if strings.HasPrefix(trimmed, bin) {
					return true
				}
			}
		}
	}
	// cmd= and exec= style parameters name the command directly, with no
	// separator in front of it.
	for _, param := range []string{"cmd=", "exec=", "command=", "execute="} {
		if i := strings.Index(s, param); i >= 0 {
			rest := strings.TrimLeft(s[i+len(param):], " '\"")
			for _, bin := range binaries {
				if strings.HasPrefix(rest, bin) {
					return true
				}
			}
			// A bare `cmd=pwd` has nothing after the binary to match a
			// trailing space, so those are checked whole.
			for _, bare := range []string{"pwd", "id", "whoami", "ls", "uname"} {
				if rest == bare || strings.HasPrefix(rest, bare+"&") {
					return true
				}
			}
		}
	}
	return false
}

// bareHostname reports whether a query string is nothing but a hostname --
// no key, no value, just a name. Scanners testing for an open resolver or
// open proxy send exactly that, and it cannot be confused with a normal
// query, which has an "=" in it.
func bareHostname(q string) bool {
	if q == "" || len(q) > 253 || strings.ContainsAny(q, "=&/ ") {
		return false
	}
	if !strings.Contains(q, ".") || strings.HasPrefix(q, ".") || strings.HasSuffix(q, ".") {
		return false
	}
	for _, r := range q {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '.' && r != '-' {
			return false
		}
	}
	// A trailing label of letters is what separates a hostname from a
	// version string or a filename.
	last := q[strings.LastIndex(q, ".")+1:]
	if len(last) < 2 {
		return false
	}
	for _, r := range last {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// binaryPayload reports whether a body is something other than text.
//
// utf8.ValidString alone is not the test: the 38-event probe that prompted
// this ("\x00\x00\x00\x00\x03:\x01*") is perfectly valid UTF-8, because C0
// control characters encode as themselves. A NUL byte, or control
// characters beyond the ones text actually uses, is the real signal.
func binaryPayload(body string) bool {
	if body == "" {
		return false
	}
	if !utf8.ValidString(body) || strings.ContainsRune(body, 0) {
		return true
	}
	control := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			control++
		}
	}
	return control*10 > len(body)
}

// phpSerializedObject matches PHP's serialize() object header -- O:<len>:"
// -- without matching the O: that shows up in ordinary prose.
func phpSerializedObject(s string) bool {
	i := strings.Index(s, "o:")
	if i < 0 {
		return false
	}
	rest := s[i+2:]
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	return digits > 0 && strings.HasPrefix(rest[digits:], `:"`)
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
	// #573: the two named-CVE plugin baits below (mirrored from serve()'s own
	// switch, same ordering: specific plugin+CVE cases before the generic
	// wp-content fallback) get their own category instead of falling into
	// the generic "wordpress" bucket -- a hit on one of these exact readme.txt
	// paths is a scanner actively probing for a specific known RCE, much
	// stronger signal than a bare wp-login scan, and worth being able to
	// filter/aggregate on separately.
	case strings.Contains(p, "/wp-content/plugins/duplicator/") && strings.HasSuffix(p, "readme.txt"):
		return "wordpress-cve-2020-11738"
	case strings.Contains(p, "/wp-content/plugins/wp-file-manager/") && strings.HasSuffix(p, "readme.txt"):
		return "wordpress-cve-2020-25213"
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
	// listenPort (#1889) is the destination half of the flow tuple. Read
	// once from the configured address rather than per request, which does
	// not carry it.
	listenPort int
	// tarpitEnabled (#246): stream a slow Markov-drip response (tarpit.go)
	// for requests classify() buckets as unrecognized scanning/exploit
	// noise, instead of the normal fast reply. See HTTP_TARPIT in main().
	tarpitEnabled bool
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// #1677: this binary's own -healthcheck dials 127.0.0.1 directly (see
	// main()) -- a real external request can never present that address
	// (it either arrives with a genuine attacker IP via portbridge's ":pp"
	// rule, or as the tunnel peer via a plain rule), so this can only be
	// the container's own healthcheck. Answer it without logging a fake
	// sensor event with a meaningless source IP.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && (host == "127.0.0.1" || host == "::1") {
		w.WriteHeader(http.StatusOK)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10)) // cap at 64 KiB
	r.Body.Close()

	e := event{
		Time:         time.Now().UTC().Format(time.RFC3339),
		Sensor:       s.sensor,
		Persona:      s.persona,
		Site:         s.site,
		Asset:        s.asset,
		Org:          s.org,
		SrcIP:        clientIP(r),
		SrcPort:      clientPort(r),
		DstPort:      s.listenPort,
		Method:       r.Method,
		Host:         r.Host,
		Path:         r.URL.Path,
		Query:        r.URL.RawQuery,
		UserAgent:    r.UserAgent(),
		Headers:      headerMap(r),
		Body:         string(body),
		Category:     classify(r.URL.Path),
		PayloadClass: classifyPayload(r.URL.RawQuery, string(body)),
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

	if s.tarpitEnabled && tarpitCategory(e.Category) {
		e.Status = http.StatusOK
		e.Tarpitted = true
		n, held := tarpit(r.Context(), w)
		e.TarpitBytes = n
		e.TarpitMS = held.Milliseconds()
	} else {
		s.serve(w, r, &e)
	}
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

	// #1889: read before the server is built, so it can carry the
	// destination half of the flow tuple. Used again below for the
	// listener itself -- one source of truth for the address.
	addr := getenv("LISTEN_ADDR", ":8080")

	s := &server{
		log:       newLogger(getenv("LOG_FILE", "/var/log/honeypot/http.json")),
		sensor:    getenv("SENSOR_NAME", "http-honeypot"),
		serverHdr: getenv("SERVER_HEADER", "nginx/1.24.0 (Ubuntu)"),
		persona:   getenv("PERSONA_ID", "nexusai-edge"),
		site:      getenv("SITE_ID", "nexusai-eu-edge"),
		asset:     getenv("ASSET_ID", "web-edge-01"),
		org:       getenv("ORGANIZATION", "NexusAI Research GmbH"),
		// #246: on by default -- a HellPot-style tarpit for unrecognized
		// scan/rce-probe noise costs the requester bandwidth/time for
		// zero GPU/API cost on our side, unlike the LLM-honeypot half of
		// #246 (blocked on #84's shared-GPU budget). Opt out per-instance
		// with HTTP_TARPIT=0 if a deployment wants the old fast-404
		// behavior instead.
		tarpitEnabled: getenv("HTTP_TARPIT", "1") != "0",
		listenPort:    listenPort(addr),
	}

	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		// #881: ReadHeaderTimeout alone only bounds the header phase --
		// once headers arrive, a slow-dripped body (still size-capped at
		// 64KB via io.LimitReader, but not time-bounded) or an idle
		// keep-alive connection could hold a goroutine/socket open
		// indefinitely (IdleTimeout doesn't fall back to ReadHeaderTimeout,
		// only to ReadTimeout, which was also unset). WriteTimeout is set
		// well above tarpitMaxDuration (tarpit.go, 90s) so it never cuts a
		// legitimate tarpit response short -- it's a backstop against some
		// other write-side hang, not a bound on the tarpit itself.
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
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
