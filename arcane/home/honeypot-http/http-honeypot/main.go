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
	// #3212: bytes and crypto/sha256 for the byte-safe evidence and its
	// hash, encoding/base64 for the former and encoding/hex for the latter.
	// #3213 removed base64 from this file when the Basic/Bearer header
	// parsing moved into credentials.go; #3212 needs it again for a
	// different reason, which is not a reason to move the parsing back.
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	// Body is the captured prefix as text, for the same reason it has
	// always been logged: it is what an analyst greps. It is NOT a
	// byte-preserving record of the request on two counts, and both are
	// now stated rather than left for a reader to discover.
	//
	// Lossiness: every byte outside UTF-8 is replaced by U+FFFD on the way
	// into JSON, so the stored value is a different byte string from the
	// one received. BodyB64/BodyEncoding are the byte-exact half.
	//
	// Redaction (#3213): this is creds.redactedBody, never the bytes off
	// the wire. BodyB64 is built from this same string, so the two cannot
	// disagree and neither is a way around the redaction.
	Body string `json:"body,omitempty"`
	// #3213: the account half of a submitted credential, kept because it
	// is the analytic value (a spray is a spray of accounts) and it is not
	// a secret. The secret half of the same credential is never written
	// here, never logged, and never returned over the API -- see
	// credentials.go. The pre-#3213 event carried a sibling `password`
	// field for exactly that half; it is gone, and `body`, `query` and
	// `headers` are scrubbed of credential values in its place, because a
	// removed field is not a removed leak.
	Username string `json:"username,omitempty"`
	// AuthType is the channel the credential arrived on ("basic",
	// "bearer", "form", or the name of a scheme this sensor does not
	// decode) -- never what was in it.
	AuthType string `json:"auth_type,omitempty"`
	// #3213: the presence/extraction axis, separate from Status (what the
	// decoy served) and from AuthOutcome (who decided anything). Always
	// present, and always one of the four credentialStatus values --
	// including "unknown", which is the whole reason the field is a string
	// rather than a boolean.
	CredentialStatus string `json:"credential_status"`
	// CredentialPresent is the presence boolean, and it is null exactly
	// when CredentialStatus is "unknown". That is not a formatting
	// nicety: a plain false would be indistinguishable from a request we
	// looked at and found nothing in, which is the collapse #3213 exists
	// to prevent.
	CredentialPresent *bool `json:"credential_present"`
	// CredentialIndicatorMatch is true when an attempt used this decoy's
	// own FICTIONAL bait credential (credentials.go's decoyIndicators --
	// not a vendor default list, and not a claim about any product but our
	// own). It marks an ATTEMPT, scoped by CredentialIndicator, and
	// nothing else: not access, not a bypass, not a CVE.
	CredentialIndicatorMatch bool   `json:"credential_indicator_match"`
	CredentialIndicator      string `json:"credential_indicator,omitempty"`
	// AuthOutcome is the provenance of any authentication decision this
	// response made (credentials.go's authOutcome). It is "simulated" for
	// anything the decoy's persona served and "unknown" when no
	// authentication decision was made. It is never derived from Status,
	// so a 200 on a login page -- or on a bearer-authenticated fake model
	// list -- can never read as a real authentication success.
	AuthOutcome string `json:"auth_outcome"`
	Status      int    `json:"status"`
	Category    string `json:"category"`
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

	// --- #3212: what we captured, how much of it, and the bytes ---
	//
	// Before this block, the only statement this event made about a body
	// was `body`, a Go string of whatever one io.ReadAll behind a 64 KiB
	// LimitReader happened to return -- with its error discarded. Two
	// defects followed from that, and both are unfixable by a consumer:
	//
	//  1. A JSON string does not preserve arbitrary bytes. A Java
	//     serialized object, a PNG, a lone 0x80 -- json.Marshal replaces
	//     every byte that is not valid UTF-8 with U+FFFD, so the stored
	//     value is a different byte string from the one received, and
	//     nothing in the document says so.
	//  2. A 40-byte body and the first 64 KiB of a 4 MB one serialized to
	//     the same shape. "The attacker sent 40 bytes" and "we kept 4 KB
	//     of something much larger" were the same record.
	//
	// So the capture is now described rather than implied. BodyCaptureState
	// is the authoritative answer to "is this the whole body": "complete",
	// "truncated" (we stopped at the cap and more bytes existed), or
	// "unknown" (the read failed, so completeness is not knowable). It is
	// set on every request event, including zero-byte ones, so an aggregate
	// over it has no missing-value bucket -- a genuinely short body answers
	// "complete", which is exactly the distinction defect 2 was missing.
	//
	// BodyReadError is the discarded io error, kept because "truncated" and
	// "we never found out" are different failures and the state field can
	// only carry one of them.
	//
	// BodySHA256 covers the CAPTURED PREFIX and says so in
	// BodySHA256Scope -- the same field name galah's body_sha256 already
	// established (see ip_enrichment/sensors.rs's promotion of
	// httpRequest.bodySha256), with the scope its hash could not claim. A
	// hash whose scope is ambiguous is worse than no hash: it looks
	// comparable across sensors and is not. It is deliberately NOT the
	// complete body's hash, because computing that would mean draining
	// whatever the client claims to be sending -- unbounded work, on
	// time this sensor does not spend, to obtain a fact nobody downstream
	// needs. See captureBody.
	//
	// BodyB64 is the byte-safe half of the answer: a bounded head, base64,
	// with BodyEncoding naming that encoding so a consumer never has to
	// guess it. BodyDeclaredBytes is the Content-Length the request CLAIMED
	// -- attacker-controlled, so it is recorded as a claim and never trusted
	// as a fact, and it is the only thing that turns "truncated at 64 KiB"
	// into "truncated at 64 KiB of 4 MB".
	//
	// JavaMarker is #3212's other half: a separate, Java-only observation,
	// deliberately not a new payload_class (see javaMarker).
	//
	// --- #3213 changed one of these premises, and the change is load-bearing
	//
	// This block was written against a `body` that held the raw capture, and
	// on that basis the byte-safe evidence was free: it carried the same
	// bytes `body` already published, so it disclosed nothing new. #3213
	// redacted `body`, and with it that argument. The evidence is now built
	// from the same redacted string, so the two fields still agree and
	// neither reintroduces what #3213 removed -- a base64 blob is not a
	// disclosure control, and treating it as one would have made this field
	// the single place a submitted credential survived.
	//
	// The per-field comments below say which of the two questions each field
	// answers, because the capture and the published bytes are now different
	// things and only one of them is allowed out of the process.
	// BodyCaptureState / BodyCapturedBytes / BodyReadError describe the
	// CAPTURE: how many bytes came off the wire, whether that was all of
	// them, and what ended the read. Nothing about redaction changes any of
	// the three, because redaction is not a fact about the wire.
	BodyCaptureState string `json:"body_capture_state"`
	// BodyCapturedBytes is the raw captured length, so it can exceed
	// len(decode(body_b64)) whenever the redactor shortened the body. See
	// bodyCapture.apply.
	BodyCapturedBytes int    `json:"body_captured_bytes"`
	BodyReadError     string `json:"body_read_error,omitempty"`
	// BodyB64 and BodySHA256 describe the PUBLISHED bytes: the redacted
	// body, bounded to a head, and the hash of the whole redacted captured
	// prefix. They are derived from the same string Body carries, so a
	// consumer can decode one, hash it, and get the other -- and neither
	// field is a route around the redaction that #3213 put on `body`.
	// Before #3213 these were safe to publish only because `body` already
	// published the same bytes; that is exactly the premise #3213
	// invalidated, and it is why the evidence is no longer built from the
	// raw capture.
	BodyEncoding string `json:"body_encoding,omitempty"`
	BodyB64      string `json:"body_b64,omitempty"`
	// BodySHA256 covers the CAPTURED PREFIX, post-redaction, and says so in
	// BodySHA256Scope -- the same field name galah's body_sha256 already
	// established (see ip_enrichment/sensors.rs's promotion of
	// httpRequest.bodySha256), with a scope label that names both bounds. A
	// hash whose scope is ambiguous is worse than no hash: it looks
	// comparable across sensors and is not. It is deliberately NOT the
	// complete body's hash, because computing that would mean draining
	// whatever the client claims to be sending -- unbounded work, on time
	// this sensor does not spend, to obtain a fact nobody downstream needs.
	// See captureBody and bodyCapture.apply.
	BodySHA256      string `json:"body_sha256,omitempty"`
	BodySHA256Scope string `json:"body_sha256_scope,omitempty"`
	// BodyDeclaredBytes is the Content-Length the client CLAIMED, and
	// BodyJavaMarker the byte-pattern Java observation. See declaredLength
	// and javaMarker.
	BodyDeclaredBytes int64  `json:"body_declared_bytes,omitempty"`
	JavaMarker        string `json:"java_marker,omitempty"`
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
	// Second-granularity timestamps collide when two rotations happen within
	// the same wall-clock second (#1403 -- the same pattern originated in
	// multipot's logger and was fixed there with a counter suffix; applying
	// the identical fix here). Disambiguate with a counter suffix instead of
	// trusting the clock alone.
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
	if err := os.Rename(l.path, target); err != nil {
		// Rename failing (e.g. path already gone) shouldn't stop logging --
		// reopening O_APPEND on the original path either resumes the same
		// file or creates a new one, either of which beats losing the fd.
	}
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
	// Unlike galah and hellpot, the guard above is a real
	// discriminator here rather than a guess: this sensor's raw port is a
	// ":pp" rule, so RemoteAddr is the attacker on that path and being the
	// tunnel peer genuinely does mean "came through Traefik". #1908 split
	// galah and hellpot onto separate ports to earn the same property
	// (wordpot got a third such split before its #2381 retirement).
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
	// #3213: a header whose whole value is a credential is replaced, not
	// shortened. Authorization carries the password (base64, which is
	// encoding, not protection), and Cookie carries session tokens an
	// attacker will replay -- neither is a fact about the request that a
	// log line needs to carry verbatim. The header still appears, with its
	// scheme where that is not itself a secret, so "did this request
	// authenticate at all" stays answerable.
	return redactSecretHeaders(m)
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
// checked first. This runs on the RAW body: naming one class does not
// decide what is kept, and since #3213 the kept copy is redacted, so this
// pass must not be the thing that reads a redacted string and finds nothing
// in it.
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

	// #3364, CVE-2026-48842: pre-authentication SQL injection in Roundcube
	// Webmail's virtuser_query plugin. CVSS 8.1; the Canadian Centre for
	// Cyber Security's AV26-503 (2026-09-21) reports it exploited in the
	// wild and has published no exploitation detail, so the shape below
	// comes from the advisory and the product's own dispatch, not from a
	// capture. The value the plugin is handed is escaped with
	// preg_replace(), and a backslash inside the value defeats that escape,
	// so what to match is a SQL payload on one of Roundcube's own dispatch
	// parameters -- not a path. A real attack goes to whatever endpoint the
	// application's dispatch resolves, which is the same reason #2919 and
	// #3309 matched on the request's own bytes: a bait path for it would
	// never match, because the path in a real attack is not ours.
	//
	// Checked first, ahead of the generic sqli case below, because a
	// Roundcube probe is often both at once -- the same value is caught
	// there when it happens to use one of that case's six tokens and
	// unnamed otherwise. This class says which CVE, and that no session was
	// needed to reach it.
	//
	// Not measured against the fleet's corpus: #3364 marks the coverage gap
	// as unmeasured and the corpus is not reachable from here. What the
	// tests pin instead is the boundary that decides whether the class is
	// usable -- a real Roundcube login, an apostrophe in a mail address and
	// a bare plugin enumeration each keep their own answer.
	//
	// Cost is bounded the way the rest of this function is: the body was
	// already capped at 64 KiB by ServeHTTP, and every needle here is a
	// plain substring search over one parameter value, so the whole case is
	// a fixed number of linear passes over bytes already in memory.
	case roundcubeVirtuserSQLi(query, body):
		return "roundcube-virtuser-query-sqli"

	// #3189, CVE-2026-63077: unauthenticated deserialization RCE in
	// JetBrains TeamCity. CVSS 3.1 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H),
	// CWE-502, in CISA KEV since 2026-08-05, fixed in 2025.11.7 and
	// 2026.1.3. The JetBrains CNA record names the mechanism --
	// deserialization of untrusted data reached through the agent polling
	// protocol -- so no credential is involved, which is what PR:N above
	// means and why a bait login form would be the wrong shape to look for.
	//
	// What is matched is the ATTEMPT, as bytes: a serialization container
	// on the wire, which is the mark of a deserialization sink being aimed
	// at. Nothing here is decoded, reconstructed, evaluated or answered --
	// a classifier that read the object graph to confirm it would be a
	// second copy of the sink it exists to observe, which is the whole
	// thing this sensor must never be. See
	// teamcityAgentDeserialization for the two halves and why both are
	// required.
	//
	// Checked first, ahead of the generic serialized-object case near the
	// bottom of this switch, which is where a TeamCity attempt would
	// otherwise land. That case recognises a stream at the very start of a
	// body or raw magic bytes anywhere in one, so the same attempt arrives
	// under three different labels depending on transport and none of them
	// says which product or which CVE it was. Outside this gate that case
	// is untouched, and the tests pin that it is.
	//
	// Not measured, and that is a fact about the evidence rather than a
	// formatting choice: #3189's research note records no capture, no PoC
	// and no published exploitation detail for this signature, and the
	// fleet's corpus is not reachable from here. There is no event count to
	// quote, so none is invented. What the tests pin instead is the
	// boundary, because that is what decides whether the class is usable.
	case teamcityAgentDeserialization(query, body, q, b):
		return "teamcity-agent-deserialization"

	// #3309, CVE-2026-87902 (KEV 2026-09-25): WordPress resolves the page
	// template from `pagename`, which it urldecodes once more itself, so a
	// double-encoded traversal walks out of the theme directory into any
	// readable .php -- pearcmd.php for RCE. Checked before pearcmd-rce,
	// which is this chain's second stage and would otherwise claim it.
	// Zero matches in the 30 days before this landed; the traffic that
	// looks similar (theme css.php?files=../, index.php pearcmd LFI) has no
	// pagename and keeps its own class.
	case wordpressPagenameTraversal(query, body):
		return "wordpress-pagename-traversal"

	// #3309, CVE-2026-87902 again (KEV 2026-09-25), and the half
	// #3359's case above cannot reach. That case is `../` in a parameter
	// named `pagename`. The flaw is a file *inclusion* -- get_page_template()
	// urldecodes `pagename` and hands the result to locate_template(), which
	// checks only that the candidate exists and ends in .php/.html, never
	// that it is still inside a theme root -- so a PHP stream wrapper is the
	// same primitive reached a different way, and `template`, `page_template`,
	// `theme` and `stylesheet` name a template through the same hierarchy as
	// `pagename` does.
	//
	// Checked after the pagename case and before pearcmd-rce, so #3359's
	// labels do not move: a request it already claims keeps the class it has
	// had since #3359 shipped, and this case only picks up what falls
	// through. It is also before the generic cases below, which is the
	// point -- an inclusion aimed at /etc/passwd is a narrower and more
	// actionable reading than "somebody asked for /etc/passwd", the same
	// precedence the corpus table already gives command-injection over
	// secret-read.
	//
	// Both halves are required and neither is the payload alone. `pagename`
	// and `template` are WordPress *query variables*, not WordPress-exclusive
	// parameter names, so a WordPress signal that is not the attacker's
	// target file is required alongside them: WordPress's own routing
	// variables, or a WordPress core path somewhere in the request. A
	// generic LFI or RFI aimed anywhere else keeps the class it already had.
	case wordpressTemplateInclusion(query, body):
		return "wordpress-template-inclusion"

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

	// #3394, OllamaDrama/Ollure (arXiv 2609.29757): the model *name* on an
	// Ollama management call used as a network target rather than a model
	// reference. The paper's Table 2 measures it as two categories --
	// 17 pull + 14 push naming an out-of-band-interaction host, and 10
	// pull naming an internal one -- and every name in both is unique, so
	// this is a shape and not a list. It is the same SSRF primitive the
	// issue proposed, and the issue's own regex cannot reach it: its
	// alternation is anchored with ^, and an Ollama body is JSON, so
	// `^(https?://)` and `^127.` never see the value. Measured, that regex
	// matches 5 of the paper's 34 request shapes; this case reaches the
	// 9 the anchored branches were aimed at, and 0 of the 27 real-corpus
	// entries in payload_test.go.
	//
	// Placed after path-traversal and secret-read so those keep the
	// classes they already have: a name that is both a traversal and a
	// target is a traversal, which is the more specific of the two.
	case ollamaModelTarget(b):
		return "ollama-model-target"

	// 171 events. Creating an administrator through an API that should not
	// allow it -- persistence rather than a smash-and-grab.
	case strings.Contains(b, "roleid") && strings.Contains(b, "administrator"):
		return "admin-account-create"

	// #3430: agent-driven scanner-laundering -- the double-encoding bypass
	// of a method/path filter, aimed at an OData-style endpoint. Matched on
	// the option's own bytes rather than on a path, for the reason #2919,
	// #3309 and #3364 each give: a real probe goes to whatever endpoint the
	// target's own dispatch resolves, and a bait path would never match.
	//
	// #3430 proposes a three-layer rule. Two of its layers are not
	// implementable in this binary and are not claimed here: per-source
	// session behaviour and cross-source header-fingerprint correlation both
	// need state the sensor does not keep -- it classifies one request and
	// logs it, consulting no backend. What is left that this function can
	// read is the query and body, and that is this case.
	case odataDoubleEncode(query, body):
		return "odata-double-encode-probe"

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
	// contents. rO0AB is base64 for the Java stream magic. Unchanged by
	// #3212 and deliberately so: this is one ordered class shared by two
	// languages, and the Java-specific evidence it lacked now lives in
	// its own java_marker field (see javaMarker) rather than in a split of
	// this value, which existing queries already mean and the PHP case
	// would lose.
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

// decodeUpTo percent-decodes s up to rounds times, stopping as soon as a
// round changes nothing or stops being decodable. Three rounds is the budget
// the CVE-2026-87902 cases allow, because the whole point of the CVE is that
// the target application decodes the value again after the web server has
// already decoded it once.
func decodeUpTo(s string, rounds int) string {
	full := s
	for i := 0; i < rounds; i++ {
		next, err := url.QueryUnescape(full)
		if err != nil || next == full {
			break
		}
		full = next
	}
	return full
}

// formValues splits a query string or form body into key/value pairs the way
// the application being attacked does, which is not always the way
// url.ParseQuery does.
//
// The difference that matters is the semicolon. Since Go 1.17
// url.ParseQuery rejects any pair containing one and drops it; PHP's only
// separator is "&", so `data://text/plain;base64,...` arrives at WordPress as
// a single value with its media type intact -- and the sensor, parsing it the
// Go way, could not see the parameter at all. Using the stricter parser would
// drop exactly the values worth seeing, in both WordPress cases: the CVE
// works because the target decodes what the web server hands it, so the
// classification has to be done on the bytes the target will parse.
//
// Deliberately minimal -- split on "&", then on the first "=", then unescape
// each side. An undecodable side is kept exactly as it arrived rather than
// dropped, because a deliberately broken escape is a way of hiding a payload
// and the bytes are still worth matching.
func formValues(raw string) url.Values {
	out := url.Values{}
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		out.Add(formUnescape(key), formUnescape(value))
	}
	return out
}

// formUnescape percent-decodes one side of a form pair, returning it
// unchanged when it will not decode. A malformed escape is a way of varying a
// probe's appearance without changing what it means, so the raw bytes are
// kept rather than discarded.
func formUnescape(s string) string {
	if unescaped, err := url.QueryUnescape(s); err == nil {
		return unescaped
	}
	return s
}

// wordpressPagenameTraversal reports a `pagename` parameter -- in the query
// or a form-encoded body -- carrying traversal. Double encoding is the tell:
// after the one decode there is above, a legitimate page slug never still
// contains an encoded dot, slash or backslash, and a fully decoded one never
// contains "../". Parameters are parsed, not substring-matched, so "pagename"
// inside some other value cannot trigger it.
func wordpressPagenameTraversal(query, body string) bool {
	for _, raw := range []string{query, body} {
		for key, vals := range formValues(raw) {
			if !strings.EqualFold(key, "pagename") {
				continue
			}
			for _, v := range vals {
				once := strings.ToLower(v)
				if containsAny(once, "%2e", "%2f", "%5c") {
					return true
				}
				if containsAny(decodeUpTo(once, 3), "../", "..\\") {
					return true
				}
			}
		}
	}
	return false
}

// odataDoubleEncode reports an OData system query option -- $select, $filter,
// $top and the rest -- whose key or value still carries a percent-escape
// after one decode. That residue is the whole signature: a client that
// encodes its query once has nothing left to encode, so %2520 (a literal
// %20, or a space one decode too late) is a request that was assembled to
// survive a second decode, which is what #3430's double-encoding bypass is.
//
// Both halves are required and the ordering is the design. The escape alone
// is not this class's business: measured against the pinned 30-day corpus,
// a bare residual escape claims the PHP-CGI probe arriving as %25ADd and
// both WordPress pagename double-encodings, and all three are already
// correctly labelled by the more specific classes above. An OData option
// alone is worse, because a legitimate OData client sends exactly those keys
// and would be indistinguishable from a scanner. Together they are a shape
// neither produces: a field-selection endpoint probed with a filter that
// only comes out of the filter after the second decode.
//
// Keys are parsed rather than substring-matched, and the alias form
// (`northwind.$filter`) is allowed because OData defines one -- which also
// means "$filter" inside some other value cannot trigger this.
func odataDoubleEncode(query, body string) bool {
	options := map[string]bool{
		"$select": true, "$filter": true, "$expand": true, "$orderby": true,
		"$top": true, "$skip": true, "$count": true, "$apply": true,
		"$format": true, "$search": true, "$skiptoken": true, "$index": true,
	}
	for _, raw := range []string{query, body} {
		values, err := url.ParseQuery(raw)
		if err != nil && len(values) == 0 {
			continue
		}
		for key, vals := range values {
			// OData allows a namespace alias prefix, so compare the last
			// dotted part: `northwind.$filter` is the same option.
			name := strings.ToLower(key)
			if i := strings.LastIndex(name, "."); i >= 0 {
				name = name[i+1:]
			}
			if !options[name] {
				continue
			}
			if residualEscape(key) {
				return true
			}
			for _, v := range vals {
				if residualEscape(v) {
					return true
				}
			}
		}
	}
	return false
}

// residualEscape reports whether s holds a %XX escape that is still there --
// a string that will decode again if something asks it to. Malformed
// sequences are not escapes and do not count.
func residualEscape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		var hi, lo byte
		if unhex(s[i+1], &hi) && unhex(s[i+2], &lo) {
			return true
		}
	}
	return false
}

// ollamaAPIPath reports whether p is one of the Ollama management API's
// documented routes, and nothing else. The list is the whole of the REST
// surface Ollure emulated, and every entry is compared whole -- a prefix
// match on "/api/" would take /api/v1/namespaces with it.
func ollamaAPIPath(p string) bool {
	switch p {
	case "/api/tags", "/api/version", "/api/ps", "/api/show",
		"/api/generate", "/api/chat", "/api/embed",
		"/api/pull", "/api/push", "/api/create", "/api/copy", "/api/delete":
		return true
	}
	return false
}

// ollamaModelName returns the value of the first JSON string field called
// "name" or "model" in body, which is where the Ollama management API
// carries the model reference: "name" on the registry calls (pull, push,
// create, copy, delete, show) and "model" on the inference calls (generate,
// chat, embed).
//
// It scans the text rather than parsing it, and that is the point rather
// than a shortcut. Everything this file matches arrived from the network,
// and none of it is deserialized here; the field's value is delimited in the
// bytes that arrived, and ServeHTTP has already capped the body at 64 KiB.
// A value carrying an escaped quote truncates early, which under-matches;
// the raw body is stored on the event regardless, so nothing is lost.
func ollamaModelName(body string) string {
	for _, key := range []string{`"name"`, `"model"`} {
		rest := body
		for {
			i := strings.Index(rest, key)
			if i < 0 {
				break
			}
			rest = rest[i+len(key):]
			// A field only carries a value if one follows the colon.
			// Without this, the word "name" inside some other string is a
			// hit and the value it is handed is the rest of the request.
			j := 0
			for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t' || rest[j] == ':') {
				j++
			}
			if j >= len(rest) || rest[j] != '"' {
				continue
			}
			rest = rest[j+1:]
			k := strings.IndexByte(rest, '"')
			if k < 0 {
				// Unterminated: this was the tail of a string, not a
				// field, and there is nothing left to look at.
				break
			}
			return rest[:k]
		}
	}
	return ""
}

// ollamaModelTarget reports whether an Ollama model name names a network
// target instead of a model.
//
// The three shapes are the ones Ollure measured across 84 days and four
// deployments, and none of them can be a model reference:
//
//   - a URL, for the external-URL category (17 pull + 14 push) and the
//     internal-URL category (10 pull): out-of-band-interaction hosts, the
//     link-local metadata address, loopback API recursion, port probes;
//   - an out-of-band-interaction hostname anywhere in the name, which is
//     unambiguous -- there is no benign reason for one in a model reference;
//   - a bare `host:port/model`, which is the insecure-registry form and
//     carries no scheme at all, so the issue's `^(https?://)` branch is
//     blind to it by construction.
//
// Anchoring matters more than reach here. A name is not disqualified by
// containing a slash: `meta-llama/llama3.1:70b-instruct` and
// `huihui_ai/gemma-4-abliterated:12b` are ordinary references, and the
// abliterated one is a deliberate guardrail-bypass intent the sensor
// should record as a model name rather than as an SSRF. The host part has
// to be an address, which is what separates `127.0.0.1:37987/cve-12886`
// from `llama3.1:70b`.
func ollamaModelTarget(body string) bool {
	v := strings.ToLower(ollamaModelName(body))
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return true
	}
	if strings.Contains(v, ".oast.") {
		return true
	}

	var host, port string
	if strings.HasPrefix(v, "[") {
		// The bracketed form the paper records for internal targets.
		end := strings.IndexByte(v, ']')
		if end < 0 || !strings.HasPrefix(v[end+1:], ":") {
			return false
		}
		host, port = v[1:end], v[end+2:]
	} else {
		i := strings.IndexByte(v, ':')
		if i <= 0 {
			return false
		}
		host, port = v[:i], v[i+1:]
	}
	if k := strings.IndexByte(port, '/'); k >= 0 {
		port = port[:k]
	}
	if host == "" || port == "" {
		return false
	}
	address := true
	for _, r := range host {
		if r != '.' && r != ':' && !(r >= '0' && r <= '9') {
			address = false
			break
		}
	}
	if !address {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// roundcubeVirtuserSQLi reports a pre-authentication SQL injection aimed at
// Roundcube Webmail's virtuser_query plugin (CVE-2026-48842).
//
// The gate is the request's shape and the payload is a requirement on top of
// it, in that order, and the order is the whole design. Roundcube addresses
// its own requests with a small set of dispatch parameters: `?_task=login`
// IS the login form, and `?_action=plugin.<name>` is a plugin endpoint, so
// both are reachable with no session and no credential -- which is the
// pre-auth half of the CVE. The plugin can also be named outright, as a
// parameter key or as the value of `_action`, which is how a scanner that
// knows the endpoint addresses it directly.
//
// Both halves are required because each alone is ordinary traffic. A request
// that merely names virtuser_query is a scanner enumerating plugins, and a
// request that merely carries SQL is somebody else's class -- the generic
// sqli case below, or nothing at all when the payload rides in the query
// string, which that case does not read. A login form is the one route where
// a wrong label is guaranteed to cost something, because mail addresses
// contain apostrophes and this classifier is the thing reading them.
//
// Parameters are parsed, not substring-matched, for the reason
// wordpressPagenameTraversal gives: the text "virtuser_query" inside some
// other value must not trigger this, and neither must a payload that happens
// to contain "_task". Nothing is deserialized and nothing is evaluated --
// url.ParseQuery splits a string into key/value pairs, and every value is
// then matched as bytes.
func roundcubeVirtuserSQLi(query, body string) bool {
	for _, raw := range []string{query, body} {
		values, err := url.ParseQuery(raw)
		if err != nil && len(values) == 0 {
			continue
		}
		roundcube := false
		for key, vals := range values {
			// The dispatch parameters, and the plugin named as a key.
			// Matched whole rather than by substring: a key called
			// "_task_id" is some other application's, and "_user" -- the
			// field the lookup is actually handed -- carries no such
			// meaning, so the value check below is what decides that half.
			if strings.EqualFold(key, "_task") || strings.EqualFold(key, "_action") ||
				strings.EqualFold(key, "virtuser_query") || strings.EqualFold(key, "virtuser") {
				roundcube = true
			}
			// The plugin named as a value, in both the forms Roundcube
			// dispatches it: "virtuser_query" and "plugin.virtuser_query".
			// A test, not a Contains, so a path or a parameter whose name
			// merely starts with the plugin's does not open the gate.
			for _, v := range vals {
				switch v {
				case "virtuser_query", "plugin.virtuser_query":
					roundcube = true
				}
			}
		}
		if !roundcube {
			continue
		}
		for _, vals := range values {
			for _, v := range vals {
				if roundcubeSQLPayload(v) {
					return true
				}
			}
		}
	}
	return false
}

// teamcityAgentDeserialization reports a request aimed at a Java
// deserialization sink through TeamCity's build-agent polling protocol
// (CVE-2026-63077), as a conjunction of two things seen on the wire.
//
// Half one is the product's own agent protocol: a call name from TeamCity's
// polling channel, or one of its qualified DTO/package names. Half two is a
// serialization container: the Java stream header, raw or base64, or a gadget
// class name -- see javaSerializationContainer.
//
// Both are required, and neither alone is worth anything. Every TeamCity
// server on earth has agents polling it, so the product half on its own is
// the fleet's background traffic, and a classified agent poll would be worse
// than no classification at all. A serialized object on an HTTP port is
// somebody else's finding: this sensor serves a WordPress XML-RPC bait of
// its own (#238) and buckets xmlrpc paths as "wordpress", so containers on
// that transport are expected to arrive here, and they are not TeamCity's.
// The conjunction is the CVE, which is why this takes the product AND the
// container and cannot be reduced to a single substring.
//
// The raw and lowered forms of each channel are both passed in, and the
// distinction is load-bearing rather than tidiness. The container has to be
// read from the RAW bytes: strings.ToLower replaces every byte that is not
// valid UTF-8 with U+FFFD, so the lowered form of a raw AC ED 00 05 header
// is replacement characters and the signature is gone. That is the same
// reason the generic serialized-object case reads `body` rather than this
// function's `b`. The product names are ASCII and are read from the lowered
// copies, which the caller has already built for its own cases -- so this
// function allocates nothing.
//
// What it does not do: deserialize. No decoder, no parser, no object
// reader, no evaluation of anything received. The class reports that a
// request carried the marks of a deserialization attempt on a named
// product's protocol, and nothing more: not that the object graph was
// well-formed, not that the sink existed, and emphatically not that anything
// was executed. Those are different claims, and only this one is available
// from the bytes a sensor receives.
func teamcityAgentDeserialization(rawQuery, rawBody, lowerQuery, lowerBody string) bool {
	if !javaSerializationContainer(rawQuery, rawBody, lowerQuery, lowerBody) {
		return false
	}
	return teamcityAgentProtocol(lowerQuery, lowerBody)
}

const (
	// javaStreamHeader is the four bytes every java.io ObjectOutputStream
	// begins with: STREAM_MAGIC (0xAC 0xED) followed by the serialization
	// protocol version (0x00 0x05). It is the only place in a Java stream
	// that says "this is a Java object stream", which is what makes it worth
	// matching on its own -- a payload whose class descriptor has been
	// mangled to slip a filter still starts with these four bytes.
	//
	// Read as bytes and compared. Never handed to a deserializer: that
	// would be the vulnerability, not the detection.
	javaStreamHeader = "\xac\xed\x00\x05"
	// javaStreamHeaderBase64 is base64(javaStreamHeader), truncated to the
	// five characters that are fixed whatever follows it. The first three
	// bytes fill one base64 group exactly, and the fifth character is the
	// first six bits of the version byte, so it is 'B' in every stream. An
	// attacker who rewrites the tail of their blob cannot move the header
	// without rewriting the transport that carries it.
	//
	// This is how the XML-RPC string/base64 types and TeamCity's own JSP
	// entry point actually put a serialized object on the wire, so it is
	// the form this class is most likely to meet in the clear.
	javaStreamHeaderBase64 = "rO0AB"
)

// javaGadgetClasses are the class names a published Java gadget chain needs,
// lowercased for the case-insensitive comparison
// javaSerializationContainer makes against the caller's lowered copies.
//
// A Java stream carries its class descriptor in cleartext -- the descriptor
// names the class before any of it has been read -- which makes a gadget
// class name in the request two things at once: the reason a container on
// the wire is an attack rather than an accident, and the signal that
// survives an attempt whose header bytes were tampered with. The list is the
// gadget families that are actually published, not a guess at what might
// work: the commons-collections chains that are the ysoserial default, the
// JNDI datasource rowset, BeanComparator, the annotation proxy that wraps
// it, the Xalan TemplatesImpl bytecode sink that nearly every chain ends
// in, the xbean JNDI converter, and the ysoserial marker itself.
//
// Only ever matched in company with TeamCity's protocol shape, so ordinary
// traffic that happens to contain one of these words is unaffected.
var javaGadgetClasses = []string{
	// commons-collections 3 and 4: InvokerTransformer, ChainedTransformer
	// and the rest of the default chain.
	"org.apache.commons.collections.functors",
	"org.apache.commons.collections4.functors",
	// The JNDI route: a rowset that will be told where to look up.
	"com.sun.rowset.jdbcrowsetimpl",
	// BeanComparator, and the annotation proxy that carries it.
	"org.apache.commons.beanutils.beancomparator",
	"sun.reflect.annotation.annotationinvocationhandler",
	// The bytecode sink.
	"com.sun.org.apache.xalan.internal.xsltc.trax.templatesimpl",
	// The xbean converter, for the chains that need a different entry.
	"org.apache.xbean.propertyeditor.jndiconverter",
	// A scanner naming its own toolchain, which is the clearest possible
	// statement of intent and costs nothing to recognise.
	"com.ysoserial",
}

// javaSerializationContainer reports whether either channel carries the
// marks of an object stream that something might deserialize.
//
// Three marks, in the order they are worth matching: the stream header
// itself, the same header in the base64 form the transports use, and a
// gadget class name. The first two are byte comparisons over the raw
// strings and the third is a substring search over copies the caller
// already holds, so the common case -- ordinary traffic with no container
// anywhere -- costs two linear scans and no allocation.
//
// There is no decoder anywhere in this function, and that is the point
// rather than an accident of implementation. Decoding in order to "confirm"
// the object is the sink reimplemented inside the thing meant to observe it:
// a second place to get parsing wrong, on attacker-chosen bytes, for no
// extra signal, since every container worth naming is already caught by its
// header. One consequence is worth stating, because it reads like a
// limitation and is not -- a payload whose bytes would not survive a
// decoder still matches here, and one that would is caught by the same four
// bytes the decoder would have needed.
func javaSerializationContainer(rawQuery, rawBody, lowerQuery, lowerBody string) bool {
	// The header, raw. Containment rather than a prefix test, because the
	// raw transport is not always a body on its own: the same four bytes
	// arrive inside a form field, inside an XML element, and on a JSP entry
	// point's query string.
	if strings.Contains(rawQuery, javaStreamHeader) || strings.Contains(rawBody, javaStreamHeader) {
		return true
	}
	// The header, base64'd, anchored to the start of a base64 token, and
	// case-sensitively -- because base64 is. Lowercasing this token would
	// match attempts that cannot work and reject ones that can.
	if base64TokenHasPrefix(rawQuery, javaStreamHeaderBase64) ||
		base64TokenHasPrefix(rawBody, javaStreamHeaderBase64) {
		return true
	}
	// A gadget class name, in either channel.
	return containsAny(lowerQuery, javaGadgetClasses...) ||
		containsAny(lowerBody, javaGadgetClasses...)
}

// base64TokenHasPrefix reports whether a base64 token in s begins with
// prefix -- that is, whether prefix sits at a position where a base64 blob
// could begin rather than somewhere inside one.
//
// Deep inside a long blob any five characters turn up by chance; at the
// start of one they are the header. Every character a base64 value travels
// inside -- the XML element's angle brackets, a URL's own separators,
// whitespace -- is outside the base64 alphabet, which is what lets a
// five-byte comparison stand in for "the start of the blob" without parsing
// the surrounding transport, let alone decoding anything.
func base64TokenHasPrefix(s, prefix string) bool {
	if len(prefix) == 0 || len(s) < len(prefix) {
		return false
	}
	for i := 0; i+len(prefix) <= len(s); i++ {
		if s[i:i+len(prefix)] != prefix {
			continue
		}
		if i == 0 || !isBase64Char(s[i-1]) {
			return true
		}
	}
	return false
}

// isBase64Char reports whether c can appear inside a base64 token.
//
// Padding is deliberately excluded: '=' ends a token, so a '=' immediately
// before a match is a delimiter, and in a query string it is the very
// separator that introduces the parameter. data=rO0AB... has to match.
func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/'
}

// teamcityAgentCallNames are the call names TeamCity's own build agents use
// on the polling channel, lowercased.
//
// Matched as WHOLE values, because the transport is not TeamCity's alone:
// xmlrpc/remote in particular is an XML-RPC convention, and a product a
// request merely mentions is not a product a request is aimed at. The
// registration family is the part of this channel that needs no credential,
// which is the shape the CVE actually takes.
var teamcityAgentCallNames = []string{
	"xmlrpc/allowregistration",
	"xmlrpc/canregisteragent",
	"xmlrpc/registeragent",
	"xmlrpc/getunregisteredagents",
	"xmlrpc/unregisteragent",
	// The generic envelope the rest of the protocol travels inside, and the
	// two work-download calls by which an agent is handed a build.
	"xmlrpc/remote",
	"agentunload",
	"agentunload2",
}

// teamcityProtocolMarkers are TeamCity's own qualified names: a DTO the
// agent protocol exchanges, the product's Java packages, and the JSP entry
// point's file name.
//
// A substring match is right here, unlike for the call names: these are
// package-qualified identifiers rather than words, and
// "org.jetbrains.teamcity" is not something ordinary traffic carries. The
// teamcity.* namespace at large is deliberately NOT in this list -- an
// agent's own property bag is full of teamcity.agent.jvm.os.name and
// neighbours, and that bag is what a normal poll looks like. The namespace
// is the product's; these are its internals.
var teamcityProtocolMarkers = []string{
	"teamcity.server.message",
	"org.jetbrains.teamcity",
	"jetbrains.buildserver",
	"buildserver.action",
}

// teamcityAgentProtocol reports whether a request names TeamCity's own
// build-agent protocol, on the lowered copies of the two channels.
//
// Two ways, and the cheap one comes first: a product-qualified marker
// anywhere, or a call name as a whole value. The call name is extracted
// rather than substring-matched -- from the parameters a caller addressed it
// with, and from the XML-RPC <methodName> element it arrives in -- so that
// xmlrpc/allowRegistrationAndPing, and a call name sitting inside somebody
// else's parameter value, both keep their own answers.
//
// Nothing is parsed in order to answer this. url.ParseQuery splits a string
// into key/value pairs and the element extractor is two index searches;
// neither is told what to do with what it found, and neither can fail in a
// way that changes the answer. Parsing a request to learn what it asked for
// is a different job from noticing what it carried, and the second one is
// this sensor's.
func teamcityAgentProtocol(lowerQuery, lowerBody string) bool {
	if containsAny(lowerQuery, teamcityProtocolMarkers...) ||
		containsAny(lowerBody, teamcityProtocolMarkers...) {
		return true
	}
	for _, channel := range []string{lowerQuery, lowerBody} {
		// A body that is not a parameter list at all parses into junk keys
		// and values, which is harmless: the key test below rejects them.
		// An error alongside real values is tolerated for the same reason
		// wordpressPagenameTraversal tolerates it.
		values, err := url.ParseQuery(channel)
		if err != nil && len(values) == 0 {
			continue
		}
		for key, vals := range values {
			if key != "methodname" && key != "method" {
				continue
			}
			for _, v := range vals {
				if teamcityAgentCall(v) {
					return true
				}
			}
		}
	}
	return teamcityAgentCall(xmlrpcMethodName(lowerBody))
}

// teamcityAgentCall reports whether a lowercased call name is one of
// TeamCity's.
func teamcityAgentCall(lowerName string) bool {
	if lowerName == "" {
		return false
	}
	for _, name := range teamcityAgentCallNames {
		if lowerName == name {
			return true
		}
	}
	return false
}

// xmlrpcMethodName returns the text of an XML-RPC <methodName> element from
// an already-lowercased body, or "" when there is none.
//
// Two index searches over the same string, and deliberately consistent about
// which string they search: lowercasing can change a body's length, so
// indices taken from one copy must never be used to slice another. Working
// throughout on the lowered copy sidesteps that instead of measuring around
// it, and the result is only ever compared as a name, never acted on.
func xmlrpcMethodName(lowerBody string) string {
	const open, closing = "<methodname>", "</methodname>"
	i := strings.Index(lowerBody, open)
	if i < 0 {
		return ""
	}
	rest := lowerBody[i+len(open):]
	j := strings.Index(rest, closing)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// wpCorePaths are the strings that say "this request is aimed at WordPress"
// without being the attacker's target file. wp-config.php is deliberately
// absent: naming a file is what an attacker does, and treating that as proof
// of what application was being attacked is how a real disclosure probe ends
// up filed as a WordPress CVE.
var wpCorePaths = []string{
	"wp-content/", "wp-includes/", "wp-json", "wp-admin/",
	"wp-login.php", "wp-blog-header.php", "wp-load.php",
}

// wordpressTemplateInclusion reports CVE-2026-87902 (WordPress Core
// unauthenticated local PHP file inclusion) reached in a way the
// pagename-traversal case above cannot see: a stream wrapper or a remote URL
// instead of a `../`, or one of the other parameters that name a template.
//
// The gate is the request's shape and the payload is a requirement on top of
// it, and the order is the design. Three things must be true, and any one of
// them alone is ordinary traffic:
//
//   - a template selector is present -- pagename, page_template, template,
//     theme or stylesheet, the parameters WordPress resolves through its page
//     template hierarchy;
//   - a WordPress signal that is not the attacker's target is present -- the
//     routing variables WordPress Core reads (page_id, the CVE's documented
//     precondition, and rest_route, WordPress's own REST multiplexer), or a
//     WordPress core path in a value;
//   - and an inclusion payload sits in a template selector: traversal, a PHP
//     stream wrapper, a remote URL, or -- the advisory's third indicator --
//     PEAR command syntax in the query string of a WordPress front end.
//
// The second condition is the one that keeps this from being a wider
// `pagename` check. `pagename` and `template` are WordPress query variables,
// which is not the same as being a WordPress-only parameter name, and a
// scanner probing one application must not have its generic LFI relabelled as
// somebody else's CVE. Requiring a second, WordPress-owned signal is
// deliberately the stricter choice: a probe that sends a wrapper in
// `pagename` and nothing else is left unlabelled rather than guessed at.
//
// The query and the body are read together rather than one at a time, because
// WordPress merges them: WP::parse_request() builds its query variables from
// $_GET plus $_POST, and the verified PoC depends on that -- its routing
// travels in the form body while PEAR's argv travels in the raw query string,
// because PHP splits the query on literal `+` without decoding the
// arguments. Checked one bag at a time, that request has a WordPress half and
// a PEAR half and no reason to connect them.
//
// Nothing here resolves a path. A request-supplied name is never joined to a
// directory, opened, stat'd or included -- formValues splits a string into
// key/value pairs and every value is matched as bytes, which is the same
// contract wordpressPagenameTraversal has.
func wordpressTemplateInclusion(query, body string) bool {
	shape, selectors := false, []string(nil)
	for _, raw := range []string{query, body} {
		for key, vals := range formValues(raw) {
			lower := strings.ToLower(key)
			if lower == "page_id" || lower == "rest_route" {
				shape = true
			}
			if lower == "pagename" || lower == "page_template" || lower == "template" ||
				lower == "theme" || lower == "stylesheet" {
				selectors = append(selectors, vals...)
			}
			for _, v := range vals {
				if containsAny(strings.ToLower(v), wpCorePaths...) {
					shape = true
				}
			}
		}
	}
	if !shape || len(selectors) == 0 {
		return false
	}
	for _, v := range selectors {
		if wordpressInclusionPayload(v) {
			return true
		}
	}
	// The PEAR stage. The existing pearcmd-rce case needs both markers in the
	// query string, which a split request never has: the advisory tells
	// defenders to look for "+config-create+" in the query of a request to
	// the WordPress front end, and that is a pair this classifier alone can
	// see. Both needles are PEAR's own vocabulary and cannot appear in
	// ordinary traffic.
	return containsAny(strings.ToLower(query), "config-create", "pearcmd") ||
		containsAny(strings.ToLower(body), "config-create", "pearcmd")
}

// roundcubeSQLPayload reports a parameter value that is trying to break out
// of a SQL string literal -- the second half of roundcubeVirtuserSQLi.
//
// The token list is the generic sqli case's, widened. This runs per
// parameter value, so it sees a value rather than a whole body, and the
// families the generic case does not name -- schema enumeration, error-based
// extraction, pg_sleep -- are the ones a webmail login probe reaches for
// once the escape is defeated. Every needle is a metacharacter sequence with
// no ordinary parameter value behind it, because the cost of a wrong label
// here is every Roundcube login in the corpus turning into an alert.
//
// Matching is case-insensitive, the way the generic sqli case effectively is
// (it matches a lowercased body). SQL keyword case is the cheapest encoding
// variation there is -- the note on classifyPayload records the PHP-CGI
// probe arriving as %ADd, %25ADd and plain -d in one window -- and a class
// that matches only the published casing loses the event outright:
// measured, an uppercase `UNION SELECT` through the gate was unlabelled
// on both GET and POST (#3364).
func roundcubeSQLPayload(v string) bool {
	v = strings.ToLower(v)
	return containsAny(v,
		// A quote closed and the rest of the statement appended.
		"';", "'--", "' #", "'/*", "')",
		// Tautologies -- the cheapest thing to automate.
		"' or '", "or 1=1", "or 1'='1", "or '1'='1", "and 1=1",
		// Union, and the schema table that makes a union worth running.
		"union select", "union all select", "information_schema",
		// Time- and error-based, including the PostgreSQL sleep a
		// Roundcube install is as likely to be behind as MySQL.
		"sleep(", "benchmark(", "waitfor delay", "extractvalue(", "updatexml(") ||
		pregReplaceEscapeBypass(v)
}

// pregReplaceEscapeBypass is the other half of roundcubeSQLPayload, and the
// only part of this classifier that looks at a backslash.
//
// The root cause of CVE-2026-48842 is an escaping routine whose backslash
// handling can be defeated from inside the value it is escaping: a backslash
// immediately before the quote turns the escape into a second backslash and
// the quote closes the literal anyway. So the byte pattern worth naming is
// the pair -- backslash-quote plus a SQL metacharacter in the same value --
// and not the injection alone, which is what the generic sqli case already
// looks for.
//
// Both halves are required, and that is not belt-and-braces. On a webmail
// login form the two halves are each ordinary on their own: a lone backslash
// is a Windows path, a JSON escape or a regex, and a lone apostrophe is a
// name like O'Brien -- an address this classifier would otherwise label as
// an attack on a route whose entire job is receiving mail addresses. The
// metacharacter is what makes the escape an attempt.
//
// The metacharacter list is SQL punctuation only. A bare "-" is left out
// deliberately: it is a hyphen in an address or a date, and admitting it
// would put this class straight back on ordinary mail traffic.
func pregReplaceEscapeBypass(v string) bool {
	i := strings.Index(v, `\'`)
	if i < 0 {
		return false
	}
	rest := v[:i] + v[i+2:]
	return containsAny(rest, "'", `"`, ";", "--", "#", "/*", "*/", "=", ")")
}

// wordpressInclusionPayload reports one template-bearing value that is trying
// to make the server include something -- the second half of
// wordpressTemplateInclusion.
//
// Three families, all of them things the target application would hand to an
// include or a stream-wrapper resolver:
//
//   - traversal, at either depth, since the CVE's mechanism is a late
//     urldecode() that a scanner which has read the advisory will pre-empt;
//   - a PHP stream wrapper. `php://filter` is the interesting one here: it
//     reads an arbitrary file and base64-encodes it, with no traversal at
//     all, so the traversal-only cases cannot see it. `pear://` is not in
//     this list because PHP has no such wrapper -- the PEAR stage is caught
//     by the command channel instead;
//   - a remote include, which is the same primitive pointed at the
//     attacker's own host.
//
// What is left out is the point of the exercise. A bare "..", a slug with a
// double dot in it, and a relative path that walks up and back down are all
// absent on purpose: they are what an ordinary WordPress front end is full
// of, and one false positive here puts this class on ordinary page views.
func wordpressInclusionPayload(v string) bool {
	once := strings.ToLower(v)
	full := decodeUpTo(once, 3)
	// Traversal. In `once` the dots are still encoded, which is the shape
	// wordpressPagenameTraversal looks for; in `full` they have come back.
	if containsAny(once, "%2e%2e", "%252e") || containsAny(full, "../", "..\\") {
		return true
	}
	// Wrappers and remote URLs are matched at both depths for the same
	// reason: the value reaches the target after one more urldecode() there,
	// so a probe that pre-encodes the scheme must not read as harmless.
	if containsAny(once, phpStreamWrappers...) || containsAny(full, phpStreamWrappers...) {
		return true
	}
	return containsAny(once, remoteIncludeSchemes...) || containsAny(full, remoteIncludeSchemes...)
}

// phpStreamWrappers and remoteIncludeSchemes are the inclusion primitives
// above. Every needle is a scheme followed by its delimiter, never a bare
// word: "php" and "data" are ordinary parameter values, and a scheme without
// its "//" is not a wrapper.
var (
	phpStreamWrappers = []string{
		"php://", "phar://", "data://", "data:text/", "expect://",
		"zip://", "glob://", "rar://", "ogg://", "compress.zlib://",
	}
	remoteIncludeSchemes = []string{"http://", "https://", "ftp://", "ftps://"}
)

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

// javaStreamMagic is the four-byte header a Java serialization stream begins
// with -- STREAM_MAGIC 0xACED followed by STREAM_VERSION 5 -- and the same
// four bytes "rO0AB" is the base64 of. Named once so the classifier case
// above and javaMarker below cannot drift apart on the literal.
var javaStreamMagic = []byte{0xac, 0xed, 0x00, 0x05}

// javaMarker names the Java serialization marker observed in the captured
// bytes, or "" when there is none (#3212). "stream-magic" and
// "stream-magic-base64" say a marker was seen. They do not say an object
// graph was valid, a gadget was named, or anything executed -- nothing here
// can, and nothing here tries.
//
// Byte patterns only. No ObjectInputStream, no class loading, no
// instantiation of anything that arrived over the socket: the sole decode
// performed is base64's, on eight characters, to check whether they decode to
// four known bytes -- a comparison, not a parse. A received stream is never
// read as a stream, only compared against four literals.
//
// This is a SEPARATE field, not a new payload_class, and that is the whole
// point of it. classifyPayload is an ordered first-match-wins classifier, and
// its "serialized-object" value is shared with PHP's serialize(); splitting
// Java out of that value would repurpose a class existing queries already
// mean, and would lose the PHP case the moment a Java-looking body arrived
// first. Kept separate, a request can carry both at once: a body that trips
// "sqli" three cases earlier and also starts with the Java header keeps
// payload_class "sqli" AND java_marker "stream-magic", so neither observation
// erases the other.
func javaMarker(body []byte) string {
	// Offset 0 only. A serialization stream starts with this header, so
	// that is the only position where seeing it means what it says. The
	// classifier's Contains above accepts the four bytes anywhere in the
	// body; that looser class label stays exactly as it was, and this field
	// reports the narrower observation it is able to stand behind.
	if bytes.HasPrefix(body, javaStreamMagic) {
		return "stream-magic"
	}
	// The same header transported as base64 text, which is how it arrives
	// when the payload is submitted as a form value. Verified rather than
	// assumed: eight characters is the shortest run that can carry four
	// bytes, so a body that merely starts with the five-character "rO0AB"
	// is a coincidental prefix and is not evidence of anything. That is
	// the whole difference between this and the classifier's HasPrefix.
	const b64Run = 8
	if bytes.HasPrefix(body, []byte("rO0AB")) && len(body) >= b64Run {
		if decoded, err := base64.StdEncoding.DecodeString(string(body[:b64Run])); err == nil &&
			bytes.Equal(decoded, javaStreamMagic) {
			return "stream-magic-base64"
		}
	}
	return ""
}

// bodyCaptureMaxBytes is how much of a request body this sensor keeps. The
// value is unchanged from the io.LimitReader(64<<10) it replaces -- a bounded
// capture is the point, and an unbounded one is the denial of service an
// attacker picks the size of. What #3212 adds is the record of WHICH bound
// was hit, so a reader can tell a short body from a clipped one.
const bodyCaptureMaxBytes = 64 << 10

// bodyEvidenceMaxBytes is how much of the captured prefix is also retained
// as a byte-safe head. Sized for the job the head exists to do: hold any
// serialization header, its class descriptor and the class name, which is
// what the marker evidence is about, in a few hundred bytes. It is not sized
// to reproduce a body -- body_sha256 covers the whole captured prefix, and
// nothing in the fleet reads a 64 KiB body out of a log line to re-hash it.
//
// It also has to stay under the 32000-character ignore_above on the
// flattened `honeypot` field (honeypot-init's elasticsearch-setup.sh), or the
// value stops being indexed and only survives in _source -- so 4 KiB raw,
// 5464 characters of base64, against a 32000-character ceiling. The test
// asserts that margin rather than trusting the arithmetic.
const bodyEvidenceMaxBytes = 4 << 10

// The three capture states, and the two fixed strings that make the rest of
// the block self-describing: the encoding of body_b64, and the scope
// body_sha256 covers. Both are recorded on the event rather than left to
// documentation, because a consumer reading a log line three months from now
// does not have this file.
const (
	captureComplete  = "complete"
	captureTruncated = "truncated"
	captureUnknown   = "unknown"

	bodyEvidenceEncoding = "base64"

	// bodySHA256Scope names both axes the hash is bounded on, because
	// "captured-prefix" alone would now be a half-truth: it says which part
	// of the body is covered, and says nothing about the fact that the bytes
	// covered are the credential-scrubbed ones (#3213). A reader comparing
	// this hash against a body they hold elsewhere would get a mismatch on
	// any request that carried a credential, with no field on the event to
	// explain it -- which is the "hash whose scope is ambiguous" defect this
	// field exists to prevent, reintroduced one axis over. So the value says
	// "a prefix, and post-redaction", and a body with no credential in it
	// hashes identically under either reading, because redaction is a no-op
	// there.
	bodySHA256Scope = "captured-prefix-redacted"
)

// bodyCapture is what came off the wire and how much of it that was. Bytes
// is the captured prefix, never longer than bodyCaptureMaxBytes.
type bodyCapture struct {
	Bytes []byte
	// Truncated records that more bytes existed than were kept. It is a
	// fact about the cap, independent of ReadErr.
	Truncated bool
	// ReadErr is whatever ended the read early. A non-nil error means
	// completeness is not knowable, whatever the length.
	ReadErr error
}

// state is the one authoritative answer to "is this the whole body". The two
// failure facts are separate fields because a single string cannot carry
// both: a body that hit the cap AND whose read then failed is reported as
// truncated (the cap is a fact; the error is in BodyReadError) rather than
// as unknown, which would discard something that is known.
func (c bodyCapture) state() string {
	switch {
	case c.Truncated:
		return captureTruncated
	case c.ReadErr != nil:
		return captureUnknown
	default:
		return captureComplete
	}
}

// captureBody reads at most bodyCaptureMaxBytes of r, and says which of the
// three things happened.
//
// One byte past the cap is the whole trick: a read that stops exactly at the
// limit is indistinguishable from a body of precisely that size, so
// truncating to the cap and reporting nothing is the ambiguity this exists
// to remove. Reading one more byte is what makes "there was more" knowable.
//
// The read error is returned rather than dropped, which is the other half of
// it: the old `body, _ := io.ReadAll(...)` threw away the only signal that
// the capture was not what it appeared to be.
func captureBody(r io.Reader) bodyCapture {
	data, err := io.ReadAll(io.LimitReader(r, bodyCaptureMaxBytes+1))
	if len(data) > bodyCaptureMaxBytes {
		return bodyCapture{Bytes: data[:bodyCaptureMaxBytes], Truncated: true, ReadErr: err}
	}
	return bodyCapture{Bytes: data, ReadErr: err}
}

// apply records the capture's completeness, its byte-safe evidence and the
// hash of exactly the bytes it is allowed to publish onto e. The state is
// written even for a zero-byte capture -- a request with no body is genuinely
// a short body, and answering "complete" is what distinguishes it from a
// clipped one.
//
// redacted is the credential-scrubbed body (#3213's creds.redactedBody),
// passed in rather than recomputed here so that this cannot become a second
// redaction path with its own rules. It is deliberately NOT c.Bytes: the
// completeness fields below describe the CAPTURE, which is a fact about what
// came off the wire and is unaffected by redaction, while the two evidence
// fields describe the PUBLISHED bytes, which are the redacted ones. Both are
// recorded because both are true and they answer different questions -- "how
// much arrived" and "what are you allowed to see" are not the same question,
// and answering only the first would still be a leak.
//
// The consequence, stated rather than hidden: when redaction shortened the
// body, the retained head and the hash are of the redacted form, so
// len(decode(body_b64)) can be less than body_captured_bytes. That is the
// redaction working, and BodySHA256Scope is what says so on the event.
func (c bodyCapture) apply(e *event, redacted string) {
	e.BodyCaptureState = c.state()
	e.BodyCapturedBytes = len(c.Bytes)
	if c.ReadErr != nil {
		e.BodyReadError = c.ReadErr.Error()
	}
	if redacted == "" {
		// Nothing to preserve and nothing to identify. The sha256 of the
		// empty string is a real hash of the empty string, and carrying it
		// on every bodyless request would be noise wearing a hash's clothes.
		return
	}
	published := []byte(redacted)
	head := published
	if len(head) > bodyEvidenceMaxBytes {
		head = head[:bodyEvidenceMaxBytes]
	}
	e.BodyEncoding = bodyEvidenceEncoding
	e.BodyB64 = base64.StdEncoding.EncodeToString(head)
	sum := sha256.Sum256(published)
	e.BodySHA256 = hex.EncodeToString(sum[:])
	e.BodySHA256Scope = bodySHA256Scope
}

// declaredLength is the Content-Length the request claimed, or 0 when it
// claimed nothing usable. A claim, never a fact: it is written by the
// attacker, it disagrees with the wire as often as not, and it exists here
// only so "we kept 64 KiB" can be read as "we kept 64 KiB of 4 MB" when --
// and only when -- the client was straight about it.
//
// Read from the header, falling back to the value net/http parsed out of that
// same header, so the field describes the wire rather than one particular
// way of asking for it. A chunked request arrives as -1 and has no declared
// length to record, which is 0 here rather than a made-up number.
func declaredLength(r *http.Request) int64 {
	raw := strings.TrimSpace(r.Header.Get("Content-Length"))
	if raw == "" {
		if r.ContentLength > 0 {
			return r.ContentLength
		}
		return 0
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
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
	// #2919: CVE-2026-9586, Sangoma Switchvox unauth SQLi/RCE via the
	// public /pa endpoint's PhoneIP XML field, mass-exploited since
	// 2026-08-30. Exact match, not Contains -- "/pa" is short enough that a
	// substring match would false-positive on unrelated paths, and the
	// vulnerable route itself is exact. This fleet runs no Switchvox
	// instance; the value is recognizing the campaign's own signature
	// against the generic decoy rather than letting it fall into
	// undifferentiated "scan", same reasoning as the wordpress-cve cases
	// above.
	case p == "/pa":
		return "switchvox-cve-2026-9586"
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
	// #3394, OllamaDrama/Ollure (arXiv 2609.29757): the Ollama-native half
	// of the same management API. Its own summary is that 79.36% of 290,887
	// observed interactions went to model- and service-information endpoints,
	// and the largest single one (/api/tags, 102,795) has no entry here at
	// all -- it fell to "scan", indistinguishable from a web port rake.
	//
	// Its own category rather than a branch of llm-api, because the paper
	// measures the two behaving differently: 102,795 requests from 979 IPs
	// against 60,949 from 203. Which dialect a scanner has decided to hunt
	// is the thing worth being able to count, and folding the Ollama half
	// into the OpenAI half would erase the answer.
	//
	// Exact match against a fixed list, not a prefix, for the reason
	// switchvox-cve-2026-9586 above gives: /api/v1/ and /apis/ are the
	// Kubernetes cases and are matched before this, and a bare /api/ prefix
	// would swallow every other decoy route that happens to start /api.
	// /api/copy is on the list even though the paper records zero
	// interactions against it, because a scanner asking for it is still
	// asking for it and the list is the surface, not the traffic.
	case ollamaAPIPath(p):
		return "ollama-api"
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
	// launder (#3447): the bounded cross-request component, and the only
	// state this package keeps between requests. Nil disables it, which is
	// how HTTP_LAUNDERING=0 is expressed -- see laundering.go, which also
	// answers #3447's two design questions (where the state lives, and what
	// bounds it). Consulted after classifyPayload, and only into an empty
	// PayloadClass, so it stays the last case rather than the first.
	launder *launderingState
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

	// #3212: read through captureBody instead of a bare LimitReader. The
	// cap is the same 64 KiB it always was, and it is bodyReadCap's value:
	// #3213's credential pass reads the same bytes, so the two have to
	// agree on where "all of it" ends. What the event now carries is which
	// of "all of it", "a bounded prefix" and "we never found out" this
	// request was, so that a 40-byte POST and the first 64 KiB of a 4 MB
	// upload stop being the same record.
	capture := captureBody(r.Body)
	r.Body.Close()
	body := capture.Bytes

	// #3213: one pass over every channel that can carry a credential,
	// answering three questions the event used to answer badly or not at
	// all -- was a credential present, could it be read, and what (if
	// anything) did the decoy decide about it. classifyPayload still sees
	// the raw body and query: redaction must not cost the fleet a payload
	// signature, and the two passes are independent.
	creds := inspectCredentials(r, string(body))

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
		Query:        creds.redactedQuery,
		UserAgent:    r.UserAgent(),
		Headers:      headerMap(r),
		Body:         creds.redactedBody,
		Category:     classify(r.URL.Path),
		PayloadClass: classifyPayload(r.URL.RawQuery, string(body)),
		// The three #3213 axes. AuthOutcome stays authUnknown until a
		// branch in serve() decides this response was an artifact of the
		// decoy's simulated authentication surface -- and no branch ever
		// sets it from the status code.
		CredentialStatus:         string(creds.status),
		CredentialPresent:        creds.present(),
		CredentialIndicatorMatch: creds.indicator != "",
		CredentialIndicator:      creds.indicator,
		AuthOutcome:              string(authUnknown),
		Username:                 creds.username,
		AuthType:                 creds.authType,
		// Recorded from the raw bytes, independently of PayloadClass: an
		// earlier case in that ordered switch must not be able to erase
		// the fact that a Java marker was seen, and vice versa. Byte
		// patterns only, and detection rather than disclosure, so these read
		// the raw body the way classifyPayload does -- what leaves the
		// process is a fixed marker name, never a byte of the payload.
		JavaMarker:        javaMarker(body),
		BodyDeclaredBytes: declaredLength(r),
	}
	// The evidence of what was captured is built from the SAME redacted
	// string Body was just given, never from string(body). Before #3213
	// these bytes were safe to publish because `body` already published
	// them; that stopped being true when `body` was redacted, and had this
	// call still read the raw capture it would have made body_b64 the only
	// copy of a submitted credential anywhere in the event. One string, two
	// fields -- the two cannot drift apart, and neither is a way around
	// inspectCredentials.
	capture.apply(&e, creds.redactedBody)

	// #3447 layer C, and the reason the state has to be here and not in the
	// classifier: this is a decision about two requests, so it cannot be made
	// by classifyPayload, which sees one. It runs after the event literal
	// because it reads r.URL.Path -- the value #3430's bypass rides and
	// #3443 was never given -- and before the reply, so the class is on the
	// event that gets logged either way.
	s.observeLaundering(r, &e, string(body))

	if s.tarpitEnabled && tarpitCategory(e.Category) {
		e.Status = http.StatusOK
		e.Tarpitted = true
		// A tarpit is the absence of a decision: the request was slowed
		// and never answered, so there is no authentication outcome to
		// report and authUnknown is the honest one. The 200 above is a
		// drip stream completing, not an authentication result.
		n, held := tarpit(r.Context(), w)
		e.TarpitBytes = n
		e.TarpitMS = held.Milliseconds()
	} else {
		s.serve(w, r, &e)
	}
	s.log.log(e)
}

// serve writes a plausible response and records the status code onto e.
//
// #3213: the branches that answer from the decoy's simulated
// authentication surface also record auth_outcome=simulated. That is a
// statement about provenance -- this response was chosen by the persona,
// not by any authentication backend -- and it is set by the branch, never
// derived from the status code. A 200 here is the decoy working, and the
// two 200s below (a login page rendering; a fake model list for a bearer
// token that was never checked against anything) are exactly why the
// status code cannot answer this question.
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
		// An authorization decision made by the decoy's simulated
		// Kubernetes API, for the anonymous user. Simulated, not real: no
		// RBAC was consulted, and the 403 is the persona's answer.
		e.AuthOutcome = string(authSimulated)
		writeJSON(w, http.StatusForbidden, `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"forbidden: User system:anonymous cannot access this resource","reason":"Forbidden","code":403}`)

	case p == "/v2/":
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.registry.nexusai.internal/token",service="registry.nexusai.internal"`)
		e.Status = http.StatusUnauthorized
		e.AuthOutcome = string(authSimulated)
		writeJSON(w, http.StatusUnauthorized, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`)

	case strings.HasPrefix(p, "/v1/models"), strings.HasPrefix(p, "/v1/chat/completions"):
		if e.AuthType != "bearer" {
			e.Status = http.StatusUnauthorized
			e.AuthOutcome = string(authSimulated)
			writeJSON(w, http.StatusUnauthorized, `{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","code":"invalid_api_key"}}`)
		} else {
			// The branch #3213 is really about. A 200 here, for a token
			// nobody validated: the outcome is the decoy's own simulated
			// answer, and reading this status as a successful
			// authentication is the inference the issue forbids. Nothing
			// in this binary can record authReal.
			e.Status = http.StatusOK
			e.AuthOutcome = string(authSimulated)
			writeJSON(w, http.StatusOK, `{"object":"list","data":[{"id":"nexusai-chat-70b-v3","object":"model","owned_by":"nexusai-mlops"},{"id":"nexusai-embed-bge-v1","object":"model","owned_by":"nexusai-mlops"}]}`)
		}

	case strings.HasPrefix(p, "/manager/html") || strings.Contains(p, "jmx-console"):
		// Tomcat manager — challenge for Basic auth so scanners submit creds.
		if e.AuthType == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
			e.Status = http.StatusUnauthorized
			e.AuthOutcome = string(authSimulated)
			writeHTML(w, http.StatusUnauthorized, tomcat401)
		} else {
			// A submitted credential earns a simulated rejection. The
			// decoy has no account store to accept or reject against, and
			// the 403 is a persona's page, not a verdict.
			e.Status = http.StatusForbidden
			e.AuthOutcome = string(authSimulated)
			writeHTML(w, http.StatusForbidden, tomcat403)
		}

	case strings.Contains(p, "wp-login") || strings.Contains(p, "wp-admin"):
		// The WordPress login page over 200. status=200 here means the page
		// rendered; auth_outcome=simulated is what says the authentication
		// surface answered, and neither field says anybody was let in.
		e.Status = http.StatusOK
		e.AuthOutcome = string(authSimulated)
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
		writeXML(w, http.StatusOK, wpXMLRPCFault)

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

	case p == "/pa":
		// #2973 / CVE-2026-9586: the Sangoma Switchvox provisioning endpoint
		// the classifier already recognises (see classify()). Exact match for
		// the same reason it is exact there -- "/pa" is short enough that a
		// substring match would swallow unrelated paths.
		//
		// A real vulnerable appliance answers a provisioning request it
		// cannot parse with an XML error envelope over HTTP 200, not a 404:
		// neither a bare GET probe nor a PhoneIP field stuffed with SQL is a
		// well-formed request, so both land here. The exploitation attempt
		// itself is already captured onto e.Body by ServeHTTP before this
		// runs -- answering plausibly is what buys the follow-on request.
		//
		// The Server header stays the persona's (#2926): this fleet presents
		// one host with one banner, and a /pa that suddenly claimed a
		// different server than / would be the inconsistency that gives the
		// decoy away.
		e.Status = http.StatusOK
		writeXML(w, http.StatusOK, switchvoxPAFault)

	case strings.Contains(p, "phpmyadmin") || strings.Contains(p, "/pma") || strings.Contains(p, "adminer"):
		// A database console's login form, rendered over 200. The 200 is
		// the page rendering; the fact that the decoy's authentication
		// surface answered is auth_outcome, and neither says a login
		// succeeded.
		e.Status = http.StatusOK
		e.AuthOutcome = string(authSimulated)
		writeHTML(w, http.StatusOK, phpMyAdmin)

	case strings.Contains(p, "login") || strings.Contains(p, "admin") || strings.Contains(p, "signin"):
		// Generic login page. Posted creds are already captured above (as a
		// presence/extraction answer, never as text). A 200 here is the
		// form rendering, so #3213's "status is not an auth verdict" is
		// not a hypothetical here -- it is this branch.
		e.Status = http.StatusOK
		e.AuthOutcome = string(authSimulated)
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

// writeXML is the same mechanism as its siblings, for the endpoints that
// answer in XML. It exists because setting Content-Type at the call site and
// then calling writeHTML does not work -- writeHTML sets the header itself,
// so the XML declared by the caller went out as text/html (#2973).
func writeXML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/xml; charset=UTF-8")
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
		// #3447. On by default, like the tarpit, and off the same way
		// (HTTP_LAUNDERING=0), because a detector whose evidence cap has been
		// reached has void coverage and an operator needs the switch. The
		// three bounds are configurable because they are the answer to
		// #3447's second design question and an operator has to be able to
		// move them; the defaults are the values argued for in laundering.go.
		launder: func() *launderingState {
			if getenv("HTTP_LAUNDERING", "1") == "0" {
				return nil
			}
			return newLaunderingState(
				int(getenvInt64("LAUNDER_MAX_ENTRIES", launderMaxEntries)),
				int(getenvInt64("LAUNDER_PER_FINGERPRINT", launderPerFingerprint)),
				time.Duration(getenvInt64("LAUNDER_TTL_SECONDS", int64(launderTTL/time.Second)))*time.Second,
			)
		}(),
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
