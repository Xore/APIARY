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
	"os"
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

// javaStreamMagic is the four-byte header a Java serialization stream begins
// with -- STREAM_MAGIC 0xACED followed by STREAM_VERSION 5 -- and the same
// four bytes "rO0AB" is the base64 of. Named once so the classifier case in
// classify_generic.go and javaMarker below cannot drift apart on the literal.
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
	// classifier's Contains (serializedObject, in classify_generic.go)
	// accepts the four bytes anywhere in the body; that looser class label
	// stays exactly as it was, and this field reports the narrower
	// observation it is able to stand behind.
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
