// webvpn.go ports asa_server.py's WebLogicHandler (#238, #414): the Cisco
// ASA WebVPN HTTPS decoy for CVE-2018-0101 (a crafted host-scan-reply POST
// body crashes/exploits a real ASA; here it's just captured and logged).
package main

import (
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// asaFiles mimics upstream's asa/ directory: send_file(filename) looks up
// a file by basename only (SimpleHTTPRequestHandler.send_file semantics),
// regardless of the rest of the request path.
var asaFiles = map[string]string{
	"wrong_url.html":   ciscoWrongURLPage,
	"logon_redir.html": ciscoLogonRedirPage,
	"logon_failure":    ciscoLogonFailurePage,
	"logon.html":       ciscoLogonPage,
	"blank.html":       "",
	"index.html":       ciscoRootRedirectPage,
}

const exploitString = "host-scan-reply"

// canned VPN-parse-error response upstream always returns for a POST that
// isn't specifically handled otherwise (WebLogicHandler.RESPONSE).
const asaParseErrorResponse = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
<version who="sg">9.0(1)</version>
<error id="98" param1="" param2="">VPN Server could not parse request.</error>
</config-auth>`

type webvpnHandler struct {
	log  *logger
	port int
}

// webvpnExchange is one request's in-flight state: the request, the
// credential answer, and the events raised so far.
//
// #3213 moved the logging to AFTER the response is written, and this is
// what that costs. Before, log2 emitted the event as each branch started
// and the event therefore had no idea what the decoy was about to serve.
// The new schema puts `status` on the event, which means the branch cannot
// know it until the branch has finished -- so the branches stage their
// events here and ServeHTTP flushes them once the response writer knows the
// status.
//
// The staging is per-request rather than per-handler on purpose: one
// webvpnHandler serves every connection, so pending state on the handler
// itself would be a data race under the concurrency a decoy is supposed to
// attract.
type webvpnExchange struct {
	h     *webvpnHandler
	r     *http.Request
	creds asaCredentialFinding
	// status is filled in by the statusRecorder as the response is
	// written, and copied onto every staged event at flush time.
	status int
	// authOutcome is set by whichever branch is serving an artifact of the
	// decoy's own authentication surface, and is copied onto every staged
	// event at flush time for the same reason status is. It is never
	// derived from status: this decoy serves the "Login failed" page over
	// 200 and a parse-error envelope over 200, and #3213's acceptance
	// criteria refuse the inference "200 = authentication succeeded".
	authOutcome authOutcome
	pending     []event
}

// log2 stages one event for this request. It is the same call shape as
// before #3213 and the same event kinds, so nothing downstream of the log
// line has to change; the difference is that the line is written at flush
// time, with the status attached.
func (x *webvpnExchange) log2(kind, reqPath, data string) {
	ip, port := webvpnSrcIP(x.r)
	// Two redaction paths, because the two Data values are different
	// shapes. The POST body is a form or a protocol payload, so it goes
	// through the same content-type-aware scrubber the credential answer
	// used -- the stored copy and the credential decision are derived from
	// the same raw bytes on purpose. The host-scan-reply payload is XML
	// full of addresses, so it goes through the shape-agnostic scrubber.
	//
	// The unredacted body is what parseHostScanReplies needs and is still
	// what it reads; only the stored copy is scrubbed. Redacting before
	// the parse would corrupt exactly the signature this decoy exists to
	// capture, and TestCVEPayloadSurvivesRedaction is what holds that
	// trade-off honest.
	stored, _ := redactOpaque(data)
	if kind == "post" {
		stored = x.creds.redactedBody
	}
	x.pending = append(x.pending, event{
		Port: x.h.port, SrcIP: ip, SrcPort: port, Event: kind,
		Path: reqPath, Query: x.creds.redactedQuery, Data: stored,
		UserAgent:                x.r.UserAgent(),
		Headers:                  webvpnHeaderMap(x.r),
		CredentialStatus:         string(x.creds.status),
		CredentialPresent:        x.creds.present(),
		CredentialIndicatorMatch: x.creds.indicator != "",
		CredentialIndicator:      x.creds.indicator,
		Username:                 x.creds.username,
		AuthType:                 x.creds.authType,
		DecoySessionPresent:      x.creds.decoySession,
	})
}

// flush emits every staged event, with the status this request actually
// served and the authentication outcome the serving branch recorded
// attached to each.
//
// Both are applied here rather than at stage time because the branch that
// decides the outcome runs AFTER the event is staged -- servePOST logs the
// "post" event and only then works out which of five responses it is
// about to give. Reading the outcome off the exchange at flush time is
// what keeps those two facts from disagreeing.
func (x *webvpnExchange) flush() {
	for _, e := range x.pending {
		e.Status = x.status
		e.AuthOutcome = string(x.authOutcome)
		x.h.log.emit(e)
	}
	x.pending = nil
}

// statusRecorder remembers the status a handler wrote.
//
// The alternative was threading a status return value through every branch
// of serveGET/servePOST, and there are a dozen of them across two
// functions; a recorder that observes the write is the same information for
// none of that churn, and it cannot drift out of sync with what was
// actually served the way a hand-passed value can.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		// net/http's own default for a handler that writes without
		// calling WriteHeader.
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func webvpnSrcIP(r *http.Request) (string, int) {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// webvpnHeaderMap flattens net/http's []string-per-key header representation
// into one string per key -- which client hit this decoy, and with what
// else, was previously available on every request and simply never read.
//
// #3213: the value of every header that IS a credential is replaced rather
// than shortened. Authorization carries the password (base64, which is
// encoding, not protection) and Cookie carries the session tokens an
// attacker will replay; neither is a fact about the request that a log line
// needs verbatim. The header name survives, so "did this request attempt to
// authenticate at all" stays answerable.
func webvpnHeaderMap(r *http.Request) map[string]string {
	m := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		m[k] = strings.Join(v, ", ")
	}
	return redactSecretHeaders(m)
}

func (h *webvpnHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// #3213: one pass over every channel that can carry a credential, and
	// one read of the body that both the credential answer and the
	// CVE-2018-0101 parse are made from. The read cap is the credential
	// one (bodyReadCap), not the 1 MiB one further down: the exploit
	// payload is genuinely large and must be captured whole, while the
	// credential question has to be able to say "I could not read all of
	// it" -- which is the only way credential_status=unknown becomes
	// reachable on this sensor.
	body, _ := io.ReadAll(io.LimitReader(r.Body, bodyReadCap))
	r.Body.Close()
	x := &webvpnExchange{h: h, r: r, creds: inspectASACredentials(r, string(body))}

	rec := &statusRecorder{ResponseWriter: w}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		x.serveGET(rec, r)
	case http.MethodPost:
		x.servePOST(rec, r, string(body))
	default:
		rec.WriteHeader(http.StatusOK)
	}
	if rec.status == 0 {
		// A handler that wrote nothing at all. net/http would answer 200,
		// so the event says 200 rather than reporting a status that never
		// happened.
		rec.status = http.StatusOK
	}
	x.status = rec.status
	x.flush()
}

func clearedCookies() []string {
	return []string{
		"tg=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpn=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpn_portal=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpnSharePoint=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
		"webvpnlogin=1; path=/; secure",
		"sdesktop=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure",
	}
}

func (h *webvpnHandler) redirect(w http.ResponseWriter, loc string) {
	for _, c := range []string{"tg=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure"} {
		w.Header().Add("Set-Cookie", c)
	}
	w.Header().Set("Location", loc)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusFound)
}

func (h *webvpnHandler) sendFile(w http.ResponseWriter, name string, status int) {
	body, ok := asaFiles[name]
	if !ok {
		if name != "wrong_url.html" {
			h.sendFile(w, "wrong_url.html", http.StatusNotFound)
			return
		}
		body = ciscoWrongURLPage
	}
	if status == http.StatusOK {
		for _, c := range clearedCookies()[1:5] {
			w.Header().Add("Set-Cookie", c)
		}
		w.Header().Add("Set-Cookie", "webvpnlogin=1; secure")
		w.Header().Set("Cache-Control", "max-age=0")
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func (x *webvpnExchange) serveGET(w http.ResponseWriter, r *http.Request) {
	h := x.h
	reqPath := r.URL.Path
	x.log2("get", reqPath, "")

	// Upstream compares against self.path, which (unlike Go's r.URL.Path)
	// includes the raw query string -- so its bare-path check only matches
	// a request with NO query string at all, and "?reason=1" always falls
	// to the second branch instead. Checking RawQuery here keeps that
	// same precedence.
	if reqPath == "/+CSCOE+/logon.html" && r.URL.RawQuery == "" {
		// A redirect INTO the logon page: the decoy's authentication
		// surface answering, so auth_outcome says so. The 302 is a
		// redirect, not a verdict on any credential.
		x.authOutcome = authSimulated
		h.redirect(w, "/+CSCOE+/logon.html?fcadbadd=1")
		return
	}
	if reqPath == "/+CSCOE+/logon.html" && strings.Contains(r.URL.RawQuery, "reason=1") {
		// The "Login failed" page, over 200. This is the branch that
		// makes #3213's refusal of "200 = authentication succeeded"
		// concrete on this sensor: a rejection, served as a 200, by a
		// decoy with no account store behind it.
		x.authOutcome = authSimulated
		h.sendFile(w, "logon_failure", http.StatusOK)
		return
	}

	if reqPath == "/" {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Pragma", "no-cache")
		for _, c := range clearedCookies() {
			w.Header().Add("Set-Cookie", c)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(ciscoRootRedirectPage))
		return
	}

	name := path.Base(strings.TrimRight(strings.SplitN(reqPath, "?", 2)[0], "/"))
	if name == "asa" {
		h.sendFile(w, "wrong_url.html", http.StatusForbidden)
		return
	}
	// Any other known file is a static page of the decoy's own portal. The
	// logon page and the portal index are artifacts of the simulated
	// authentication surface; a wrong-url or a readme is not, and saying
	// otherwise would make auth_outcome meaningless by inflation.
	if name == "logon.html" || name == "logon_redir.html" {
		x.authOutcome = authSimulated
	}
	h.sendFile(w, name, http.StatusOK)
}

func (x *webvpnExchange) servePOST(w http.ResponseWriter, r *http.Request, body string) {
	h := x.h
	x.log2("post", r.URL.Path, body)

	respBody := asaParseErrorResponse

	if strings.Contains(body, exploitString) {
		// The CVE-2018-0101 path. Authenticated? No -- nothing about this
		// branch consults a credential, so auth_outcome stays unknown
		// rather than being borrowed from the 200 the canned parse-error
		// response is served with.
		if payloads := parseHostScanReplies([]byte(body)); len(payloads) > 0 {
			for _, p := range payloads {
				x.log2("cve_2018_0101_payload", r.URL.Path, p)
			}
		}
	} else if r.URL.Path == "/" {
		x.authOutcome = authSimulated
		h.redirect(w, "/+webvpn+/index.html")
		return
	} else if r.URL.Path == "/+CSCOE+/logon.html" {
		// A submitted logon form. Upstream redirects to the same page
		// with ?fcadbadd=1, which is this decoy's rejection -- and a
		// rejection is still the persona's answer, not a verdict from a
		// verifier that does not exist here.
		x.authOutcome = authSimulated
		h.redirect(w, "/+CSCOE+/logon.html?fcadbadd=1")
		return
	} else if strings.SplitN(r.URL.Path, "?", 2)[0] == "/+webvpn+/index.html" {
		x.authOutcome = authSimulated
		respBody = ciscoLogonRedirPage
	} else if r.URL.Path == "/+CSCOE+/login.html" {
		x.authOutcome = authSimulated
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(respBody))
}

// parseHostScanReplies extracts every <host-scan-reply> element's text
// content, matching upstream's `xml.iter('host-scan-reply')`. Malformed
// XML (a crafted exploit attempt need not be well-formed) yields no
// payloads rather than an error -- an honeypot has no obligation to make
// sense of attacker input, only to never crash on it.
func parseHostScanReplies(data []byte) []string {
	type node struct {
		XMLName xml.Name
		Content string `xml:",chardata"`
		Nodes   []node `xml:",any"`
	}
	var root node
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil
	}
	var out []string
	var walk func(n node)
	walk = func(n node) {
		if n.XMLName.Local == "host-scan-reply" {
			out = append(out, strings.TrimSpace(n.Content))
		}
		for _, c := range n.Nodes {
			walk(c)
		}
	}
	walk(root)
	return out
}
