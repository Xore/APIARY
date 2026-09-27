// credentials.go answers the three questions #3213 says the ASA WebVPN
// decoy's event was conflating, and it answers them separately, because
// they are separate facts about a request:
//
//  1. What did the decoy serve back?            -> Status (webvpn.go)
//  2. Did the request carry credentials, and could they be read? ->
//     CredentialStatus / CredentialPresent / AuthType (this file)
//  3. Was an authentication decision made, and by whom? -> AuthOutcome
//     (this file)
//
// This is a twin of http-honeypot/credentials.go, not a shared package:
// the two sensors are separate Go modules with no dependency on each other,
// and the only thing they share is the vocabulary. Where the ASA differs
// materially it says so below rather than being made to look identical --
// in particular the session-correlation section, which is the one place
// this fleet has genuine session signal and where inventing a join key
// would have been easy and wrong.
//
// #3213's secret-handling rule is a trust boundary, not a preference: a
// captured password is never stored, logged, or returned. Only the
// booleans below survive. The `data` field is the reason this file exists
// at all on this sensor -- before it, a POSTed WebVPN logon form was
// written to the event verbatim, username and password both, and that body
// is the single most ordinary thing an attacker sends to this port.
//
// The IKE side is in the same log and is explicitly NOT covered by the
// extraction below: an IKE packet's identity and key material are not read
// by this decoy, so its events are filed as credential_status=unknown
// rather than being left to imply "absent" by omission. See logger.emit.

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"
)

// credentialStatus is the presence/extraction axis: what the sensor was
// able to learn about the credentials in one request. Exactly one of these
// rides on every event.
//
// The three states #3213 names are credAbsent, credUnparsed and
// credUnknown. credExtracted is the fourth because the success case cannot
// honestly be spelled with any of the three: a form body the sensor mapped
// onto a username is neither absent (material was there), nor
// present-but-unparsed (it was parsed), nor unknown (the sensor knows). It
// is reported as its own state rather than folded into one of the three,
// because every fold of it is a claim this sensor cannot make.
type credentialStatus string

const (
	// credAbsent: every channel that can carry credentials (the
	// Authorization header, a form-urlencoded body, a JSON body, the
	// query string) was read in full and none of them held credential
	// material. This is a positive finding, not a default.
	credAbsent credentialStatus = "absent"
	// credExtracted: credential material was present and this sensor
	// mapped it onto fields. The username survives (see
	// asaCredentialFinding.username for why); the secret half does not.
	credExtracted credentialStatus = "extracted"
	// credUnparsed: credential material was present and this sensor
	// could not read it -- an Authorization scheme it does not decode, a
	// base64 value that does not decode, a credential-shaped field in a
	// body shape it does not parse. Distinct from credAbsent on purpose:
	// "there is something here I could not read" and "there is nothing
	// here" are different facts and must not share a value.
	credUnparsed credentialStatus = "present_unparsed"
	// credUnknown: the sensor could not tell. The body hit the read cap
	// (so its tail was never seen), or it is a byte stream whose contents
	// no key scan can speak for, or -- on this sensor -- it is an IKE
	// packet, which goes through no credential inspection at all. This
	// state exists so the unreadable case has somewhere to go that is NOT
	// credAbsent: filing a truncated logon POST as credential-free is how
	// a scan of the data would learn to trust the wrong number.
	credUnknown credentialStatus = "unknown"
)

// authOutcome is the provenance axis: when this response was an
// authentication artifact, where the decision came from, and nothing else.
//
// It deliberately carries no accept/reject verdict. The HTTP status
// already says what was served, and #3213's own acceptance criteria refuse
// the inference "status 200 = authentication succeeded" -- which on this
// decoy is not hypothetical. A GET of /+CSCOE+/logon.html?reason=1 serves
// the "Login failed" page over 200, a POSTed logon form is answered with a
// 302 to the same page, and an unparseable POST is answered with a
// parse-error envelope over 200. Every one of those is a 200 or a 302
// from a decoy with no account store behind it.
type authOutcome string

const (
	// authSimulated: the response the decoy chose was an artifact of its
	// own simulated authentication surface -- the logon page, the logon
	// failure page, the portal redirect, the canned parse error. The
	// decision is the persona's, by construction.
	authSimulated authOutcome = "simulated"
	// authReal: an authentication decision was made by a real
	// authentication backend. Nothing in this decoy can produce it --
	// there is no backend, no account store, no verifier. It exists in
	// the vocabulary because the axis is about provenance, and a sensor
	// that did delegate would have to say so. auth_outcome is never
	// derived from a status code anywhere in this binary; see
	// TestAuthRealIsUnreachable in webvpn_test.go for the test that pins
	// that.
	authReal authOutcome = "real"
	// authUnknown: no authentication decision was made for this request.
	// The CVE-2018-0101 payload path, a static file, a 403 wrong-url, a
	// bare GET of "/".
	authUnknown authOutcome = "unknown"
)

// asaCredentialFinding is one request's answer on the presence/extraction
// axis, before it is copied onto the event.
type asaCredentialFinding struct {
	status credentialStatus
	// authType is the channel: "form", "basic", or the lowercased name of
	// an Authorization scheme this sensor does not decode. Empty when the
	// request carried no credential material. It says which channel,
	// never what was in it.
	authType string
	// username is the account identifier only. A submitted username is
	// the analytic value here -- it is how a spray is recognised as a
	// spray -- and it is not a secret. The password half of the same
	// credential is never assigned anywhere.
	username string
	// indicator is the scope label of a matched FICTIONAL decoy
	// credential ("<product>/<account>"), empty when nothing matched.
	indicator string
	// decoySession is true when the request carried one of this decoy's
	// OWN cookie values -- see decoySessionCookies for what that is and,
	// just as importantly, what it is not.
	decoySession bool
	// redactedBody / redactedQuery are the body and query string with
	// every credential-shaped value replaced. They come out of the same
	// pass that decided status, so the event cannot carry a credential
	// the status claims is not there.
	redactedBody  string
	redactedQuery string
}

// present renders the presence boolean. It is a pointer so credUnknown can
// serialize as JSON null rather than false: "we could not tell" and "we
// looked and there was nothing" are different answers, and a single bool
// cannot say both. Every consumer of this field has to consult
// credential_status to tell them apart -- that is the point.
func (f asaCredentialFinding) present() *bool {
	if f.status == credUnknown {
		return nil
	}
	seen := f.status == credExtracted || f.status == credUnparsed
	return &seen
}

// usernameFieldKeys and secretFieldKeys are the field names this sensor
// can MAP onto a username/secret pair. Which account an attacker tried is
// a live analytic -- the ASA's own logon form is the canonical case -- and
// moving the vocabulary would quietly change what those aggregate.
var usernameFieldKeys = []string{"username", "user", "login", "email", "name", "uname"}

var secretFieldKeys = []string{"password", "pass", "passwd", "pwd"}

// materialFieldKeys is the wider set of field names whose presence means
// "credential material is in here" even where this sensor cannot map it
// onto fields. The ASA's own logon form carries `otp` alongside the
// username and password, and `group`/`realm` beside them; a body carrying
// those is a login attempt in a shape the decoy does not map, and that is
// worth recording as such rather than as absent.
var materialFieldKeys = []string{
	"username", "user", "login", "email", "uname",
	"password", "pass", "passwd", "pwd", "passcode", "passphrase",
	"pin", "otp", "secret", "token", "jwt",
	"api_key", "apikey", "api-key", "access_key", "secret_key", "private_key",
	"auth", "authorization", "credential", "credentials", "sessionid", "session_id",
}

// redactFieldKeys is what the scrubber replaces values under. Wider than
// materialFieldKeys on purpose: a false redaction costs one scanner's junk
// parameter, while a missed one is the failure this whole file exists to
// prevent. csrf, cookie and sig are in it because they are session secrets
// an attacker will happily replay, even though they are not a login
// credential and so do not set credential_status on their own.
var redactFieldKeys = []string{
	"pass", "pwd", "secret", "token", "jwt", "auth", "credential", "session",
	"csrf", "xsrf", "otp", "pin", "cookie", "sig", "signature", "nonce",
	"api_key", "apikey", "api-key", "access_key", "secret_key", "private_key",
}

// redactMarker replaces a credential-shaped value. A literal, so a reader
// -- and the tests on both sides of the API -- can recognise a redaction
// instead of guessing at one.
const redactMarker = "[redacted]"

// bodyReadCap is the most of a request body this sensor will hold for
// credential purposes. A body that reaches it has been cut off mid-flight,
// and everything after the cut is credential material this sensor never
// saw -- which is why a request that hits the cap is credUnknown rather
// than credAbsent.
//
// This is deliberately NOT webvpn.go's 1 MiB read limit. That one exists
// to capture a CVE-2018-0101 payload whole, and a host-scan-reply POST
// really is that large; keeping the two separate means raising one for its
// own reason never silently weakens the other.
const bodyReadCap = 64 << 10

// secretHeaderNames are the request headers whose entire value is a
// credential or a session token. Matched case-insensitively as substrings,
// so X-Api-Key and Proxy-Authorization are covered by the same list.
var secretHeaderNames = []string{"authorization", "proxy-authorization", "cookie", "api-key", "apikey", "auth-token"}

// redactSecretHeaders replaces the value of every header in
// secretHeaderNames, keeping the header itself. Which credential channel a
// request used is recorded in auth_type; what it put in there is not the
// log's business.
func redactSecretHeaders(headers map[string]string) map[string]string {
	for name := range headers {
		lower := strings.ToLower(name)
		for _, secret := range secretHeaderNames {
			if strings.Contains(lower, secret) {
				headers[name] = redactMarker
				break
			}
		}
	}
	return headers
}

// decoySessionCookies are this decoy's own cookie names (see
// clearedCookies() in webvpn.go, which the handler sets on every response).
//
// Their presence is the ONLY genuine session signal this sensor has, and
// it is worth being precise about how weak it is. A real ASA mints a unique
// session identifier per client; this decoy sets the same seven fixed
// values for everybody, and never reads one back out of a request for any
// purpose. So the presence of one of these says exactly one thing -- this
// request came from a client that had already been shown a logon page by
// this decoy -- and identifies no individual session.
//
// #3213 asks for correlation on a source event or session "only where one
// genuinely exists", and forbids inventing a join key. Inventing a session
// id here would have been the easy way to make the events look joinable:
// hash the src/dst tuple, or stamp a counter, and every event would have
// a `session_id` that looked like a real one and correlated nothing. So
// there is no session id. The join keys that genuinely exist on this
// sensor are the flow tuple (src_ip, src_port, port) and this presence
// boolean, and the boolean is reported as a boolean.
var decoySessionCookies = []string{"webvpnlogin", "tg", "webvpn", "webvpnc", "webvpn_portal", "sdesktop"}

// hasDecoySessionCookie reports whether the request carried one of this
// decoy's own cookie names. The VALUE is not examined and is not recorded:
// it is the same fixed string for every client on the fleet, so reading it
// would produce a constant, not a session.
func hasDecoySessionCookie(r *http.Request) bool {
	for _, c := range r.Cookies() {
		for _, name := range decoySessionCookies {
			if c.Name == name {
				return true
			}
		}
	}
	return false
}

// decoyIndicator is one FICTIONAL static credential belonging to a product
// this fleet invented for its own decoy pages, and to one account within
// it.
type decoyIndicator struct {
	product  string
	account  string
	username string
	password string
}

// decoyIndicators is the static-credential indicator set #3213 asks for,
// and it is deliberately not a vendor default-credential list.
//
// #3180's research proposed flagging "known default creds for Cisco FMC".
// This fleet runs no FMC instance, has never had one to test a list
// against, and a list of another vendor's factory credentials shipped here
// as fact would be a claim this repository cannot support -- the exact
// research-proposal status #3180's own correction established. So there
// are none, here or in the HTTP decoy.
//
// It is worth being blunt about the temptation on THIS sensor in
// particular. The decoy is a Cisco ASA, a real product with real,
// published, well-known default credentials, and a maintainer looking at
// this file would find it obvious to paste that list in. A match would
// then read as "this attacker used a Cisco default", which is a claim about
// a real product's behaviour that nobody here has tested, on hardware this
// fleet does not own, against a decoy that cannot authenticate anybody
// anyway. So the indicators are bait this fleet invented for its own
// persona -- the same "nexusai-*" product the rest of the decoys serve.
//
// A match says one thing: an attempt was made with this decoy's own
// fictional credential, for this decoy's own fictional product and
// account. Not evidence of vendor defaults, not evidence of access, and
// not evidence of any CVE. Both halves must match, and against the same
// entry.
var decoyIndicators = []decoyIndicator{
	{product: "nexusai-asa-vpn", account: "vpn-operator", username: "vpn-operator", password: "nexusai-bait-not-a-real-password"},
}

// inspectASACredentials reads every channel that can carry a credential
// and reports one presence/extraction answer. It never returns, and never
// stores, a password.
func inspectASACredentials(r *http.Request, body string) asaCredentialFinding {
	f := asaCredentialFinding{
		status:        credAbsent,
		redactedBody:  body,
		redactedQuery: r.URL.RawQuery,
		decoySession:  hasDecoySessionCookie(r),
	}

	// The Authorization header first: it is the channel that carries a
	// complete credential in one piece.
	if scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok {
		switch {
		case strings.EqualFold(scheme, "Basic"):
			f.authType = "basic"
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
			if err != nil {
				// Credential-shaped, not decodable. Present, unreadable.
				f.status = credUnparsed
				break
			}
			user, secret, found := strings.Cut(string(raw), ":")
			if !found {
				// Decoded, but not user:secret -- malformed Basic.
				f.status = credUnparsed
				break
			}
			f.status = credExtracted
			f.username = user
			f.indicator = matchDecoyIndicator(user, secret)
		case strings.EqualFold(scheme, "Bearer") && token != "":
			// The token IS the credential -- it is password-equivalent --
			// so it is dropped exactly like a password. It carries no
			// account, so there is nothing for the account-scoped
			// indicator to match against either.
			f.authType = "bearer"
			f.status = credExtracted
		default:
			// Digest, Negotiate, NTLM, anything a client invented: real
			// credential material in a shape this sensor does not decode.
			// The scheme name is not a secret and is worth having.
			f.authType = strings.ToLower(scheme)
			f.status = credUnparsed
		}
	}

	// … then the body and the query string. The ASA's canonical credential
	// submission is a form POST to /+CSCOE+/logon.html, and before #3213
	// that whole body -- username and password both -- went into the
	// event's `data` field verbatim.
	//
	// The body is read RAW for the credential decision and separately
	// redacted for storage. Those orderings are not interchangeable: read
	// it redacted and the secret half is already "[redacted]" by the time
	// the indicator matcher sees it, so matchDecoyIndicator could never
	// match anything at all. The redaction is for what leaves the process,
	// not for what the decision is made from.
	contentType := r.Header.Get("Content-Type")
	rawBody := body
	fromBody := false
	if len(rawBody) > 0 {
		redacted, material := redactSecretValues(rawBody, contentType)
		f.redactedBody = redacted
		if user, secret, ok := extractFormCredentials(rawBody, contentType); ok && f.status == credAbsent {
			f.status = credExtracted
			f.authType = "form"
			f.username = user
			f.indicator = matchDecoyIndicator(user, secret)
			fromBody = true
		}
		if material && f.status == credAbsent {
			f.status = credUnparsed
			fromBody = true
		}
	}
	if r.URL.RawQuery != "" {
		redactedQuery, material := redactSecretValues(r.URL.RawQuery, "application/x-www-form-urlencoded")
		f.redactedQuery = redactedQuery
		if material && f.status == credAbsent {
			f.status = credUnparsed
		}
	}

	// Unknown last, and only for what is genuinely unknowable.
	//
	// The test is not "did we find anything" but "is every channel that
	// could have carried a credential one we read in full". A finding from
	// a channel that was read completely -- the Authorization header, or
	// the query string, neither of which the read cap touches -- stands on
	// its own and is never downgraded. A finding from the body of a
	// request that hit the cap does not: there is an unbounded amount of
	// that body nobody read, so "we mapped the credentials" would be a
	// claim about a prefix.
	if fromBody && !asaBodyInspectable(body) {
		f.status = credUnknown
	}
	if f.status == credAbsent && !asaBodyInspectable(body) {
		f.status = credUnknown
	}
	return f
}

// asaBodyInspectable reports whether the body can be read for credentials
// at all. Two ways it cannot: the read cap in webvpn.go truncated it, so
// its tail was never seen; or it is a byte stream no key scan can speak
// for.
func asaBodyInspectable(body string) bool {
	if len(body) >= bodyReadCap {
		return false
	}
	return len(body) == 0 || utf8.ValidString(body)
}

// extractFormCredentials maps a form-urlencoded body onto a username and a
// secret. ok is false when the body is not form-encoded or carries no
// credential field at all, in which case the caller falls back to
// detection.
func extractFormCredentials(body, contentType string) (user, secret string, ok bool) {
	if len(body) == 0 || !strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		return "", "", false
	}
	vals, _ := parseForm(body)
	user = firstNonEmpty(vals, usernameFieldKeys...)
	secret = firstNonEmpty(vals, secretFieldKeys...)
	return user, secret, user != "" || secret != ""
}

// matchDecoyIndicator returns the scope label of a fictional decoy
// credential when BOTH halves match the same entry, and "" otherwise. An
// empty username never matches: a decoy credential is an account-specific
// thing, and the bearer channel carries no account.
func matchDecoyIndicator(username, secret string) string {
	if username == "" || secret == "" {
		return ""
	}
	for _, d := range decoyIndicators {
		if strings.EqualFold(username, d.username) && secret == d.password {
			return d.product + "/" + d.account
		}
	}
	return ""
}

// redactSecretValues replaces the value of every credential-shaped field
// in a body or query string, and reports whether it found any credential
// material (a session secret alone does not count as material).
//
// The two answers come out of one pass on purpose. A detector and a
// redactor that disagree are how "we never saw a credential" and "here is
// the credential" end up in the same event.
func redactSecretValues(raw, contentType string) (string, bool) {
	if raw == "" {
		return raw, false
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "multipart/form-data"):
		// A multipart part's value sits after a blank LINE, so it needs
		// its own pass. Checked before the general scrubber for the same
		// reason redactBareBasic is: this shape carries no separator for a
		// key/value scan to act on, and the password is in the part body.
		if out, ok := redactMultipart(raw, multipartBoundary(contentType)); ok {
			return out, true
		}
		// Not multipart after all, or nothing credential-shaped in it.
		// The general scrubber is the honest fallback.
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		if out, ok := redactForm(raw); ok {
			return out, true
		}
		// Content-Type claims a form and the bytes are not one. Fall
		// through to the opaque scrubber rather than passing unparsed bytes
		// through on the strength of a header the attacker wrote -- which
		// is the same rule the JSON case below follows. A body of
		// `password: hunter2` labelled as a form was reported absent AND
		// stored verbatim, so the sensor claimed there was nothing here
		// while holding the secret.
	case strings.Contains(ct, "json"):
		if out, ok := redactJSON(raw); ok {
			return out, ok
		}
		// Content-Type claims JSON and the bytes disagree. Fall through
		// to the opaque scrubber rather than passing unparsed bytes
		// through on the strength of a header the attacker wrote.
	}
	// A body that is nothing but a cleartext Basic credential. Checked
	// before the general scrubber because it carries no field name at all,
	// so no key scan will ever find it.
	if out, ok := redactBareBasic(raw); ok {
		return out, true
	}
	return redactOpaque(raw)
}

// redactBareBasic scrubs a body that is exactly one cleartext user:secret
// pair and nothing else.
//
// The shape is deliberately narrow, because the alternative is either
// logging a password or destroying the payload signal this sensor's
// host-scan-reply parser depends on. It has to be a single line, exactly
// one colon, an account half that is a bare identifier, and a secret half
// with no whitespace anywhere in it. A prose body is not caught, and a
// host-scan-reply payload is not caught.
func redactBareBasic(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsAny(trimmed, "\r\n\t ") {
		return raw, false
	}
	account, secret, found := strings.Cut(trimmed, ":")
	if !found || account == "" || secret == "" || strings.Contains(secret, ":") {
		return raw, false
	}
	if len(account) > 64 || len(secret) > 256 {
		return raw, false
	}
	for i := 0; i < len(account); i++ {
		if !isNameByte(account[i]) && account[i] != '@' && account[i] != '+' {
			return raw, false
		}
	}
	return account + ":" + redactMarker, true
}

// redactForm scrubs a form-urlencoded body or query string pair by pair.
func redactForm(raw string) (string, bool) {
	pairs := strings.Split(raw, "&")
	found := false
	for i, pair := range pairs {
		key, value, hasValue := strings.Cut(pair, "=")
		if !hasValue || value == "" {
			continue
		}
		// The key is compared decoded (an attacker percent-encodes
		// freely) but written back as it arrived, so the redacted body
		// still looks like the request that came in.
		name := urlDecode(key)
		if !isCredentialField(name, false) {
			continue
		}
		found = found || isCredentialField(name, true)
		pairs[i] = key + "=" + redactMarker
	}
	return strings.Join(pairs, "&"), found
}

// redactJSON scrubs a JSON body's credential-shaped members, recursively.
// It re-serializes rather than editing in place, so a redacted JSON body
// is canonical (alphabetical keys, no incidental whitespace) rather than
// byte-identical to what the attacker sent. That is the trade: preserving
// the exact bytes of a body we have just rewritten is not worth the chance
// of leaving a value behind.
func redactJSON(raw string) (string, bool) {
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return raw, false
	}
	found := redactJSONValue(&doc)
	out, err := json.Marshal(doc)
	if err != nil {
		return raw, false
	}
	return string(out), found
}

// redactJSONValue walks a decoded JSON value, replacing every
// credential-shaped member and reporting whether any of them held a value.
// A member present with an empty value is left alone: there is nothing
// there to redact, and a redaction marker would claim otherwise.
func redactJSONValue(node *any) bool {
	switch v := (*node).(type) {
	case map[string]any:
		found := false
		for key, child := range v {
			if isCredentialField(key, false) {
				if s, ok := child.(string); ok && s != "" {
					found = found || isCredentialField(key, true)
				}
				v[key] = redactMarker
				continue
			}
			// A map index is not addressable, so the child is recursed into
			// by value and written back rather than by pointer.
			if redactJSONValue(&child) {
				found = true
			}
			v[key] = child
		}
		return found
	case []any:
		found := false
		for i := range v {
			if redactJSONValue(&v[i]) {
				found = true
			}
		}
		return found
	}
	return false
}

// isCredentialField reports whether a field name is credential material.
//
// The reportable set (materialFieldKeys) is what sets credential_status.
// The wider set (redactFieldKeys) is what the scrubber replaces values
// under: a CSRF token or a cookie is a secret worth removing even though
// its presence is not, on its own, a login attempt.
func isCredentialField(name string, reportable bool) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	keys := redactFieldKeys
	if reportable {
		keys = materialFieldKeys
	}
	for _, key := range keys {
		if strings.Contains(lower, key) {
			return true
		}
	}
	return false
}

// The three helpers below are the form-parsing half of credential
// extraction. They are here rather than in webvpn.go because the only
// caller is extractFormCredentials, and because this module had no form
// parser at all before #3213 -- the ASA's logon POST is form-urlencoded and
// nothing here could read it.

// parseForm splits a form-urlencoded payload into a lowercased key map.
// The error return is always nil: it is part of the shape callers of the
// HTTP decoy expect, and inventing a failure mode this sensor never has
// would be noise.
func parseForm(body string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(body, "&") {
		k, v, _ := strings.Cut(pair, "=")
		out[strings.ToLower(urlDecode(k))] = urlDecode(v)
	}
	return out, nil
}

// urlDecode percent-decodes a form value, treating '+' as a space.
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
