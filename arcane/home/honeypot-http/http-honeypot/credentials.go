// credentials.go answers the three questions #3213 says the HTTP decoy's
// event was conflating, and it answers them separately, because they are
// separate facts about a request:
//
//  1. What did the decoy serve back?            -> Status (main.go)
//  2. Did the request carry credentials, and could they be read? ->
//     CredentialStatus / CredentialPresent / AuthType (this file)
//  3. Was an authentication decision made, and by whom? -> AuthOutcome
//     (this file)
//
// Before this file, question 2 had exactly two representable answers --
// "there is a username" and "there is nothing here" -- and question 3 had
// none at all. Every other answer (credentials were present but in a shape
// this sensor does not parse; the body was cut off at the read cap so we
// cannot tell; the decoy served a 200 on /wp-login.php and a 200 on a
// bearer-authenticated /v1/models) landed on the same "absent" or on the
// same status number as a request that carried no credentials at all. Two
// consequences, both of them bad for an analyst:
//
//   - A scan of /login with a JSON body and a scan of / with no body were
//     indistinguishable, so "no credentials seen" was really "we did not
//     look, or we looked and did not understand".
//   - A decoy 200 on a login page is the decoy working. Reading it as an
//     authentication success is the exact inference #3213 forbids, and the
//     old schema gave an analyst nothing that said otherwise.
//
// #3213's secret-handling rule is a trust boundary, not a preference: a
// captured password is never stored, logged, or returned. Only the
// booleans below survive. A password is held in a local for the length of
// one request -- long enough to compare it against this decoy's own
// fictional bait credential, and to be dropped on the floor -- and is never
// assigned to the event, never written to the log, and never returned over
// the API. If you find yourself wanting to log it to make debugging
// easier, that is the bug, not the fix.

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
// honestly be spelled with any of the three: a Basic header the sensor
// decoded into a username is neither absent (material was there), nor
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
	// credentialFinding.username for why); the secret half does not.
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
	// no key scan can speak for. This state exists so the unreadable case
	// has somewhere to go that is NOT credAbsent: a truncated login POST
	// is a login attempt of unknown content, and filing it as
	// credential-free is how a scan of the data would learn to trust the
	// wrong number.
	credUnknown credentialStatus = "unknown"
)

// authOutcome is the provenance axis: when this response was an
// authentication artifact, where the decision came from, and nothing else.
//
// It deliberately carries no accept/reject verdict. The HTTP status
// already says what was served, and #3213's own acceptance criteria refuse
// the inference "status 200 = authentication succeeded" -- a 200 here is
// the login page rendering, or the decoy's fake model list answering a
// bearer token that was never checked against anything. A second field
// saying "accepted" would be the same conflation wearing a new name.
type authOutcome string

const (
	// authSimulated: the response the decoy chose was an artifact of its
	// own simulated authentication surface -- a challenge, a rejection,
	// a login page, or a canned reply for a token it never validated.
	// The decision is the persona's, by construction.
	authSimulated authOutcome = "simulated"
	// authReal: an authentication decision was made by a real
	// authentication backend. Nothing in this decoy can produce it --
	// there is no backend, no account store, no verifier. It exists in
	// the vocabulary because the axis is about provenance, and a sensor
	// that did delegate would have to say so. auth_outcome is never
	// derived from a status code anywhere in this binary; see
	// TestAuthRealIsUnreachable for the test that pins that.
	authReal authOutcome = "real"
	// authUnknown: no authentication decision was made for this request.
	// A 404, a static file, a metadata probe, a tarpitted scan.
	authUnknown authOutcome = "unknown"
)

// credentialFinding is one request's answer on the presence/extraction
// axis, before it is copied onto the event.
type credentialFinding struct {
	status credentialStatus
	// authType is the channel: "basic", "bearer", "form", or the
	// lowercased name of an Authorization scheme this sensor does not
	// decode ("digest", "negotiate", ...). Empty when the request carried
	// no Authorization header and no form credentials. It says which
	// channel, never what was in it.
	authType string
	// username is the account identifier only. A submitted username is
	// the analytic value here -- it is how a spray is recognised as a
	// spray -- and it is not a secret. The password half of the same
	// credential is never assigned anywhere.
	username string
	// indicator is the scope label of a matched FICTIONAL decoy
	// credential ("<product>/<account>"), empty when nothing matched.
	indicator string
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
func (f credentialFinding) present() *bool {
	if f.status == credUnknown {
		return nil
	}
	seen := f.status == credExtracted || f.status == credUnparsed
	return &seen
}

// usernameFieldKeys and secretFieldKeys are the field names this sensor can
// MAP onto a username/secret pair. Unchanged from the pre-#3213 extraction
// on purpose: which account an attacker tried is a live analytic (TopCreds
// aggregates it, the dashboard searches it), and moving the vocabulary
// would quietly change what those aggregate.
var usernameFieldKeys = []string{"username", "user", "login", "email", "name", "uname"}

var secretFieldKeys = []string{"password", "pass", "passwd", "pwd"}

// materialFieldKeys is the wider set of field names whose presence means
// "credential material is in here" even where this sensor cannot map it
// onto fields. A body carrying secret=/api_token=/credentials[] is
// present_unparsed, not absent: the request is a login attempt in a shape
// the decoy does not speak, and that is worth recording as such.
//
// Matching is a case-insensitive substring test on the field name, so
// "api_key", "apiKey" and "APIKEY" are one key here.
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

// bodyReadCap is the most of a request body this sensor will hold. A body
// that reaches it has been cut off mid-flight, and everything after the cut
// is credential material this sensor never saw -- which is why a request
// that hits the cap is credUnknown rather than credAbsent.
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
// are none. What there is instead is bait this fleet invented for itself.
//
// A match says one thing, and one thing only: an attempt was made with
// this decoy's own fictional credential, for this decoy's own fictional
// product and account. It is not evidence of vendor defaults, not evidence
// of access, and not evidence of any CVE -- no field in the event can
// carry such a claim, and the matching code below deliberately has no way
// to set one. Both halves must match, and against the same entry: a
// username alone is not a credential, and a password tried against an
// account nobody defined is just a password.
var decoyIndicators = []decoyIndicator{
	// The "nexusai-edge" persona this binary's own pages.go serves a
	// login surface for, and one operator account on it. The password is
	// written to be obvious about what it is.
	{product: "nexusai-edge", account: "edge-operator", username: "edge-operator", password: "nexusai-bait-not-a-real-password"},
}

// inspectCredentials reads every channel that can carry a credential and
// reports one presence/extraction answer. It never returns, and never
// stores, a password.
func inspectCredentials(r *http.Request, body string) credentialFinding {
	f := credentialFinding{status: credAbsent, redactedBody: body, redactedQuery: r.URL.RawQuery}

	// The Authorization header first, exactly as before: it is the
	// channel that carries a complete credential.
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
			// so it is dropped exactly like a password. The pre-#3213 code
			// stored it in the event's password field under the username
			// "bearer", which was both a leak and a username that was
			// never a username. It carries no account, so there is nothing
			// for the account-scoped indicator to match against either.
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

	// … then the body and the query string, which are credential channels
	// in their own right and used to be inspected (the body) or ignored
	// (the query) with no way to say which happened.
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
	// its own and is never downgraded. A finding from the body of a request
	// that hit the cap does not: there is an unbounded amount of that body
	// nobody read, so "we mapped the credentials" would be a claim about a
	// prefix. That is why the downgrade below is scoped to fromBody rather
	// than to credAbsent.
	//
	// Reporting that as unknown is the whole reason the state exists. A
	// truncated login POST is a login attempt of unknown completeness, and
	// filing it as extracted -- or as absent -- is how a scan of the data
	// would learn to trust the wrong number.
	if fromBody && !bodyInspectable(body) {
		f.status = credUnknown
	}
	if f.status == credAbsent && !bodyInspectable(body) {
		f.status = credUnknown
	}
	return f
}

// bodyInspectable reports whether the body can be read for credentials at
// all. Two ways it cannot: the read cap in ServeHTTP truncated it, so its
// tail was never seen; or it is a byte stream no key scan can speak for.
func bodyInspectable(body string) bool {
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
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		return redactForm(raw)
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
	// so no key scan will ever find it -- and "admin:password" is the
	// canonical login POST, so leaving it alone would leave the most
	// ordinary credential in the fleet's most ordinary request unredacted.
	if out, ok := redactBareBasic(raw); ok {
		return out, true
	}
	return redactOpaque(raw)
}

// redactBareBasic scrubs a body that is exactly one cleartext
// user:secret pair and nothing else -- what a client that was told not to
// base64 sends, and what several scanners POST to a login path.
//
// The shape is deliberately narrow, because the alternative is either
// logging a password or destroying the payload signal this sensor's
// classifyPayload depends on. It has to be a single line, exactly one
// colon, an account half that is a bare identifier, and a secret half with
// no whitespace anywhere in it. "Host: example.com" is not caught (the
// space after the colon), a prose paragraph is not caught, and a payload is
// not caught. What is caught is the one thing worth catching.
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
