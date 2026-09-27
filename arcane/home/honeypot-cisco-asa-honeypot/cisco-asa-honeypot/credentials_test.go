// credentials_test.go is the ASA half of the #3213 proof.
//
// http-honeypot/credentials_test.go covers the same three axes on the HTTP
// decoy. This file covers what is different here, and it covers the one
// thing that is not a copy: the pre-#3213 ASA wrote a posted WebVPN logon
// form into the event's `data` field verbatim, username and password both.
// That is the leak this issue is really about on this sensor, and
// TestPasswordNeverReachesTheEvent is the test that matters.
//
// Two things here are worth reading before the tests below them:
//
//   - This decoy serves "Login failed" over HTTP 200, redirects a
//     submitted logon form, and answers an unparseable POST with a
//     parse-error envelope over 200. So the "a 200 is not an
//     authentication success" rule is not a hypothetical on this sensor;
//     it is the logon.html?reason=1 branch.
//
//   - There is no session id, and none was invented. See decoySessionCookies
//     in credentials.go for why, and TestNoSessionIdWasInvented for what
//     holds that line.
package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// canarySecret is the password every leak test submits. It appears in this
// file and nowhere else in the binary, which is exactly the property the
// leak tests assert.
const canarySecret = "correct-horse-battery-staple-9f2c"

// newFileLoggerHandler returns a handler whose logger writes to a temp
// file. The module's logger has no in-memory sink -- newLogger("") writes
// to stdout only -- so any test that has to assert on what was logged needs
// a file to read back.
func newFileLoggerHandler(t *testing.T) *webvpnHandler {
	t.Helper()
	return &webvpnHandler{log: newLogger(filepath.Join(t.TempDir(), "out.json")), port: 8443}
}

// asaExchange drives one real request through ServeHTTP and returns every
// event the handler logged, in order.
func asaExchange(t *testing.T, h *webvpnHandler, method, target, contentType, body string) []event {
	t.Helper()
	if h.log.out == nil {
		h.log = newLogger(filepath.Join(t.TempDir(), "out.json"))
	}
	r := httptest.NewRequest(method, "https://example"+target, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r.RemoteAddr = "198.51.100.7:54321"
	h.ServeHTTP(httptest.NewRecorder(), r)

	raw := readLog(t, h)
	if raw == "" {
		return nil
	}
	var out []event
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("undecodable log line (%v): %s", err, line)
		}
		out = append(out, e)
	}
	return out
}

// last returns the terminal event of an exchange, which is the one carrying
// the response. A CVE-2018-0101 POST emits one "post" plus one event per
// payload; they all describe the same response.
func last(t *testing.T, events []event) event {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("no event was logged for a request that was served")
	}
	return events[len(events)-1]
}

// TestStatusIsRecordedOnTheEvent is the new information this schema adds.
// Before #3213 the event carried no status at all, because the event was
// logged before the response was written. The decoy serves 200, 302, 403
// and 404 from the same path prefix depending on the request, and the only
// way to tell them apart in the log was the event kind.
func TestStatusIsRecordedOnTheEvent(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		target     string
		wantStatus int
	}{
		{name: "the root redirect page", method: http.MethodGet, target: "/", wantStatus: http.StatusOK},
		{name: "the bare logon page redirect", method: http.MethodGet, target: "/+CSCOE+/logon.html", wantStatus: http.StatusFound},
		{name: "the logon failure page", method: http.MethodGet, target: "/+CSCOE+/logon.html?reason=1", wantStatus: http.StatusOK},
		{name: "the asa directory", method: http.MethodGet, target: "/asa/", wantStatus: http.StatusForbidden},
		{name: "an unknown file", method: http.MethodGet, target: "/no-such-file.html", wantStatus: http.StatusNotFound},
		{name: "a known file", method: http.MethodGet, target: "/+CSCOE+/logon.html?reason=2", wantStatus: http.StatusOK},
		{name: "a posted logon form", method: http.MethodPost, target: "/+CSCOE+/logon.html", wantStatus: http.StatusFound},
		{name: "a posted root", method: http.MethodPost, target: "/", wantStatus: http.StatusFound},
		{name: "an unparseable post", method: http.MethodPost, target: "/whatever", wantStatus: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestWebvpnHandler()
			e := last(t, asaExchange(t, h, tc.method, tc.target, "", ""))
			if e.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", e.Status, tc.wantStatus)
			}
		})
	}
}

// TestCredentialStatusStatesAreReachable walks all four states on this
// sensor and proves each is reachable from a real request. The one that
// matters most here is unknown, because it is the only state the HTTP
// decoy's evidence does not obviously imply and the one whose absence
// would let a truncated logon POST read as credential-free.
func TestCredentialStatusStatesAreReachable(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		header      [2]string
		want        credentialStatus
		wantUser    string
		wantChannel string
	}{
		{
			name:        "absent: a logon POST with no credential field",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "application/x-www-form-urlencoded",
			body:        "portal=remote&reason=1",
			want:        credAbsent,
		},
		{
			name:   "absent: a plain GET",
			method: http.MethodGet,
			target: "/",
			want:   credAbsent,
		},
		{
			name:        "extracted: the canonical ASA logon form",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=admin&password=" + canarySecret + "&otp=&csrf=abc",
			want:        credExtracted,
			wantUser:    "admin",
			wantChannel: "form",
		},
		{
			name:        "extracted: a Basic header",
			method:      http.MethodGet,
			target:      "/",
			header:      [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:"+canarySecret))},
			want:        credExtracted,
			wantUser:    "admin",
			wantChannel: "basic",
		},
		{
			name:        "present_unparsed: a scheme this decoy does not decode",
			method:      http.MethodGet,
			target:      "/",
			header:      [2]string{"Authorization", "Negotiate YIIFjbGFpbQ=="},
			want:        credUnparsed,
			wantChannel: "negotiate",
		},
		{
			name:        "present_unparsed: a credential the decoy does not map (an OTP alone)",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "application/x-www-form-urlencoded",
			body:        "otp=" + canarySecret,
			want:        credUnparsed,
		},
		{
			name:   "present_unparsed: a credential in the query string",
			method: http.MethodGet,
			target: "/+CSCOE+/logon.html?token=" + canarySecret,
			want:   credUnparsed,
		},
		{
			name:        "unknown: a logon POST past the credential read cap",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=admin&filler=" + strings.Repeat("x", bodyReadCap) + "&password=" + canarySecret,
			want:        credUnknown,
		},
		{
			name:        "unknown: a body no key scan can speak for",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "application/octet-stream",
			body:        "\xff\xfe\x00\x01\x02\x03",
			want:        credUnknown,
		},
	}
	seen := map[credentialStatus]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFileLoggerHandler(t)
			r := httptest.NewRequest(tc.method, "https://example"+tc.target, strings.NewReader(tc.body))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if tc.header[0] != "" {
				r.Header.Set(tc.header[0], tc.header[1])
			}
			r.RemoteAddr = "198.51.100.7:54321"
			h.ServeHTTP(httptest.NewRecorder(), r)

			data, err := os.ReadFile(h.log.path)
			if err != nil {
				t.Fatalf("read log: %v", err)
			}
			line := strings.TrimSpace(string(data))
			var e event
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatalf("undecodable log line: %v", err)
			}
			if got := credentialStatus(e.CredentialStatus); got != tc.want {
				t.Fatalf("credential_status = %q, want %q", got, tc.want)
			}
			if tc.wantUser != "" && e.Username != tc.wantUser {
				t.Fatalf("username = %q, want %q", e.Username, tc.wantUser)
			}
			if tc.wantChannel != "" && e.AuthType != tc.wantChannel {
				t.Fatalf("auth_type = %q, want %q", e.AuthType, tc.wantChannel)
			}
			seen[credentialStatus(e.CredentialStatus)] = true
		})
	}
	for _, want := range []credentialStatus{credAbsent, credExtracted, credUnparsed, credUnknown} {
		if !seen[want] {
			t.Errorf("credential_status %q was never produced by a real request on this sensor", want)
		}
	}
}

// TestUnknownIsNeverCollapsedIntoAbsent is the collapse #3213 is named for,
// on the wire rather than in the struct: a null credential_present has to be
// distinguishable from a false one, or "we could not read it" reads as
// "there was nothing there".
func TestUnknownIsNeverCollapsedIntoAbsent(t *testing.T) {
	truncated := "username=admin&filler=" + strings.Repeat("x", bodyReadCap) + "&password=" + canarySecret
	h := newTestWebvpnHandler()
	asaExchange(t, h, http.MethodPost, "/+CSCOE+/logon.html", "application/x-www-form-urlencoded", truncated)
	unknownLine := readLog(t, h)

	h2 := newTestWebvpnHandler()
	asaExchange(t, h2, http.MethodPost, "/+CSCOE+/logon.html", "application/x-www-form-urlencoded", "portal=remote")
	absentLine := readLog(t, h2)

	if !strings.Contains(unknownLine, `"credential_status":"unknown"`) {
		t.Fatalf("a logon POST past the read cap must be filed as unknown: %s", unknownLine)
	}
	if !strings.Contains(unknownLine, `"credential_present":null`) {
		t.Fatalf("unknown must serialize credential_present as null: %s", unknownLine)
	}
	if !strings.Contains(absentLine, `"credential_status":"absent"`) {
		t.Fatalf("a logon POST read in full with no credential in it must be absent: %s", absentLine)
	}
	if !strings.Contains(absentLine, `"credential_present":false`) {
		t.Fatalf("absent must serialize credential_present as false: %s", absentLine)
	}
	if unknownLine == absentLine {
		t.Fatal("the unknown and absent events are byte-identical on the wire; the distinction did not survive serialization")
	}
}

func readLog(t *testing.T, h *webvpnHandler) string {
	t.Helper()
	if h.log.path == "" {
		t.Fatal("this handler's logger has no file to read; use newFileLoggerHandler")
	}
	data, err := os.ReadFile(h.log.path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return strings.TrimSpace(string(data))
}

// TestIKEEventsAreUnknownNotAbsent is the reason credUnknown exists as a
// third answer rather than credUnparsed, on this sensor specifically.
//
// The IKE side shares this log with the WebVPN side and does carry identity
// and key material -- an IKE_SA_INIT contains an ID payload. This decoy
// parses none of it. So the honest answer for an IKE event is "we could not
// tell", and the alternative -- leaving the field off and letting a
// consumer's default read as "no credentials" -- is the exact false negative
// this whole change exists to remove.
func TestIKEEventsAreUnknownNotAbsent(t *testing.T) {
	h := newFileLoggerHandler(t)
	h.log.emit(event{Port: 500, Event: "ike_listening"})

	line := readLog(t, h)
	if !strings.Contains(line, `"credential_status":"unknown"`) {
		t.Fatalf("an IKE event must be filed as credential_status=unknown, not absent: %s", line)
	}
	if strings.Contains(line, `"credential_present":false`) {
		t.Fatalf("an IKE event must not claim credential_present=false; nothing inspected it: %s", line)
	}
	if !strings.Contains(line, `"credential_present":null`) {
		t.Fatalf("an IKE event must serialize credential_present as null: %s", line)
	}
	if !strings.Contains(line, `"auth_outcome":"unknown"`) {
		t.Fatalf("an IKE event must be filed as auth_outcome=unknown: %s", line)
	}
}

// TestAuthRealIsUnreachable is the second inference #3213 forbids, and on
// this sensor the evidence against it is unusually good: the decoy serves
// its "Login failed" page over HTTP 200.
func TestAuthRealIsUnreachable(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		wantStatus  int
	}{
		{name: "the login failure page, over 200", method: http.MethodGet, target: "/+CSCOE+/logon.html?reason=1", wantStatus: http.StatusOK},
		{name: "a submitted logon form, rejected by redirect", method: http.MethodPost, target: "/+CSCOE+/logon.html", contentType: "application/x-www-form-urlencoded", body: "username=admin&password=" + canarySecret, wantStatus: http.StatusFound},
		{name: "a submitted form to an unrecognised path, parse error over 200", method: http.MethodPost, target: "/+webvpn+/whatever", contentType: "application/x-www-form-urlencoded", body: "username=admin&password=" + canarySecret, wantStatus: http.StatusOK},
		{name: "the bare logon redirect", method: http.MethodGet, target: "/+CSCOE+/logon.html", wantStatus: http.StatusFound},
		{name: "the portal index", method: http.MethodPost, target: "/+webvpn+/index.html", contentType: "application/x-www-form-urlencoded", body: "host=example&portal=remote", wantStatus: http.StatusOK},
		{name: "the wrong-url 403", method: http.MethodGet, target: "/asa/", wantStatus: http.StatusForbidden},
		{name: "a 404", method: http.MethodGet, target: "/nope", wantStatus: http.StatusNotFound},
		{name: "the CVE-2018-0101 payload path", method: http.MethodPost, target: "/+CSCOE+/logon.html", contentType: "text/xml", body: "<host-scan-reply>10.0.0.1</host-scan-reply>", wantStatus: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestWebvpnHandler()
			e := last(t, asaExchange(t, h, tc.method, tc.target, tc.contentType, tc.body))
			if e.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", e.Status, tc.wantStatus)
			}
			if e.AuthOutcome == string(authReal) {
				t.Fatalf("auth_outcome = %q on a %d: this decoy has no account store, so no branch may claim a real decision", e.AuthOutcome, e.Status)
			}
			if authOutcome(e.AuthOutcome) != authSimulated && authOutcome(e.AuthOutcome) != authUnknown {
				t.Fatalf("auth_outcome = %q, want one of the two values this binary can honestly produce", e.AuthOutcome)
			}
		})
	}
}

// TestTheLoginFailurePageIsNotAnAuthSuccess states the 200 rule on the one
// branch where it is most tempting to get wrong, and asserts the positive
// too: the logon surface answering means simulated, not unknown. A field
// that is always "unknown" is as useless as one that is always "real".
func TestTheLoginFailurePageIsNotAnAuthSuccess(t *testing.T) {
	h := newTestWebvpnHandler()
	e := last(t, asaExchange(t, h, http.MethodGet, "/+CSCOE+/logon.html?reason=1", "", ""))

	if e.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200: the decoy serves its failure page over 200, which is the whole point", e.Status)
	}
	if strings.Contains(e.Data, "") && e.AuthOutcome == string(authReal) {
		t.Fatalf("a 200 carrying the failure page must never read as a real authentication success")
	}
	if e.AuthOutcome != string(authSimulated) {
		t.Fatalf("auth_outcome = %q, want %q: the decoy's authentication surface answered, and it was the persona answering", e.AuthOutcome, authSimulated)
	}
}

// TestPasswordNeverReachesTheEvent is the trust-boundary test, and on this
// sensor the pre-#3213 behaviour it pins is concrete: the posted WebVPN
// logon form was written into `data` verbatim.
func TestPasswordNeverReachesTheEvent(t *testing.T) {
	channels := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		header      [2]string
	}{
		{
			name:        "the canonical WebVPN logon form",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=admin&password=" + canarySecret + "&otp=" + canarySecret + "&csrf=" + canarySecret,
		},
		{
			name:        "a form using pwd, with a space in the secret",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "application/x-www-form-urlencoded",
			body:        "login=admin&pwd=" + canarySecret,
		},
		{
			name:        "a JSON body",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "application/json",
			body:        `{"username":"admin","password":"` + canarySecret + `","portal":"remote"}`,
		},
		{
			name:   "a Basic authorization header",
			method: http.MethodGet,
			target: "/",
			header: [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:"+canarySecret))},
		},
		{
			name:   "a bearer token, which is password-equivalent",
			method: http.MethodGet,
			target: "/",
			header: [2]string{"Authorization", "Bearer " + canarySecret},
		},
		{
			name:   "a scheme this decoy does not decode",
			method: http.MethodGet,
			target: "/",
			header: [2]string{"Authorization", "Digest username=\"admin\", response=\"" + canarySecret + "\""},
		},
		{
			name:   "a session cookie",
			method: http.MethodGet,
			target: "/+webvpn+/index.html",
			header: [2]string{"Cookie", "webvpn=xyz; webvpnlogin=1; tg=" + canarySecret},
		},
		{
			name:   "a credential in the query string",
			method: http.MethodGet,
			target: "/+CSCOE+/logon.html?reason=1&password=" + canarySecret,
		},
		{
			name:        "an XML logon body",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "text/xml",
			body:        `<auth><username>admin</username><password>` + canarySecret + `</password></auth>`,
		},
		{
			name:        "a cleartext basic POST",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "text/plain",
			body:        "admin:" + canarySecret,
		},
		{
			name:        "a logon form past the credential read cap",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=admin&filler=" + strings.Repeat("x", bodyReadCap) + "&password=" + canarySecret,
		},
		{
			name:        "a credential smuggled inside a host-scan-reply",
			method:      http.MethodPost,
			target:      "/+CSCOE+/logon.html",
			contentType: "text/xml",
			body:        `<host-scan-reply><ip-address>10.0.0.1</ip-address><password>` + canarySecret + `</password></host-scan-reply>`,
		},
	}

	forms := map[string]string{
		"plain":      canarySecret,
		"urlencoded": strings.ReplaceAll(canarySecret, " ", "+"),
		"base64":     base64.StdEncoding.EncodeToString([]byte(canarySecret)),
		"bearer":     "Bearer " + canarySecret,
	}

	for _, tc := range channels {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestWebvpnHandler()
			if h.log.out == nil {
				h.log = newLogger(filepath.Join(t.TempDir(), "out.json"))
			}
			r := httptest.NewRequest(tc.method, "https://example"+tc.target, strings.NewReader(tc.body))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if tc.header[0] != "" {
				r.Header.Set(tc.header[0], tc.header[1])
			}
			r.RemoteAddr = "198.51.100.7:54321"
			h.ServeHTTP(httptest.NewRecorder(), r)

			// The whole log file, every event of every kind, because the
			// pre-#3213 leak was in a specific event's Data and a test that
			// only read the terminal event would miss it.
			logged := readLog(t, h)
			for label, form := range forms {
				if strings.Contains(logged, form) {
					t.Errorf("the %s form of the captured password reached the log: %s", label, logged)
				}
			}
		})
	}
}

// TestRedactionKeepsTheLogonFormReadable is the other half of removing the
// field. The ASA's logon form is the analytic value here -- which accounts
// an attacker tried, in what order, with what else in the form -- and
// redacting the whole body would throw that away along with the secret.
func TestRedactionKeepsTheLogonFormReadable(t *testing.T) {
	h := newTestWebvpnHandler()
	e := last(t, asaExchange(t, h, http.MethodPost, "/+CSCOE+/logon.html",
		"application/x-www-form-urlencoded",
		"username=admin&password="+canarySecret+"&otp=123456&portal=remote&csrf=abc123"))

	if !strings.Contains(e.Data, "username=admin") {
		t.Errorf("the account identifier should survive -- it is the analytic value: %q", e.Data)
	}
	if !strings.Contains(e.Data, "portal=remote") {
		t.Errorf("a non-credential field should survive: %q", e.Data)
	}
	if !strings.Contains(e.Data, "password="+redactMarker) {
		t.Errorf("the password value was not replaced by the redaction marker: %q", e.Data)
	}
	if !strings.Contains(e.Data, "otp="+redactMarker) {
		t.Errorf("the OTP is password-equivalent and should be redacted: %q", e.Data)
	}
}

// TestCVEPayloadSurvivesRedaction holds the other trade-off honest. The
// host-scan-reply payload is the entire reason this decoy exists, so the
// scrubber must not damage it. It is read unredacted by
// parseHostScanReplies and stored redacted, and this test is what stops the
// second half of that from quietly eating the addresses.
func TestCVEPayloadSurvivesRedaction(t *testing.T) {
	// The real shape: the overflow payload is the chardata of
	// <host-scan-reply>, not child elements, which is what
	// parseHostScanReplies reads.
	payload := `<config-auth><csd host-scan-reply="true"><host-scan-reply>` +
		`AAAAAAAAAAAABBBBBBBBBBCCCCCCCCCC` +
		`</host-scan-reply></csd></config-auth>`
	h := newFileLoggerHandler(t)
	events := asaExchange(t, h, http.MethodPost, "/+CSCOE+/webvpn/index.html", "text/xml", payload)

	if len(events) < 2 {
		t.Fatalf("expected a post event plus a cve_2018_0101_payload event, got %d events", len(events))
	}
	var cve event
	for _, e := range events {
		if e.Event == "cve_2018_0101_payload" {
			cve = e
		}
	}
	if cve.Event == "" {
		t.Fatalf("no cve_2018_0101_payload event was emitted: %+v", events)
	}
	// The parse still has to see the unredacted bytes, or the decoy has
	// stopped detecting the exploit it was built for.
	if got := parseHostScanReplies([]byte(payload)); len(got) != 1 {
		t.Fatalf("the unredacted payload no longer parses to one reply (%v); the decoy has lost its own signature", got)
	}
	if cve.Data != "AAAAAAAAAAAABBBBBBBBBBCCCCCCCCCC" {
		t.Errorf("the exploit payload did not survive redaction intact: %q", cve.Data)
	}
	// And a credential hidden in the payload still does not get stored.
	withSecret := `<config-auth><csd host-scan-reply="true"><host-scan-reply>` +
		`<password>` + canarySecret + `</password>` +
		`</host-scan-reply></csd></config-auth>`
	h2 := newFileLoggerHandler(t)
	asaExchange(t, h2, http.MethodPost, "/+CSCOE+/webvpn/index.html", "text/xml", withSecret)
	if got := readLog(t, h2); strings.Contains(got, canarySecret) {
		t.Errorf("a credential smuggled into a host-scan-reply reached the log: %s", got)
	}
}

// TestDecoyIndicatorIsNotAVendorDefaultList is the scope guard, and on this
// sensor it is worth being explicit about why. This is a Cisco ASA decoy. A
// Cisco ASA has real, published, well-known default credentials, and
// pasting that list in would have been the obvious implementation of
// "static credential indicators". It is also a claim about a real product's
// behaviour that this fleet has never tested and cannot support, on a decoy
// that cannot authenticate anybody anyway.
func TestDecoyIndicatorIsNotAVendorDefaultList(t *testing.T) {
	if len(decoyIndicators) == 0 {
		t.Fatal("the indicator set is empty, so credential_indicator_match can never fire")
	}
	for _, d := range decoyIndicators {
		if d.product == "" || d.account == "" || d.username == "" || d.password == "" {
			t.Errorf("an incomplete indicator would be a match that says nothing: %+v", d)
		}
		// Every indicator must be scoped to this fleet's own "nexusai-*"
		// persona. A real vendor's product name here would be exactly the
		// research-proposal-as-fact that #3180's correction was about.
		if !strings.HasPrefix(d.product, "nexusai-") {
			t.Errorf("indicator product %q is not this fleet's own fictional persona; "+
				"a vendor name here would be an untested claim about a real product", d.product)
		}
		// And a real-looking default must not match by accident.
		if got := matchDecoyIndicator("cisco", "cisco"); got != "" {
			t.Errorf("a credential that is not ours matched (%q)", got)
		}
	}
	if got := matchDecoyIndicator(decoyIndicators[0].username, "hunter2"); got != "" {
		t.Errorf("a username alone matched (%q): a decoy credential is account-specific", got)
	}
	if got := matchDecoyIndicator("", decoyIndicators[0].password); got != "" {
		t.Errorf("a password alone matched (%q)", got)
	}
	if got := matchDecoyIndicator(decoyIndicators[0].username, decoyIndicators[0].password); got == "" {
		t.Fatal("the fleet's own bait credential must match itself; an unreachable indicator is a silent failure")
	}
}

// TestBaitCredentialMarksAnAttemptNotAccess keeps the scope of the
// indicator field honest in the direction that matters: matching the bait
// is an ATTEMPT, and the decoy still has no verifier to have accepted it.
func TestBaitCredentialMarksAnAttemptNotAccess(t *testing.T) {
	bait := decoyIndicators[0]
	h := newTestWebvpnHandler()
	e := last(t, asaExchange(t, h, http.MethodPost, "/+CSCOE+/logon.html",
		"application/x-www-form-urlencoded",
		"username="+bait.username+"&password="+bait.password))

	if !e.CredentialIndicatorMatch {
		t.Fatal("the fleet's own bait credential did not set credential_indicator_match")
	}
	if !strings.Contains(e.CredentialIndicator, bait.product) {
		t.Errorf("credential_indicator = %q, want it scoped to the decoy's own product", e.CredentialIndicator)
	}
	if e.AuthOutcome == string(authReal) {
		t.Fatalf("auth_outcome = %q: matching a bait credential is an attempt, not a successful authentication", e.AuthOutcome)
	}
}

// TestNoSessionIdWasInvented is the correlation guard.
//
// #3213 asks for correlation on a source event or session "only where one
// genuinely exists" and forbids inventing a join key. This decoy mints no
// per-client identifier: clearedCookies() sets the same seven fixed values
// for everybody, and nothing ever reads one back to identify a client. The
// tempting fix is to hash the flow tuple or stamp a counter so every event
// has a session_id that looks joinable -- and it would correlate nothing,
// while being indistinguishable from a real one in every dashboard. So the
// field is a presence boolean, and this test holds it there.
func TestNoSessionIdWasInvented(t *testing.T) {
	// A request with no cookie of ours, and one with several, from the
	// same client: the join key that genuinely exists must be identical
	// across them, and it is the flow tuple.
	bare := httptest.NewRequest(http.MethodGet, "https://example/", nil)
	bare.RemoteAddr = "198.51.100.7:54321"
	if hasDecoySessionCookie(bare) {
		t.Error("a request with no cookie must not report a decoy session")
	}
	withCookies := httptest.NewRequest(http.MethodGet, "https://example/", nil)
	withCookies.AddCookie(&http.Cookie{Name: "webvpnlogin", Value: "1"})
	withCookies.AddCookie(&http.Cookie{Name: "tg", Value: "anything-at-all"})
	if !hasDecoySessionCookie(withCookies) {
		t.Error("a request carrying one of this decoy's own cookies must report the session signal")
	}
	// The cookie VALUE must not matter, because this decoy sets the same
	// value for everybody -- if a different value produced a different
	// answer, the field would be quietly pretending to be a session id.
	other := httptest.NewRequest(http.MethodGet, "https://example/", nil)
	other.AddCookie(&http.Cookie{Name: "webvpnlogin", Value: "totally-different"})
	if hasDecoySessionCookie(other) != hasDecoySessionCookie(withCookies) {
		t.Error("the session signal changed with the cookie value; it is a presence boolean, not an identifier")
	}
	// An unrelated cookie is not our session.
	stranger := httptest.NewRequest(http.MethodGet, "https://example/", nil)
	stranger.AddCookie(&http.Cookie{Name: "_ga", Value: "GA1.2.1234"})
	if hasDecoySessionCookie(stranger) {
		t.Error("an unrelated cookie was read as this decoy's session signal")
	}

	// And nothing in the serialized event may carry a session identifier.
	h := newFileLoggerHandler(t)
	r := httptest.NewRequest(http.MethodGet, "https://example/+CSCOE+/logon.html", nil)
	r.AddCookie(&http.Cookie{Name: "webvpnlogin", Value: "1"})
	r.RemoteAddr = "198.51.100.7:54321"
	h.ServeHTTP(httptest.NewRecorder(), r)
	line := readLog(t, h)
	if !strings.Contains(line, `"decoy_session_present":true`) {
		t.Errorf("the session signal did not reach the event: %s", line)
	}
	for _, forbidden := range []string{"session_id", "session_key", "sid", "token"} {
		if strings.Contains(line, forbidden) {
			t.Errorf("the event carries a %q field; this decoy has no session identifier to carry", forbidden)
		}
	}
}

// TestSecretHeaderValuesAreReplaced covers the header map, which is the
// other pre-#3213 place a captured secret landed on this sensor.
func TestSecretHeaderValuesAreReplaced(t *testing.T) {
	h := newFileLoggerHandler(t)
	r := httptest.NewRequest(http.MethodGet, "https://example/", nil)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:"+canarySecret)))
	r.Header.Set("Cookie", "webvpnlogin=1; tg="+canarySecret)
	r.Header.Set("X-Api-Key", canarySecret)
	r.Header.Set("User-Agent", "curl/8.5.0")
	r.RemoteAddr = "198.51.100.7:54321"
	h.ServeHTTP(httptest.NewRecorder(), r)

	var e event
	if err := json.Unmarshal([]byte(readLog(t, h)), &e); err != nil {
		t.Fatalf("undecodable log line: %v", err)
	}
	if e.Headers["Authorization"] != redactMarker {
		t.Errorf("Authorization header value = %q, want %q", e.Headers["Authorization"], redactMarker)
	}
	if e.Headers["Cookie"] != redactMarker {
		t.Errorf("Cookie header value = %q, want %q", e.Headers["Cookie"], redactMarker)
	}
	if e.Headers["X-Api-Key"] != redactMarker {
		t.Errorf("X-Api-Key header value = %q, want %q", e.Headers["X-Api-Key"], redactMarker)
	}
	if e.Headers["User-Agent"] != "curl/8.5.0" {
		t.Errorf("a non-secret header must survive intact, got %q", e.Headers["User-Agent"])
	}
	if got := readLog(t, h); strings.Contains(got, canarySecret) {
		t.Errorf("the captured password reached the log: %s", got)
	}
}

// TestCompassDoesNotLoseItsValueToPass is the false-positive guard on the
// opaque scrubber, which now runs over the CVE payload too. It
// over-redacts on purpose -- a missed redaction costs the trust boundary --
// but "compass=1" losing its value would mean the scrubber cannot tell a
// field name from a substring of one, which would make every scrubbed body
// useless.
func TestCompassDoesNotLoseItsValueToPass(t *testing.T) {
	got, material := redactOpaque("compass=1&user=admin&password=" + canarySecret)
	if !strings.Contains(got, "=1") {
		t.Errorf("the scrubber ate a value belonging to 'compass', which merely contains 'pass': %q", got)
	}
	if !strings.Contains(got, "user=admin") {
		t.Errorf("the scrubber ate a non-credential field: %q", got)
	}
	if !material {
		t.Error("a real password in the payload was not reported as credential material")
	}
	if strings.Contains(got, canarySecret) {
		t.Errorf("the password survived the opaque scrubber: %q", got)
	}
}

// TestTheFieldNameSurvivesItsOwnRedaction is the regression guard for a
// bug the HTTP decoy's suite caught and this one would have inherited.
//
// The opaque scrubber matches the SHORTEST key that fits, so "password=x"
// matches the key "pass" with the cursor left on "word=". Redacting from
// there without first writing the rest of the name back turns
// "password=x" into "pass[redacted]". The scrubber runs over this
// sensor's CVE-2018-0101 payload too, so a field name being mangled here
// would be mangling the exploit signature as well as the secret.
func TestTheFieldNameSurvivesItsOwnRedaction(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "password=" + canarySecret, want: "password=" + redactMarker},
		{in: "pass=" + canarySecret, want: "pass=" + redactMarker},
		{in: "passwd=" + canarySecret, want: "passwd=" + redactMarker},
		{in: "api_key=" + canarySecret, want: "api_key=" + redactMarker},
		{in: "loginPassword=" + canarySecret, want: "loginPassword=" + redactMarker},
		// The space after ':' is part of the value being replaced, so it
		// goes with it. Only the field's own shape is preserved.
		{in: "password: " + canarySecret, want: "password:" + redactMarker},
		{in: `password="` + canarySecret + `"`, want: `password="` + redactMarker + `"`},
		{in: "<password>" + canarySecret + "</password>", want: "<password>" + redactMarker + "</password>"},
		{in: "user=admin&password=" + canarySecret, want: "user=admin&password=" + redactMarker},
	}
	for _, tc := range cases {
		got, _ := redactOpaque(tc.in)
		if got != tc.want {
			t.Errorf("redactOpaque(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestAQuotedValueIsBoundedByItsOwnQuote is the second bug the HTTP
// decoy's suite caught, and the one this sensor would have inherited.
//
// A quoted value used to be bounded by whichever separator introduced it,
// which is wrong for JSON: the value after ':' is a quoted string, and the
// ':' rule -- scan to the next comma, brace or bracket -- runs straight
// past the closing quote. So a JSON body sent with a Content-Type that
// lies about it wrote the secret straight back into the log. Worse, a
// quoted FIELD name has a closing quote before its separator, and a quote
// is also one of the value separators, so the scrubber used to treat the
// key's own quote as "a quoted value starts here".
func TestAQuotedValueIsBoundedByItsOwnQuote(t *testing.T) {
	cases := []string{
		`{"password":"` + canarySecret + `"}`,
		`{"user":"admin","password":"` + canarySecret + `","next":"/wp-admin"}`,
		`{"loginPassword":"` + canarySecret + `"}`,
		`{"userPassword":"` + canarySecret + `"}`,
		`{'password': '` + canarySecret + `'}`,
		`{"credentials":{"apiKey":"` + canarySecret + `"}}`,
	}
	for _, in := range cases {
		got, _ := redactOpaque(in)
		if strings.Contains(got, canarySecret) {
			t.Errorf("redactOpaque(%q) = %q -- the secret survived", in, got)
		}
		if !strings.Contains(got, redactMarker) {
			t.Errorf("redactOpaque(%q) = %q -- nothing was redacted at all", in, got)
		}
	}
}

// TestCamelCaseFieldNamesAreRecognised holds the other half of the
// token-start rule: a match mid-word needs an uppercase letter to start it,
// which separates a real camelCase field name from the "pass" inside
// "compass". Both halves have to hold, or the scrubber either mangles
// ordinary words or misses the field names real clients send.
func TestCamelCaseFieldNamesAreRecognised(t *testing.T) {
	for _, name := range []string{"loginPassword", "userPassword", "apiKey", "APIKEY", "authToken", "sessionId"} {
		in := name + "=" + canarySecret
		got, _ := redactOpaque(in)
		if strings.Contains(got, canarySecret) {
			t.Errorf("redactOpaque(%q) = %q -- a camelCase field name was missed", in, got)
		}
		if !strings.Contains(got, name+"=") {
			t.Errorf("redactOpaque(%q) = %q -- the field name was mangled", in, got)
		}
	}
	for _, word := range []string{"compass", "mypass", "bypassed", "bypasscode"} {
		in := word + "=1"
		got, _ := redactOpaque(in)
		if !strings.Contains(got, "=1") {
			t.Errorf("redactOpaque(%q) = %q -- a word containing 'pass' lost its value", in, got)
		}
	}
}

// TestSecretWithSpacesIsFullyRedacted is why the opaque scrubber is a
// value-aware scrubber rather than a truncating one. A password is exactly
// where someone puts a space, and a redactor that stopped at the first one
// would have logged most of the secret.
func TestSecretWithSpacesIsFullyRedacted(t *testing.T) {
	got, _ := redactOpaque("password=hunter2 with spaces inside\nnext=/admin")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "spaces inside") {
		t.Fatalf("the scrubber stopped at the first space and left the rest of the secret: %q", got)
	}
	if !strings.Contains(got, "next=/admin") {
		t.Errorf("the scrubber ate the line after the credential: %q", got)
	}
}

// ----------------------------------------------------- the shapes that leaked ----
//
// Everything below was found by running the built binary and grepping its own
// emitted event stream for a known password, not by reading the code. The
// scrubber is shared with http-honeypot as a deliberate byte-identical copy
// (redaction.go), so the shapes are the same on both decoys; what differs is
// where the body lands afterwards, and here it lands in the event's `data`
// field -- the field that held this sensor's full WebVPN logon form,
// username and password both, before #3213.
//
// The common cause is that the scrubber only knows how to bound a value
// introduced by a separator (`=`, `:`, `>`, a quote). Each shape below puts
// something between the credential field name and its value, or has no
// separator at all.

// TestAMultipartLogonPostIsScrubbedOnTheASA is the shared scrubber's newest
// shape, and it leaked for a structural reason: in multipart the name and the
// value are separated by a blank LINE, so there was no separator for a
// key/value scan to act on and the whole body reached `data` with the
// password in it.
func TestAMultipartLogonPostIsScrubbedOnTheASA(t *testing.T) {
	h := newFileLoggerHandler(t)
	body := "--X\r\n" +
		"Content-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n" +
		"--X\r\n" +
		"Content-Disposition: form-data; name=\"password\"\r\n\r\n" + canarySecret + "\r\n" +
		"--X\r\n" +
		"Content-Disposition: form-data; name=\"group\"\r\n\r\nnexusai\r\n" +
		"--X--"
	events := asaExchange(t, h, http.MethodPost, "/+webvpn+/index.html", "multipart/form-data; boundary=X", body)

	for _, e := range events {
		if strings.Contains(e.Data, canarySecret) {
			t.Fatalf("a multipart password reached the event data: %q", e.Data)
		}
	}
	post := last(t, events)
	for _, keep := range []string{`name="username"`, `name="password"`, "admin", "nexusai", "--X--"} {
		if !strings.Contains(post.Data, keep) {
			t.Errorf("redaction destroyed %q: %q", keep, post.Data)
		}
	}
	if post.CredentialStatus == string(credAbsent) {
		t.Errorf("credential_status = absent for a body holding a password")
	}
}

// TestAMultipartFilenameIsScrubbedWhenItCarriesACredentialField stops short
// of redacting every filename: an uploaded filename is payload signal. What
// is not kept is a filename carrying a credential-shaped field name, which is
// how a credential gets reflected back through a header nobody reads.
func TestAMultipartFilenameIsScrubbedWhenItCarriesACredentialField(t *testing.T) {
	leaky := "--X\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"password=" + canarySecret + ".txt\"\r\n\r\nx\r\n--X--"
	got, _ := redactSecretValues(leaky, "multipart/form-data; boundary=X")
	if strings.Contains(got, canarySecret) {
		t.Errorf("a credential inside a filename survived: %q", got)
	}
	// "filename=" contains "name=" as a substring, so reading the filename
	// parameter as the field name would report every file part as one.
	benign := "--X\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"seed.txt\"\r\n\r\nx\r\n--X--"
	if got, _ := redactSecretValues(benign, "multipart/form-data; boundary=X"); got != benign {
		t.Errorf("a file part was rewritten with no credential in it: %q", got)
	}
}

// TestAnHTMLFormFieldIsScrubbedOnTheASA covers `<input name="password"
// value="...">`, which is how every HTML login form spells the field. The
// scrubber wrote the name, met a 'v' where it expected a separator, and gave
// up.
func TestAnHTMLFormFieldIsScrubbedOnTheASA(t *testing.T) {
	for _, body := range []string{
		`<form action="/+webvpn+/index.html"><input name="password" value="` + canarySecret + `"></form>`,
		`<input name=password value=` + canarySecret + `>`,
		`<input type="text" name="username" value="admin"><input type="password" name="password" value="` + canarySecret + `">`,
	} {
		got, _ := redactSecretValues(body, "text/html")
		if strings.Contains(got, canarySecret) {
			t.Errorf("redactSecretValues(%q) = %q -- the secret survived", body, got)
		}
		if !strings.Contains(got, redactMarker) {
			t.Errorf("redactSecretValues(%q) = %q -- nothing was redacted", body, got)
		}
	}
	// A tag boundary stops the search: a field name must not reach into a
	// later element's value, or the scrubber becomes a document rewriter.
	got, _ := redactSecretValues(`<a title="password"><b value="`+canarySecret+`">`, "text/html")
	if !strings.Contains(got, canarySecret) {
		t.Errorf("the search escaped its own tag and redacted an unrelated value: %q", got)
	}
}

// TestAContentTypeThatLiesIsNotBelievedOnTheASA is the one with the worst
// consequence. A body of `password: <secret>` labelled form-urlencoded was
// reported `credential_status: absent` -- a positive claim that the request
// carried no credentials -- while `data` held the password. The JSON branch
// already refused to take the header's word for it; the form branch did not.
func TestAContentTypeThatLiesIsNotBelievedOnTheASA(t *testing.T) {
	for _, body := range []string{
		"password: " + canarySecret,
		`{"password":"` + canarySecret + `"}`,
	} {
		got, material := redactSecretValues(body, "application/x-www-form-urlencoded")
		if strings.Contains(got, canarySecret) {
			t.Errorf("a lying Content-Type stored the secret: %q", got)
		}
		if !material {
			t.Errorf("material = false for %q, want true: reporting this body as "+
				"credential-free is the bug -- the event claimed absent while holding the password", body)
		}
	}

	// And end to end, because "material" is only useful if it reaches the
	// event: the status has to stop saying absent.
	h := newFileLoggerHandler(t)
	post := last(t, asaExchange(t, h, http.MethodPost, "/+CSCOE+/logon.html",
		"application/x-www-form-urlencoded", "password: "+canarySecret))
	if post.CredentialStatus == string(credAbsent) {
		t.Errorf("credential_status = absent for a body holding a password: the header lied and we believed it")
	}
	if strings.Contains(post.Data, canarySecret) {
		t.Errorf("the secret survived into the event data: %q", post.Data)
	}
}
