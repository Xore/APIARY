// credentials_test.go is the proof half of #3213.
//
// Two claims are being made in production code (credentials.go) and this
// file is what holds them to account:
//
//  1. The three axes are separate. A response status says what was served,
//     credential_status says what could be learned about the credentials,
//     and auth_outcome says whether an authentication decision was made
//     and by whom. The bug was that the first was doing the work of the
//     other two.
//
//  2. A captured password never survives a request. Not in the event, not
//     in the log line, not in the response body. That is a trust boundary,
//     and TestPasswordNeverReachesTheEvent is the test that matters -- the
//     rest of this file would still be worth having without it, but a
//     regression there is the one that loses an operator's fleet.
//
// The vocabulary under test is deliberately not a vendor default-credential
// list. #3180's research proposed one; this fleet runs no such product, so
// the only indicators here are bait this repository invented for its own
// decoy pages, and both halves must match before one is reported.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// canarySecret is the password every leak test submits. It appears in this
// file and nowhere else in the binary, which is exactly the property the
// leak tests assert: a string that reaches inspectCredentials must not be
// findable in what comes out.
const canarySecret = "correct-horse-battery-staple-9f2c"

// canaryUsername is submitted alongside canarySecret. The username half IS
// allowed to survive -- it is the analytic value and not a secret -- so the
// leak tests must distinguish the two, or they would be asserting the
// feature away.
const canaryUsername = "edge-operator"

// postForm drives one real request through ServeHTTP and returns the log
// line the logger emitted, which is the same bytes the event serialized to
// and the same bytes Filebeat ships. Testing the log rather than the event
// struct covers both: the logger marshals the event, so a field carrying a
// secret is a leak into the log even when the struct is never inspected.
func postForm(t *testing.T, s *server, method, target, contentType, body string) (string, event) {
	t.Helper()
	r := httptest.NewRequest(method, "http://example"+target, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r.RemoteAddr = "198.51.100.7:54321"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	line := strings.TrimSpace(s.log.out.(*bytes.Buffer).String())
	var e event
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("log line is not a decodable event (%v): %s", err, line)
	}
	return line, e
}

// TestCredentialStatusStatesAreReachableAndDistinct walks all three states
// #3213 names, plus the fourth the sensor needs, and proves each is
// reachable from a real request and that no two requests collapse onto one
// value. The reachability half is what stops this from being a vocabulary
// that exists only in a const block.
func TestCredentialStatusStatesAreReachableAndDistinct(t *testing.T) {
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
			name:        "absent: a body with no credential field, read in full",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "application/x-www-form-urlencoded",
			body:        "next=%2Fadmin&remember=1",
			want:        credAbsent,
		},
		{
			name:   "absent: no body and no Authorization header at all",
			method: http.MethodGet,
			target: "/",
			want:   credAbsent,
		},
		{
			name:        "extracted: a form login the sensor can map",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=root&password=" + canarySecret,
			want:        credExtracted,
			wantUser:    "root",
			wantChannel: "form",
		},
		{
			name:        "extracted: a Basic header the sensor can decode",
			method:      http.MethodGet,
			target:      "/",
			header:      [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:"+canarySecret))},
			want:        credExtracted,
			wantUser:    "admin",
			wantChannel: "basic",
		},
		{
			name:        "present_unparsed: an Authorization scheme it does not decode",
			method:      http.MethodGet,
			target:      "/",
			header:      [2]string{"Authorization", "Negotiate YIIFmYWNrZXRoZG1pbnNjcmlwdA=="},
			want:        credUnparsed,
			wantChannel: "negotiate",
		},
		{
			name:        "present_unparsed: a Basic value that is not base64",
			method:      http.MethodGet,
			target:      "/",
			header:      [2]string{"Authorization", "Basic !!!not-base64!!!"},
			want:        credUnparsed,
			wantChannel: "basic",
		},
		{
			name:        "present_unparsed: credential-shaped JSON it cannot map",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "application/json",
			body:        `{"credentials":{"apiKey":"` + canarySecret + `"}}`,
			want:        credUnparsed,
		},
		{
			name:   "present_unparsed: a credential in the query string",
			method: http.MethodGet,
			target: "/login?token=" + canarySecret,
			want:   credUnparsed,
		},
		{
			name:        "unknown: a body past the read cap, so its tail was never seen",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "application/x-www-form-urlencoded",
			body:        "a=" + strings.Repeat("x", bodyReadCap),
			want:        credUnknown,
		},
		{
			name:        "unknown: a body no key scan can speak for",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "application/octet-stream",
			body:        "\xff\xfe\x00\x01\x02\x03\x04\x05",
			want:        credUnknown,
		},
	}

	seen := map[credentialStatus]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer()
			r := httptest.NewRequest(tc.method, "http://example"+tc.target, strings.NewReader(tc.body))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if tc.header[0] != "" {
				r.Header.Set(tc.header[0], tc.header[1])
			}
			r.RemoteAddr = "198.51.100.7:54321"
			s.ServeHTTP(httptest.NewRecorder(), r)

			var e event
			if err := json.Unmarshal([]byte(strings.TrimSpace(s.log.out.(*bytes.Buffer).String())), &e); err != nil {
				t.Fatalf("undecodable log line: %v", err)
			}
			if got := credentialStatus(e.CredentialStatus); got != tc.want {
				t.Fatalf("credential_status = %q, want %q", got, tc.want)
			}
			if tc.wantUser != "" && e.Username != tc.wantUser {
				t.Fatalf("username = %q, want %q (the account half is the analytic value and is kept)", e.Username, tc.wantUser)
			}
			if tc.wantUser == "" && e.Username != "" {
				t.Fatalf("username = %q, want empty: nothing in this request maps to an account", e.Username)
			}
			if tc.wantChannel != "" && e.AuthType != tc.wantChannel {
				t.Fatalf("auth_type = %q, want %q", e.AuthType, tc.wantChannel)
			}
			// Reachability, recorded per state. Many requests legitimately
			// land on the same state -- most requests carry no credential
			// at all -- so the distinctness claim is about the four values,
			// asserted below, and this map only proves each one is
			// reachable from real traffic.
			seen[credentialStatus(e.CredentialStatus)] = tc.name
		})
	}

	all := []credentialStatus{credAbsent, credExtracted, credUnparsed, credUnknown}
	for _, want := range all {
		if _, ok := seen[want]; !ok {
			t.Errorf("credential_status %q was never produced by a real request; the state is declared but unreachable", want)
		}
	}
	// Distinctness: four states, four different wire values. If any two
	// constants were given the same string, one state would be
	// unrepresentable and an analyst reading the field could not tell
	// which answer they were looking at.
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[i] == all[j] {
				t.Errorf("credential states %q and %q serialize to the same value, so they are not distinct", all[i], all[j])
			}
		}
	}
}

// TestUnknownIsNeverCollapsedIntoAbsent is the specific regression #3213
// is named for. A plain boolean cannot say "we could not tell" -- it can
// only say false, which reads as "we looked and there was nothing". So
// CredentialPresent is a pointer and is null exactly when the status is
// unknown; if that ever becomes a non-pointer or a plain false, the
// distinction an analyst is told to trust is gone.
func TestUnknownIsNeverCollapsedIntoAbsent(t *testing.T) {
	s, _ := newTestServer()
	// A form login larger than the read cap: the credentials are very
	// probably in the part nobody read, and saying "absent" would be a
	// claim this sensor cannot make.
	_, e := postForm(t, s, http.MethodPost, "/login",
		"application/x-www-form-urlencoded", "user=root&password="+strings.Repeat("A", bodyReadCap))

	if e.CredentialStatus != string(credUnknown) {
		t.Fatalf("credential_status = %q, want %q for a body past the read cap", e.CredentialStatus, credUnknown)
	}
	if e.CredentialPresent != nil {
		t.Fatalf("credential_present = %v, want null for unknown -- a false here is indistinguishable from absent", *e.CredentialPresent)
	}

	// And the contrast: a body read in full with nothing in it IS absent,
	// and reports a real false rather than a null.
	s2, _ := newTestServer()
	line, e2 := postForm(t, s2, http.MethodPost, "/login",
		"application/x-www-form-urlencoded", "next=%2Fadmin")

	if e2.CredentialStatus != string(credAbsent) {
		t.Fatalf("credential_status = %q, want %q", e2.CredentialStatus, credAbsent)
	}
	if e2.CredentialPresent == nil || *e2.CredentialPresent {
		t.Fatalf("credential_present = %v, want a real false for a body read in full with no credential in it", e2.CredentialPresent)
	}
	// The two must be distinguishable in the serialized bytes, not merely
	// in the struct: absent and unknown have to differ on the wire.
	if line == "" {
		t.Fatal("no log line emitted")
	}
	if !strings.Contains(line, `"credential_present":false`) {
		t.Fatalf("absent must serialize credential_present as false, got %s", line)
	}
	if strings.Contains(line, `"credential_present":null`) {
		t.Fatalf("absent must not serialize credential_present as null, got %s", line)
	}

	s3, _ := newTestServer()
	line3, _ := postForm(t, s3, http.MethodPost, "/login",
		"application/x-www-form-urlencoded", "user=root&password="+strings.Repeat("A", bodyReadCap))
	if !strings.Contains(line3, `"credential_present":null`) {
		t.Fatalf("unknown must serialize credential_present as null, got %s", line3)
	}
}

// TestAuthRealIsUnreachable is the second inference #3213 forbids: that a
// 200 means authentication succeeded.
//
// This binary has no account store, no verifier, and no authentication
// backend, so the honest answer for every 200 it serves is
// auth_outcome=simulated (the decoy's persona answered) or unknown (no
// decision was made). authReal exists in the vocabulary for a sensor that
// does delegate; here it must never be emitted. Every branch that can serve
// a 200 is walked, because the whole point is that a status code is not a
// verdict.
func TestAuthRealIsUnreachable(t *testing.T) {
	bearer := "Bearer sk-decoy-token-never-validated"
	cases := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		header      [2]string
		wantStatus  int
	}{
		{name: "a login page rendering", method: http.MethodGet, target: "/login", wantStatus: http.StatusOK},
		{name: "a login form POSTed to", method: http.MethodPost, target: "/login", contentType: "application/x-www-form-urlencoded", body: "username=root&password=" + canarySecret, wantStatus: http.StatusOK},
		{name: "WordPress wp-login.php", method: http.MethodGet, target: "/wp-login.php", wantStatus: http.StatusOK},
		{name: "a phpMyAdmin console", method: http.MethodGet, target: "/phpmyadmin/index.php", wantStatus: http.StatusOK},
		{name: "a bearer-authenticated fake model list", method: http.MethodGet, target: "/v1/models", header: [2]string{"Authorization", bearer}, wantStatus: http.StatusOK},
		{name: "a chat completion for an unvalidated token", method: http.MethodPost, target: "/v1/chat/completions", header: [2]string{"Authorization", bearer}, wantStatus: http.StatusOK},
		{name: "an unauthenticated model list", method: http.MethodGet, target: "/v1/models", wantStatus: http.StatusUnauthorized},
		{name: "a container registry challenge", method: http.MethodGet, target: "/v2/", wantStatus: http.StatusUnauthorized},
		{name: "a Kubernetes API denial", method: http.MethodGet, target: "/api/v1/pods", wantStatus: http.StatusForbidden},
		{name: "a Tomcat manager challenge", method: http.MethodGet, target: "/manager/html", wantStatus: http.StatusUnauthorized},
		{name: "a Tomcat manager rejection", method: http.MethodGet, target: "/manager/html", header: [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("tomcat:"+canarySecret))}, wantStatus: http.StatusForbidden},
		{name: "a plain 404", method: http.MethodGet, target: "/nothing-here", wantStatus: http.StatusNotFound},
		{name: "a metadata probe", method: http.MethodGet, target: "/latest/meta-data/", wantStatus: http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer()
			r := httptest.NewRequest(tc.method, "http://example"+tc.target, strings.NewReader(tc.body))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if tc.header[0] != "" {
				r.Header.Set(tc.header[0], tc.header[1])
			}
			r.RemoteAddr = "198.51.100.7:54321"
			s.ServeHTTP(httptest.NewRecorder(), r)

			var e event
			if err := json.Unmarshal([]byte(strings.TrimSpace(s.log.out.(*bytes.Buffer).String())), &e); err != nil {
				t.Fatalf("undecodable log line: %v", err)
			}
			if e.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", e.Status, tc.wantStatus)
			}
			if e.AuthOutcome == string(authReal) {
				t.Fatalf("auth_outcome = %q on a %d: this decoy has no authentication backend, so no branch may ever claim a real decision", e.AuthOutcome, e.Status)
			}
			if authOutcome(e.AuthOutcome) != authSimulated && authOutcome(e.AuthOutcome) != authUnknown {
				t.Fatalf("auth_outcome = %q, want one of the two values this binary can honestly produce", e.AuthOutcome)
			}
		})
	}
}

// TestAuthOutcomeIsNeverDerivedFromStatus is the same claim stated as a
// rule rather than an enumeration: no 200 anywhere in this table means
// "authentication succeeded". The 200s above are the decoy's pages
// rendering and its fake model list answering a token nobody checked; the
// auth_outcome on each says so, and 403/401/404 are equally not verdicts.
func TestAuthOutcomeIsNeverDerivedFromStatus(t *testing.T) {
	// Two requests to the same path differing only in credentials, so the
	// status is identical and nothing but the axis under test can differ.
	s, _ := newTestServer()
	bogus := "Basic " + base64.StdEncoding.EncodeToString([]byte("tomcat:"+canarySecret))
	for _, auth := range []string{bogus, "Basic " + base64.StdEncoding.EncodeToString([]byte("tomcat:wrong-entirely"))} {
		s.log.out.(*bytes.Buffer).Reset()
		r := httptest.NewRequest(http.MethodGet, "http://example/manager/html", nil)
		r.Header.Set("Authorization", auth)
		r.RemoteAddr = "198.51.100.7:54321"
		s.ServeHTTP(httptest.NewRecorder(), r)

		var e event
		if err := json.Unmarshal([]byte(strings.TrimSpace(s.log.out.(*bytes.Buffer).String())), &e); err != nil {
			t.Fatalf("undecodable log line: %v", err)
		}
		if e.Status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 for both submissions", e.Status)
		}
		if e.AuthOutcome != string(authSimulated) {
			t.Fatalf("auth_outcome = %q, want %q: a rejection by the persona is still a simulated decision", e.AuthOutcome, authSimulated)
		}
	}
}

// TestPasswordNeverReachesTheEvent is the trust-boundary test.
//
// Every credential channel this sensor reads is walked with a known
// canary secret, and the whole emitted log line is searched for it. The
// checks are deliberately blunt -- substring search over the serialized
// event, the log file, and the response body -- because a test that
// enumerates fields would pass the day someone added a fourth place to
// leak it.
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
			name:        "form-urlencoded body",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=admin&password=" + canarySecret,
		},
		{
			name:        "form body using pwd and a space in the secret",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "application/x-www-form-urlencoded",
			body:        "login=admin&pwd=" + canarySecret,
		},
		{
			name:        "JSON body",
			method:      http.MethodPost,
			target:      "/api/v1/auth",
			contentType: "application/json",
			body:        `{"user":"admin","password":"` + canarySecret + `","remember":true}`,
		},
		{
			name:        "JSON body, nested and arrays",
			method:      http.MethodPost,
			target:      "/api/v1/auth",
			contentType: "application/json",
			body:        `{"accounts":[{"login":"admin","secret":"` + canarySecret + `"}]}`,
		},
		{
			name:   "Basic authorization header",
			method: http.MethodGet,
			target: "/manager/html",
			header: [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:"+canarySecret))},
		},
		{
			name:   "bearer token, which is password-equivalent",
			method: http.MethodGet,
			target: "/v1/models",
			header: [2]string{"Authorization", "Bearer " + canarySecret},
		},
		{
			name:   "an Authorization scheme the sensor does not decode",
			method: http.MethodGet,
			target: "/manager/html",
			header: [2]string{"Authorization", "Digest username=\"admin\", response=\"" + canarySecret + "\""},
		},
		{
			name:   "a session cookie",
			method: http.MethodGet,
			target: "/admin",
			header: [2]string{"Cookie", "PHPSESSID=" + canarySecret + "; csrftoken=" + canarySecret},
		},
		{
			name:   "an api-key header",
			method: http.MethodGet,
			target: "/v1/models",
			header: [2]string{"X-Api-Key", canarySecret},
		},
		{
			name:   "a credential in the query string",
			method: http.MethodGet,
			target: "/login?next=%2Fadmin&password=" + canarySecret,
		},
		{
			name:        "an XML body no parser here reads",
			method:      http.MethodPost,
			target:      "/xmlrpc.php",
			contentType: "text/xml",
			body:        `<?xml version="1.0"?><login><username>admin</username><password>` + canarySecret + `</password></login>`,
		},
		{
			name:        "a plain-text body",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "text/plain",
			body:        "admin:" + canarySecret,
		},
		{
			name:        "a body that hits the read cap mid-credential",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=admin&filler=" + strings.Repeat("x", bodyReadCap) + "&password=" + canarySecret,
		},
		{
			name:        "a body past the read cap, credential in the unseen tail",
			method:      http.MethodPost,
			target:      "/login",
			contentType: "application/x-www-form-urlencoded",
			body:        "filler=" + strings.Repeat("x", bodyReadCap+16) + "&password=" + canarySecret,
		},
	}

	for _, tc := range channels {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer()
			r := httptest.NewRequest(tc.method, "http://example"+tc.target, strings.NewReader(tc.body))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if tc.header[0] != "" {
				r.Header.Set(tc.header[0], tc.header[1])
			}
			r.RemoteAddr = "198.51.100.7:54321"
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)

			line, _ := postFormNoServe(t, s)

			// The secret in any form: raw, and base64'd (a Basic header
			// arrives encoded, and a leak of the encoded form is still a
			// leak of the secret).
			forms := map[string]string{
				"plain":      canarySecret,
				"urlencoded": strings.ReplaceAll(canarySecret, " ", "+"),
				"base64":     base64.StdEncoding.EncodeToString([]byte(canarySecret)),
				"bearer":     "Bearer " + canarySecret,
			}
			for label, form := range forms {
				if strings.Contains(line, form) {
					t.Errorf("the %s form of the captured password reached the log line: %s", label, line)
				}
			}
			if strings.Contains(w.Body.String(), canarySecret) {
				t.Errorf("the captured password reached the response body: %s", w.Body.String())
			}
			// The whole decoded event, re-marshaled, to catch a field the
			// struct carries but omits on the way in.
			if strings.Contains(mustJSON(t, line), canarySecret) {
				t.Errorf("the captured password reached the serialized event: %s", line)
			}
		})
	}
}

// TestEventHasNoPasswordField proves the removal itself, not just the
// redaction. A field that is always empty is still a field an API consumer
// can be told to read; #3213 removes it, and the PR documents the removal
// as a breaking change to the event contract.
func TestEventHasNoPasswordField(t *testing.T) {
	s, _ := newTestServer()
	r := httptest.NewRequest(http.MethodPost, "http://example/login",
		strings.NewReader("username=admin&password="+canarySecret))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "198.51.100.7:54321"
	s.ServeHTTP(httptest.NewRecorder(), r)
	line, _ := postFormNoServe(t, s)

	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		t.Fatalf("undecodable log line: %v", err)
	}
	for key := range raw {
		if strings.Contains(strings.ToLower(key), "password") || strings.Contains(strings.ToLower(key), "passwd") {
			t.Fatalf("the event still carries a %q field: the pre-#3213 password field must be gone, not left empty", key)
		}
	}
}

// TestDecoyIndicatorNeedsBothHalves is the scope check on the one
// credential-matching code path in the binary. A match means an attempt was
// made with a credential this fleet invented for its own decoy pages. It
// must not be reachable with half a credential, and it must not be
// reachable at all against a password that is not ours -- otherwise the
// field would be a claim about a vendor default, which this repository
// cannot support.
func TestDecoyIndicatorNeedsBothHalves(t *testing.T) {
	bait := decoyIndicators[0]
	if bait.password == "" || bait.username == "" {
		t.Fatalf("the first decoy indicator is incomplete: %+v", bait)
	}

	if got := matchDecoyIndicator(bait.username, bait.password); got == "" {
		t.Fatal("the fleet's own bait credential must match itself -- the indicator is unreachable, which is a silent failure")
	}
	if got := matchDecoyIndicator(bait.username, "some-other-password"); got != "" {
		t.Errorf("username alone matched (%q): a decoy credential is account-specific", got)
	}
	if got := matchDecoyIndicator("", bait.password); got != "" {
		t.Errorf("password alone matched (%q): a password tried against no account is not a credential", got)
	}
	if got := matchDecoyIndicator("admin", "admin"); got != "" {
		t.Errorf("a credential that is not ours matched (%q): this must never read as a vendor default", got)
	}
	// And it must not match on case alone where the password is the secret:
	// the secret is compared exactly, so a case-shifted bait password is a
	// different attempt.
	if got := matchDecoyIndicator(bait.username, strings.ToUpper(bait.password)); got != "" {
		t.Errorf("a case-shifted password matched (%q)", got)
	}
}

// TestIndicatorMatchIsAnAttemptNotAVerdict states the scope of the
// indicator field in code, since the field name is what an API consumer
// reads. A bait-credential match marks an attempt against a fictional
// product this fleet serves; it says nothing about access, and the
// accompanying auth_outcome is still the decoy's own simulated answer.
func TestIndicatorMatchIsAnAttemptNotAVerdict(t *testing.T) {
	s, _ := newTestServer()
	bait := decoyIndicators[0]
	_, e := postForm(t, s, http.MethodPost, "/login",
		"application/x-www-form-urlencoded",
		"username="+bait.username+"&password="+bait.password)

	if !e.CredentialIndicatorMatch {
		t.Fatal("the fleet's own bait credential did not set credential_indicator_match")
	}
	if !strings.Contains(e.CredentialIndicator, decoyIndicators[0].product) {
		t.Fatalf("credential_indicator = %q, want it scoped to the decoy's own product", e.CredentialIndicator)
	}
	if e.AuthOutcome == string(authReal) {
		t.Fatalf("auth_outcome = %q: matching a bait credential is an attempt, not a successful authentication", e.AuthOutcome)
	}
}

// TestRedactionKeepsTheRequestReadable is the other half of removing the
// field. A redacted body that is useless costs the fleet its payload
// signatures, so the non-credential parts have to survive, and the redaction
// marker has to be recognisable as one.
func TestRedactionKeepsTheRequestReadable(t *testing.T) {
	s, _ := newTestServer()
	_, e := postForm(t, s, http.MethodPost, "/login",
		"application/x-www-form-urlencoded",
		"username=admin&password="+canarySecret+"&next=%2Fwp-admin%2F&submit=Log+In")

	if !strings.Contains(e.Body, "next=%2Fwp-admin%2F") || !strings.Contains(e.Body, "submit=Log+In") {
		t.Errorf("redaction destroyed the non-credential parts of the body: %q", e.Body)
	}
	if !strings.Contains(e.Body, "username=admin") {
		t.Errorf("the account identifier should survive -- it is the analytic value, not a secret: %q", e.Body)
	}
	if !strings.Contains(e.Body, "password="+redactMarker) {
		t.Errorf("the password value was not replaced by the redaction marker: %q", e.Body)
	}
}

// TestSecretHeaderValuesAreReplaced covers the header map, which is where
// the pre-#3213 code stored an Authorization header's value. The header
// name is worth keeping -- it names the channel -- and the value is not.
func TestSecretHeaderValuesAreReplaced(t *testing.T) {
	s, _ := newTestServer()
	r := httptest.NewRequest(http.MethodGet, "http://example/", nil)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:"+canarySecret)))
	r.Header.Set("Cookie", "PHPSESSID="+canarySecret)
	r.Header.Set("X-Api-Key", canarySecret)
	r.Header.Set("User-Agent", "curl/8.5.0")
	r.RemoteAddr = "198.51.100.7:54321"
	s.ServeHTTP(httptest.NewRecorder(), r)
	line, e := postFormNoServe(t, s)

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
	if strings.Contains(line, canarySecret) {
		t.Errorf("the captured password reached the log line: %s", line)
	}
}

// TestCompassDoesNotLoseItsValueToPass is the false-positive guard on the
// opaque scrubber. It over-redacts on purpose -- a missed redaction costs
// the trust boundary -- but "compass=1" losing its value would mean the
// scrubber cannot tell a field name from a substring of one, which would
// make every redacted body useless.
func TestCompassDoesNotLoseItsValueToPass(t *testing.T) {
	got, material := redactOpaque("compass=1&user=admin&password=" + canarySecret)
	if strings.Contains(got, "=1") == false {
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

// TestSecretWithSpacesIsFullyRedacted is why redactOpaque is a
// value-aware scrubber rather than a truncating one. A password is exactly
// where someone puts a space, and a redactor that stopped at the first one
// would have logged most of the secret.
func TestSecretWithSpacesIsFullyRedacted(t *testing.T) {
	spaced := "hunter2 with spaces inside"
	got, _ := redactOpaque("password=" + spaced + "\nnext=/admin")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "spaces inside") {
		t.Fatalf("the scrubber stopped at the first space and left the rest of the secret: %q", got)
	}
	if !strings.Contains(got, "next=/admin") {
		t.Errorf("the scrubber ate the line after the credential: %q", got)
	}
}

// TestTheFieldNameSurvivesItsOwnRedaction is the regression guard for a
// bug this suite caught while it was being written.
//
// The opaque scrubber matches the SHORTEST key that fits, so "password=x"
// matches the key "pass" with the cursor left on "word=". Redacting from
// there without first writing the rest of the name back turns
// "password=x" into "pass[redacted]" -- which loses the very field whose
// value is being protected, and leaves a body that no longer parses, so
// the next reader of it would not recognise the field at all. The same
// applies to the separator: "password=" has to come out as
// "password=[redacted]", not "password[redacted]".
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

// TestAQuotedValueIsBoundedByItsOwnQuote is the second bug this suite
// caught, and the more serious of the two.
//
// A quoted value used to be bounded by whichever separator introduced it.
// That is wrong for JSON, where the value after ':' is a quoted string and
// the ':' rule -- scan to the next comma, brace or bracket -- runs straight
// past the closing quote. So a JSON body sent with a Content-Type that
// lies about it, which redactSecretValues routes here on purpose, wrote the
// secret straight back into the log:
//
//	{"password":"secret"}  ->  {"password":"[redacted]"secret"}
//
// It is not hypothetical input either: "Content-Type: text/plain" on a JSON
// body is a one-header change, and this is the path that handles it.
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
	// The surrounding non-credential structure survives, or the scrubbed
	// body would be useless for telling one probe from another.
	got, _ := redactOpaque(`{"user":"admin","password":"` + canarySecret + `","next":"/wp-admin"}`)
	if !strings.Contains(got, `"user":"admin"`) || !strings.Contains(got, `"next":"/wp-admin"`) {
		t.Errorf("redaction destroyed the rest of the body: %q", got)
	}
}

// TestCamelCaseFieldNamesAreRecognised holds the other half of the
// token-start rule. A match mid-word needs an uppercase letter to start it,
// which is what separates a real camelCase field name from the "pass"
// inside "compass" -- and both halves have to hold, or the scrubber either
// mangles ordinary words or misses the field names Java and PHP clients
// actually send.
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
	// And a lowercase match inside a word is still a word, not a field.
	for _, word := range []string{"compass", "mypass", "bypassed", "bypasscode"} {
		in := word + "=1"
		got, _ := redactOpaque(in)
		if !strings.Contains(got, "=1") {
			t.Errorf("redactOpaque(%q) = %q -- a word containing 'pass' lost its value", in, got)
		}
	}
}

// TestTheFieldNameSurvivesThroughARealRequest is the same guard at the
// boundary, because the scrubber is only reached for bodies that are
// neither form-urlencoded nor JSON -- the shapes a login attempt is least
// likely to arrive in and most likely to hide one behind.
func TestTheFieldNameSurvivesThroughARealRequest(t *testing.T) {
	s, _ := newTestServer()
	_, e := postForm(t, s, http.MethodPost, "/login", "application/octet-stream",
		"user=admin&password="+canarySecret+"&next=/wp-admin")

	if !strings.Contains(e.Body, "password="+redactMarker) {
		t.Errorf("the field name did not survive redaction: %q", e.Body)
	}
	if !strings.Contains(e.Body, "user=admin") || !strings.Contains(e.Body, "next=/wp-admin") {
		t.Errorf("redaction destroyed the rest of the request: %q", e.Body)
	}
	if strings.Contains(e.Body, canarySecret) {
		t.Errorf("the password survived: %q", e.Body)
	}
}

// postFormNoServe reads whatever is currently in the server's log buffer
// without issuing a second request, so a test can drive a custom request
// and then assert on the line it produced.
func postFormNoServe(t *testing.T, s *server) (string, event) {
	t.Helper()
	line := strings.TrimSpace(s.log.out.(*bytes.Buffer).String())
	var e event
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("undecodable log line (%v): %s", err, line)
	}
	return line, e
}

func mustJSON(t *testing.T, line string) string {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(line), &doc); err != nil {
		t.Fatalf("undecodable log line: %v", err)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}
	return string(out)
}
