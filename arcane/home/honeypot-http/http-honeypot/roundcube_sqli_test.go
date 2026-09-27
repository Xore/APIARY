package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #3364 / CVE-2026-48842: pre-authentication SQL injection in Roundcube
// Webmail's virtuser_query plugin (CVSS 8.1; the Canadian Centre for Cyber
// Security's AV26-503 reports it exploited in the wild as of 2026-09, with
// no exploitation detail published). The value the plugin is handed is
// escaped with preg_replace() before it reaches the virtual-user lookup, and
// a backslash inside the value is what defeats that escape -- so the shape to
// look for is a SQL payload on a Roundcube request-routing parameter, not a
// path: a real attack goes to whatever endpoint the app's own dispatch
// resolves, and this fleet serves no webmail UI, so a bait path would never
// match (the same reasoning #2919 and #3309 followed for their own cases).
//
// Like those two, this is one more branch of the existing byte-pattern
// classifier and its own test table -- no new engine, no new language, and
// nothing here deserializes or evaluates a received value: the request is
// parsed as form/query parameters and each value is matched as bytes.
//
// The cases below are written against the published request shape rather
// than against a capture, because no capture exists -- #3364 is a research
// note and says so. The negatives are the ones that decide whether this is
// usable: a Roundcube login is ordinary traffic, an apostrophe in a mail
// address is not an attack, and a backslash in a value is not SQL. Each
// negative is pinned so a future loosening of the gate shows up as a test
// failure rather than as a classifier that fires on ordinary requests.
func TestRoundcubeVirtuserQuerySQLi(t *testing.T) {
	const want = "roundcube-virtuser-query-sqli"

	cases := []struct {
		name, query, body string
		want              string
	}{
		// --- the published pre-auth shape: the login form itself, whose
		// username is what virtuser_query looks up. `_task`/`_action`/
		// `_token` are Roundcube's own dispatch parameters, and none of
		// them require a session.

		// Root cause, verbatim: a backslash immediately before the quote,
		// so the escape adds a second backslash and the quote closes the
		// literal anyway. %5C and %27 are how it travels in a form body.
		{
			name: "backslash-escape bypass in the login form's username",
			body: "_token=f3a9c1d2b8e7&_task=login&_action=login&_timezone=Europe%2FBerlin&_url=&_user=admin%5C%27+or+1%3D1--&_pass=Summer2026",
			want: want,
		},
		{
			name: "union select through the same escape",
			body: "_token=f3a9c1d2b8e7&_task=login&_action=login&_user=%5C%27+union+select+1%2C2%2C3%2C4%2C5--",
			want: want,
		},
		{
			name: "time-based blind through the same escape",
			body: "_task=login&_action=login&_user=%5C%27+or+sleep(5)--",
			want: want,
		},
		{
			name: "error-based read of the database version",
			body: "_task=login&_action=login&_user=%5C%27+or+extractvalue(1%2Cconcat(0x7e%2Cversion()))--",
			want: want,
		},
		// Not every probe bothers with the backslash -- a deployment whose
		// value is not escaped at all, or a scanner firing both forms, is
		// the same pre-auth SQLi against the same plugin.
		{
			name: "plain unescaped quote, schema exfiltration",
			body: "_task=login&_action=login&_user=%27+union+select+username%2Cpassword+from+information_schema.tables--",
			want: want,
		},
		{
			name: "stacked query, semicolon percent-encoded",
			body: "_task=login&_action=login&_user=admin%27%3B+drop+table+users--",
			want: want,
		},
		// Case is the cheapest encoding variation there is, and the
		// measurement in roundcube_coverage_3364_test.go is what showed
		// the class matched only the published casing: before the fix,
		// both of these were unlabelled on GET and POST alike.
		{
			name: "uppercase union select through the same gate",
			body: "_task=login&_action=login&_user=%27+UNION+SELECT+1%2C2%2C3--",
			want: want,
		},
		{
			name:  "mixed-case time-based in the query",
			query: "_task=login&_action=login&_user=%27+Or+SlEeP(5)--",
			want:  want,
		},
		// --- the plugin reached directly rather than through the login
		// form. Roundcube names a plugin action as _action=plugin.<name>.

		{
			name:  "plugin action named in the query",
			query: "_task=mail&_action=plugin.virtuser_query&_u=%5C%27+union+select+1%2C2%2C3--",
			want:  want,
		},
		{
			name:  "plugin named bare as the action",
			query: "_action=virtuser_query&_u=admin%5C%27+or+1%3D1--",
			want:  want,
		},
		{
			name:  "plugin named as the parameter key, with no _task at all",
			query: "virtuser_query=admin%5C%27+or+1%3D1--",
			want:  want,
		},

		// --- negatives. These decide whether the class is usable at all:
		// the classifier's own rule is that a pattern which fires on
		// ordinary traffic is worse than no pattern, because it makes
		// every event look interesting.

		{
			name: "a real Roundcube login, nothing injected",
			body: "_token=f3a9c1d2b8e7&_task=login&_action=login&_timezone=Europe%2FBerlin&_url=&_user=alice.smith%40example.com&_pass=Summer2026",
			want: "",
		},
		{
			name: "an apostrophe in a mail address is not an injection",
			body: "_task=login&_action=login&_user=o%27brien%40example.com",
			want: "",
		},
		{
			name: "a backslash with no SQL metacharacter is not an injection",
			body: "_task=login&_action=login&_user=domain%5Cuser",
			want: "",
		},
		{
			name: "a bare quote with no SQL metacharacter is not an injection",
			body: "_task=login&_action=login&_user=o%27brien",
			want: "",
		},
		{
			// Plugin enumeration is a real thing to see, and it is not
			// exploitation: nothing is being injected into anything.
			name:  "naming the plugin without a payload",
			query: "_task=plugin&_action=virtuser_query",
			want:  "",
		},
		{
			// The scope this change deliberately does not take. A SQL
			// payload with no webmail shape is somebody else's class (or,
			// in the query string, nobody's -- the generic sqli case reads
			// the body only). Widening to cover it would be a second,
			// generic detection mechanism rather than this CVE, so it stays
			// exactly as it was.
			name: "SQLi with no Roundcube shape keeps its own class",
			body: `log=admin&pwd=x' or 1=1--`,
			want: "sqli",
		},
		{
			name:  "the same payload in a query string with no Roundcube shape is still unlabelled",
			query: "q=admin%5C%27+or+1%3D1--",
			want:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyPayload(c.query, c.body); got != c.want {
				t.Errorf("classifyPayload(%q, %q) = %q, want %q", c.query, c.body, got, c.want)
			}
		})
	}
}

// TestRoundcubeVirtuserSQLiReachesTheEvent is the half a unit test cannot
// cover: that the class actually lands on the emitted event, on a request
// where the decoy made no authentication decision at all.
//
// The pre-auth half is asserted, not assumed. This sensor keeps no session
// and consults no backend, so "pre-auth" here is a statement about the
// request and the response, not about a session the decoy never had:
// auth_outcome is "unknown" -- nothing in serve() decided anything about an
// identity -- while the payload is still classified. That combination is
// the pre-auth SQLi shape, and the class must not require a login to have
// happened first.
func TestRoundcubeVirtuserSQLiReachesTheEvent(t *testing.T) {
	s, output := newTestServer()

	// Roundcube's own login form, carrying the escape bypass in the
	// username. Percent-encoded exactly as a browser would send it, and
	// with the Content-Type a browser sends -- so this exercises the form
	// redaction path rather than the opaque one.
	const body = "_token=f3a9c1d2b8e7&_task=login&_action=login&_timezone=Europe%2FBerlin&_url=&_user=admin%5C%27+or+1%3D1--&_pass=Summer2026"

	r := httptest.NewRequest(http.MethodPost,
		"http://example/?_task=login&_action=login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.7:54321"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	line := output.String()
	if !strings.Contains(line, `"payload_class":"roundcube-virtuser-query-sqli"`) {
		t.Fatalf("the event did not carry the payload class: %s", line)
	}
	// #3213's rule is that redaction must not cost the fleet a payload
	// signature. This body is a form, so the redaction pass ran over it:
	// `_pass` and `_token` are session and credential material and are
	// replaced, and the injected value beside them is neither, so it has to
	// survive for an analyst to read the payload out of the event.
	if !strings.Contains(line, "_user=admin") {
		t.Fatalf("the injected value was scrubbed out of the stored body: %s", line)
	}
	if strings.Contains(line, "Summer2026") {
		t.Fatalf("the password was stored in the event: %s", line)
	}
	// No authentication decision was made for this request, which is the
	// "pre-auth" half of the class name.
	if !strings.Contains(line, `"auth_outcome":"unknown"`) {
		t.Fatalf("expected no authentication decision for this request: %s", line)
	}
}
