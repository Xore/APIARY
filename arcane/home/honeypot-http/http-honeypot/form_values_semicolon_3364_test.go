package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The semicolon root cause, and the four sites that carried it.
//
// #3364's research asked what the fleet can see of CVE-2026-48842, and this
// file is the answer to the part of that question which was still open when the
// answer was written: whether the class sees the payload when the attacker
// puts a `;` in it.
//
// Four cases parse their parameters with url.ParseQuery behind this guard:
//
//	if err != nil && len(values) == 0 { continue }
//
// Since Go 1.17 url.ParseQuery rejects every pair containing a semicolon and
// drops it, and returns a non-nil map of the pairs that had none. So the guard
// does not fire -- there are values left -- and the case keeps reading the
// truncated map, in which the attacker's own pair is simply absent. The one
// thing the guard was written to tolerate, a body that is not a parameter list
// at all, is what makes the miss invisible: there is no error to notice.
//
// That matters because the targets are PHP applications, and PHP's only query
// separator is "&". A `;` in the value is ordinary data that arrives at the
// target intact, while the sensor drops the parameter that carried it. The
// bytes the target will parse are not the bytes this sensor parsed, and the
// CVE works by making the target decode a value: so the classification has to
// be done on the bytes the target will see. classify_wordpress.go's formValues
// is that parser, added by #3449 for the same reason in both WordPress cases;
// this file is the proof the other three sites needed and did not have.
//
// Two shapes hide a payload, and both are ordinary to send:
//
//   - a literal `;` inside a value. It is a sub-delim, legal in a query
//     unencoded, and it costs the attacker nothing.
//   - a deliberately broken escape earlier in the same value
//     (`%zzadmin' or 1=1--`), which makes the whole side undecodable. A
//     parser that discards an undecodable value has just been handed a way to
//     delete its own evidence; the target keeps the raw bytes.
//
// Every positive below fails on main and is asserted through the real
// entry point (classifyPayload, or the laundering state), not through a copy of
// the logic. The negatives are the other half: the same semicolon and the same
// broken escape, with no payload behind them, must stay unlabelled -- a
// parser that sees more is only useful if it still requires the payload.

// TestSemicolonAndBrokenEscapeDoNotHideAPayload is the table, per class, and
// the whole argument in one place.
func TestSemicolonAndBrokenEscapeDoNotHideAPayload(t *testing.T) {
	cases := []struct {
		name, query, body, want string
	}{
		// --- #3364, roundcube-virtuser-query-sqli. The CVE's root cause
		// is a `preg_replace()` escape defeated from inside the value, so
		// the payload is a backslash-quote plus SQL on one of Roundcube's
		// own dispatch parameters. The `;` goes inside the injected value:
		// the target's parser keeps it, and a pair-wise parser that
		// rejects semicolons cannot see the parameter at all.
		{
			name: "roundcube: semicolon inside the injected value, form body",
			body: "_task=login&_action=login&_timezone=Europe%2FBerlin&_user=admin%5C%27;or+1%3D1--&_pass=Summer2026",
			want: "roundcube-virtuser-query-sqli",
		},
		{
			// The same request as a query string, which is the GET half.
			// A pre-auth SQLi is not a POST-only event.
			name:  "roundcube: semicolon inside the injected value, query string",
			query: "_task=login&_action=login&_user=admin%5C%27;or+1%3D1--",
			want:  "roundcube-virtuser-query-sqli",
		},
		{
			// The broken-escape half. The value as a whole will not
			// decode, so a parser that drops undecodable values drops
			// the payload with them -- while `or 1=1--` sits in it in
			// cleartext, which is what the target reads.
			name: "roundcube: broken escape ahead of a cleartext payload",
			body: "_task=login&_action=login&_user=%zzadmin' or 1=1--",
			want: "roundcube-virtuser-query-sqli",
		},
		{
			// Not the CVE's root cause, but the same class and the same
			// transport: no backslash at all, quote closed and the rest
			// appended. A deployment that does not escape the value is
			// still pre-auth SQLi against the same plugin.
			name: "roundcube: unescaped quote, semicolon in the value",
			body: "_task=login&_action=login&_user=admin';or+1%3D1--",
			want: "roundcube-virtuser-query-sqli",
		},

		// --- #3430, odata-double-encode-probe. The gate is a real OData
		// system option whose key or value still holds a %XX escape after
		// one decode, so the `;` rides on the option's own pair.
		{
			name:  "odata: semicolon on the option's own pair",
			query: `$filter=Year%2520eq%25202026;$top=10`,
			want:  "odata-double-encode-probe",
		},
		{
			name:  "odata: semicolon on an aliased option's own pair",
			query: `northwind.$select=Year%252cValue;$top=1`,
			want:  "odata-double-encode-probe",
		},
		{
			name: "odata: semicolon on the option pair in a form body",
			body: `$top=10&$filter=Year%2520eq%25202026;$format=json`,
			want: "odata-double-encode-probe",
		},

		// --- negatives. Each is the same transport trick with no payload
		// behind it, and each is traffic the fleet sees: a semicolon in a
		// value is a `Content-Type` parameter, a matrix parameter and a
		// very common typo. Requiring the payload is what keeps the wider
		// parser from being a wider false-positive machine.
		{
			name: "roundcube login, semicolon in a value, nothing injected",
			body: "_task=login&_action=login&_user=alice.smith%40example.com;x=1&_pass=Summer2026",
			want: "",
		},
		{
			name: "roundcube login, broken escape, nothing injected",
			body: "_task=login&_action=login&_user=%zzalice.smith%40example.com",
			want: "",
		},
		{
			// A semicolon in front of a dispatch parameter is not a
			// dispatch parameter. The target's parser does not strip it
			// either, so the pair is not the parameter it looks like --
			// and the gate must not open on the resemblance.
			name:  "semicolon-prefixed roundcube key is not a dispatch parameter",
			query: ";_action=login&_user=admin%5C%27+or+1%3D1--",
			want:  "",
		},
		{
			// The other half of that: the payload is visible and the gate
			// is not open, so it stays somebody else's class or nobody's.
			// This is the #3364 boundary the class's own table pins, and a
			// semicolon must not quietly become a way around it.
			name:  "payload behind a semicolon with no roundcube shape",
			query: ";_user=admin%5C%27+or+1%3D1--",
			want:  "",
		},
		{
			name:  "odata option with a semicolon but no residual escape",
			query: `$filter=Year%20eq%202026;$top=10`,
			want:  "",
		},
		{
			name:  "semicolon-prefixed odata key is not a system option",
			query: `;$filter=Year%2520eq%25202026`,
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

// TestTeamcityCallNameSurvivesTheParserSwap is the honest result for
// teamcity-agent-deserialization, and it is not a positive.
//
// The class asks whether a parameter value is a whole, named TeamCity call
// (`teamcityAgentCall`, an equality test against a fixed list). A `;` inside
// the value breaks the equality, and a `;` in front of the key breaks the
// key, so there is no semicolon payload this class can be shown to gain: for
// this site the parser swap is consistency, not detection.
//
// It is pinned anyway, in both directions, because "gains nothing" is only
// worth believing while the case still works and still refuses the shape that
// looks like it. If a future widening of the call-name test made a semicolon
// meaningful here, this table is where that has to show up.
func TestTeamcityCallNameSurvivesTheParserSwap(t *testing.T) {
	const want = "teamcity-agent-deserialization"
	// Both halves a real probe carries: a serialization container, and the
	// agent protocol. The container is a gadget class name, so every row
	// below is parsed rather than refused for want of the second half --
	// an unclaimed call name has to be unclaimed because the value is not
	// one, not because the request was missing something else.
	const container = "com.ysoserial"
	cases := []struct {
		name, query, body, want string
	}{
		{
			name:  "the plain form still claims it",
			query: "methodName=xmlrpc/allowRegistration&x=" + container,
			want:  want,
		},
		{
			// A wider parser cannot rescue this one either, and the
			// reason is the target's: the value at the far end is
			// `xmlrpc/allowRegistration;x=1` whichever parser read it,
			// and that is not a call name. Refusing it is the correct
			// answer, not a gap.
			name:  "semicolon inside the value is not that call name",
			query: "methodName=xmlrpc/allowRegistration;x=1&y=" + container,
			want:  "",
		},
		{
			name:  "semicolon-prefixed key is not the method parameter",
			query: ";methodName=xmlrpc/allowRegistration&x=" + container,
			want:  "",
		},
		{
			name:  "broken escape makes the value something else",
			query: "methodName=%zzxmlrpc/allowRegistration&x=" + container,
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

// TestQualifyingODataRequestReadsSemicolonSeparatedPairs is the fourth site,
// which is not a dispatch class: #3447's layer C asks whether a request is a
// well-formed OData system query, and uses that as one half of a pair.
//
// The `;` is on the option's own pair, so the value the consistency gate sees
// carries a trailing `;$top=1` that a pair-wise parser would have thrown away
// with the option. The gate still has to do its job on what it is shown, which
// is what the negatives below check.
func TestQualifyingODataRequestReadsSemicolonSeparatedPairs(t *testing.T) {
	const path = "/odata/Products"
	yes := []string{
		`$filter=Year%20eq%202026;$top=1`,
		`$filter=Year%20eq%20'Widget';$skip=10`,
		`northwind.$filter=Year%20eq%202026;$top=1`,
		`$filter=startswith(Name,'a.b.c');$top=1`,
	}
	for _, q := range yes {
		if !qualifyingODataRequest(path, q, "") {
			t.Errorf("qualifyingODataRequest(%q, %q) = false, want true", path, q)
		}
	}
	no := []string{
		// The value-consistency gate, still enforced on the value it is
		// shown. `$top` wants a bounded integer and gets a fragment.
		`$top=10;$filter=Year%20eq%202026`,
		`$format=yaml;$top=1`,
		// The same gate on an identifier list: the fragment is not an
		// identifier, so `$select` does not get to count a semicolon as
		// part of the field name. A wider parser must not widen this.
		`$select=Year,Value;$format=json`,
		// A semicolon in front of the option is not an option.
		`;$filter=Year%20eq%202026`,
		`;$top=10`,
	}
	for _, q := range no {
		if qualifyingODataRequest(path, q, "") {
			t.Errorf("qualifyingODataRequest(%q, %q) = true, want false", path, q)
		}
	}
}

// TestLayerCSeesTheODataHalfThroughASemicolon is that half reaching the class
// it exists for, through the real two-request path. The first request is
// unlabelled whatever happens -- the pair is what fires -- so this asserts the
// seed as well as the completion: if the semicolon hides the option, the entry
// is never created and the bypass that follows is unlabelled forever.
func TestLayerCSeesTheODataHalfThroughASemicolon(t *testing.T) {
	const fp = "scanner-fingerprint"
	d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)

	if got := d.observe(fp, "/odata/Products", `$filter=Year%20eq%202026;$top=1`, ""); got != "" {
		t.Fatalf("the OData probe alone was labelled %q; the pair is what fires", got)
	}
	if got := d.observe(fp, "/odata/%2561", "", ""); got != launderingClass {
		t.Errorf("observe(path-borne bypass after a semicolon-separated option) = %q, want %q", got, launderingClass)
	}
}

// TestRoundcubeSemicolonPayloadReachesTheEvent is the half a table of
// classifyPayload results cannot cover: that the class lands on the emitted
// event, with the injected value still readable in it.
//
// Reuse of a wider parser must not cost the fleet the payload bytes. #3213's
// rule is that redaction may not remove a signature, and the form redaction
// pass runs over this body because it is a form -- so the value beside
// `_pass` has to survive into the stored event or the analyst has a class with
// no evidence in it.
func TestRoundcubeSemicolonPayloadReachesTheEvent(t *testing.T) {
	s, output := newTestServer()

	const body = "_task=login&_action=login&_timezone=Europe%2FBerlin&_user=admin%5C%27;or+1%3D1--&_pass=Summer2026"

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
	if !strings.Contains(line, "_user=admin%5C%27;or+1%3D1--") {
		t.Fatalf("the injected value was scrubbed out of the stored body: %s", line)
	}
	if strings.Contains(line, "Summer2026") {
		t.Fatalf("the password was stored in the event: %s", line)
	}
	// Still the pre-auth shape: nothing in serve() decided an identity.
	if !strings.Contains(line, `"auth_outcome":"unknown"`) {
		t.Fatalf("expected no authentication decision for this request: %s", line)
	}
}
