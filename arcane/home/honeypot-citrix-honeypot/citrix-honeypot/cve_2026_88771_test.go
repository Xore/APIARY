package main

// Tests for #3467 (CVE-2026-88771 / CVE-2026-88772, Citrix NetScaler
// ADC/Gateway zero-day RCE pair, KEV 2026-09-27).
//
// The house rule this file exists to satisfy, from #2977's own write-up:
// a classifier with only a positive test is half a classifier. Every test
// name below therefore says which side it is on -- CAN fire, or does NOT
// fire on benign traffic -- and the benign corpus is drawn from traffic
// this decoy actually serves, not from strings chosen to be obviously
// clean.

import (
	"bytes"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestInferredCmdMetacharShapeCANFire proves the classifier fires on the
// shapes it claims to. INFERRED pattern -- see cve_2026_88771.go's header:
// the primitive ("execute arbitrary commands") is documented in CTX697096,
// the location of the unvalidated input is not.
func TestInferredCmdMetacharShapeCANFire(t *testing.T) {
	cases := []struct {
		name              string
		path, query, body string
	}{
		{"backtick in path", "/vpn/`id`", "", ""},
		{"command substitution in path", "/vpn/$(id)", "", ""},
		{"brace expansion in path", "/vpn/${IFS}", "", ""},
		{"two distinct low tokens, semicolon and pipe", "/vpn/x;id|cat", "", ""},
		{"two distinct low tokens, ampersand and redirect", "/vpn/a&b>c", "", ""},
		{"semicolon and redirect", "/vpn/;id>/tmp/p", "", ""},
		{"newline in body", "/vpn/", "", "title=x\nrm -rf /"},
		{"backtick in body", "/vpn/", "", "title=`id`"},
		{"command substitution in body", "/vpn/", "", "title=$(whoami)"},
		{"backtick in query", "/vpn/", "cmd=`id`", ""},
		{"two distinct low tokens in query", "/vpn/", "a=1;b|c", ""},
	}
	for _, c := range cases {
		if got := cmdShapeEvent(c.path, c.query, c.body); got != netscalerCmdMetacharEvent {
			t.Errorf("%s: cmdShapeEvent(%q, %q, %q) = %q, want %q",
				c.name, c.path, c.query, c.body, got, netscalerCmdMetacharEvent)
		}
	}
}

// TestInferredCmdMetacharShapeDoesNotFireOnBenignTraffic is the other
// half. Every case here is traffic this decoy really serves, and every
// one of them must classify as nothing.
func TestInferredCmdMetacharShapeDoesNotFireOnBenignTraffic(t *testing.T) {
	cases := []struct {
		name              string
		path, query, body string
		why               string
	}{
		{"root", "/", "", "", "the login page"},
		{"vpn", "/vpn", "", "", "the login page"},
		{"plain path", "/some/random/path", "", "", "the default empty 200"},
		{"language query", "/vpn/index.html", "lang=en-US", "", "ordinary query"},
		{"matrix parameter", "/store;jsessionid=ABC123", "", "",
			"Jetty/Tomcat session parameter -- the canonical benign ';'"},
		{"single semicolon", "/vpn/;id", "", "",
			"documented limitation: indistinguishable from the matrix-parameter form by shape alone"},
		{"query separators", "/vpn/", "a=1&b=2&c=3", "",
			"'&' is the query separator on essentially every real request"},
		{"sloppy encoder double ampersand", "/vpn/", "a=1&&b=2", "",
			"empty-parameter artifact; must stay ONE token, not '&' plus '&&'"},
		{"sloppy encoder double pipe", "/vpn/", "a=1||b=2", "",
			"same class of artifact"},
		{"repeated single ampersand", "/vpn/", "a=1&b=2&c=3&d=4", "",
			"four '&' are still one distinct token"},
		{"single pipe", "/vpn/", "filter=a|b", "", "templating/filter syntax"},
		{"saml wctx base64", "/wsfed/passive", "wctx=PHNhbWxwOkV4cHRpb24vPjwvc3RhbGxhYmxlLz4=", "",
			"#2977's own CVE-2026-3055 M1 shape: base64 has no token characters"},
		{"saml authnrequest base64", "/saml/login", "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdD48L1NhbWxwPg==", "",
			"same, on the AAA surface"},
		{"jwt bearer", "/oauth/idp/.well-known/openid-configuration",
			"access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.9z3Jrbm93bg", "",
			"JWT is base64url plus dots; none are tokens"},
		{"base64 with padding", "/vpn/", "RelayState=aGVsbG8gd29ybGQhPT0=", "", "base64 padding"},
		{"encoded semicolon in query", "/vpn/", "a=1%3Bb=2", "",
			"percent-encoded ';' resolves to ';' -- one token, still suppressed"},
		{"the 2019 traversal path", "/vpn/../vpns/portal/scripts/newbm.pl", "", "",
			"this decoy's own CVE-2019-19781 path, no metacharacters in it"},
		{"newbm payload field", "/vpns/portal/scripts/newbm.pl", "", "title=id",
			"the existing newbm.pl capture path, benign value"},
		{"login form post", "/vpn/login", "", "username=alice&password=hunter2",
			"an ordinary credential POST -- '&' appears twice and stays suppressed"},
	}
	for _, c := range cases {
		if got := cmdShapeEvent(c.path, c.query, c.body); got != "" {
			t.Errorf("%s (%s): cmdShapeEvent(%q, %q, %q) = %q, want no classification",
				c.name, c.why, c.path, c.query, c.body, got)
		}
	}
}

// TestInferredCmdMetacharShapeIsLoggedThroughTheExistingPath is the
// end-to-end proof: a classified request reaches the event stream through
// the same log2 the rest of the sensor uses, alongside the unconditional
// get, and a benign request through the same handler emits no such event.
func TestInferredCmdMetacharShapeIsLoggedThroughTheExistingPath(t *testing.T) {
	capture := func(run func()) string {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		orig := os.Stdout
		os.Stdout = w
		run()
		os.Stdout = orig
		w.Close()
		var buf bytes.Buffer
		io.Copy(&buf, r)
		return buf.String()
	}

	h := newTestHandler()

	// Fires: backtick in the path.
	metachar := capture(func() {
		req := httptest.NewRequest("GET", "/vpn/`id`", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	})
	if !strings.Contains(metachar, `"event":"`+netscalerCmdMetacharEvent+`"`) {
		t.Errorf("expected the classified event for a metacharacter path, got %q", metachar)
	}
	if !strings.Contains(metachar, `"event":"get"`) {
		t.Errorf("the unconditional get event must still be emitted, got %q", metachar)
	}

	// Does not fire: ordinary query string.
	benign := capture(func() {
		req := httptest.NewRequest("GET", "/vpn/index.html?lang=en-US&theme=dark", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	})
	if strings.Contains(benign, netscalerCmdMetacharEvent) {
		t.Errorf("benign query must not classify, got %q", benign)
	}
	if !strings.Contains(benign, `"event":"get"`) {
		t.Errorf("the unconditional get event must still be emitted, got %q", benign)
	}
}

// TestInferredCmdMetacharShapeFiresOnAnAuthSurfacePath pins the ordering
// in serveGET. authSurfaceResponse returns early for the AAA/SAML paths,
// so a classifier placed after that block would silently never run on
// them -- a metacharacter probe dressed up as an auth request would go
// unclassified. This is the regression test for that placement.
func TestInferredCmdMetacharShapeFiresOnAnAuthSurfacePath(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	req := httptest.NewRequest("GET", "/saml/login?RelayState=`id`", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	out := buf.String()
	if !strings.Contains(out, `"event":"`+netscalerCmdMetacharEvent+`"`) {
		t.Fatalf("a metacharacter on an auth-surface path must still classify, got %q", out)
	}
	if !strings.Contains(out, `"event":"netscaler_saml_surface_probe"`) {
		t.Fatalf("the existing auth-surface classification must be unaffected, got %q", out)
	}
}

// TestInferredCmdMetacharShapeReadsThePOSTBody covers the third surface.
// An unvalidated-input primitive is at least as likely to arrive in a
// form field as in the request target, and the existing newbm.pl capture
// proves POST bodies reach this handler.
func TestInferredCmdMetacharShapeReadsThePOSTBody(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	req := httptest.NewRequest("POST", "/vpn/login", strings.NewReader("title=$(whoami)"))
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	out := buf.String()
	if !strings.Contains(out, `"event":"`+netscalerCmdMetacharEvent+`"`) {
		t.Fatalf("expected the classified event from the POST body, got %q", out)
	}
	if !strings.Contains(out, "title=$(whoami)") {
		t.Fatalf("expected the body captured on the classified event, got %q", out)
	}
}

// TestQueryForShapeDecodesPercentEscapes is why queryForShape exists.
// r.URL.RawQuery is the raw wire form, so an encoded payload would never
// reach the high-conviction tier without this; r.URL.Path does not have
// the problem because net/http decodes it before the handler runs.
func TestQueryForShapeDecodesPercentEscapes(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"/vpn/?cmd=%60id%60", "cmd=`id`"},
		{"/vpn/?cmd=%24%28id%29", "cmd=$(id)"},
		{"/vpn/?a=1&b=2", "a=1&b=2"},
		// Malformed escape: lenient by design, the raw value must survive
		// so a scanner probing decoders still reaches the classifier.
		{"/vpn/?a=%zz", "a=%zz"},
		{"/vpn/?a=100%", "a=100%"},
	}
	for _, c := range cases {
		got := queryForShape(httptest.NewRequest("GET", c.target, nil))
		if got != c.want {
			t.Errorf("queryForShape(%q) = %q, want %q", c.target, got, c.want)
		}
	}
}

// TestShellShapeTokenScanIsNonOverlapping pins the fix for the design bug
// the first draft had: with per-token strings.Contains, "a=1&&b=2" matched
// both "&" and "&&" and counted as two distinct low-conviction tokens, so
// the classifier fired on the very sloppy-encoder artifact the low tier
// exists to tolerate. Left-to-right consumption must make "&&" one token.
func TestShellShapeTokenScanIsNonOverlapping(t *testing.T) {
	cases := []struct {
		s    string
		want bool
		why  string
	}{
		{"a=1&b=2", false, "one '&'"},
		{"a=1&&b=2", false, "'&&' consumed whole, not also '&'"},
		{"a=1||b=2", false, "'||' consumed whole, not also '|'"},
		{"a=1&b=2&c=3", false, "three '&', still one distinct token"},
		{"a=1&&b=2&&c=3", false, "three '&&', still one distinct token"},
		{"a=1;b", false, "one ';'"},
		{"a=1;b|c", true, "two distinct low tokens"},
		{"`id`", true, "high-conviction backtick"},
		{"$(id)", true, "high-conviction command substitution"},
		{"${IFS}", true, "high-conviction brace expansion"},
		{"$(id)", true, "'$(' consumed whole"},
		{"x\ny", true, "high-conviction newline"},
		{"x\ry", true, "high-conviction carriage return"},
		{"a=1;>b", true, "';' and '>' are two distinct tokens"},
	}
	for _, c := range cases {
		if got := hasShellShape(c.s); got != c.want {
			t.Errorf("hasShellShape(%q) = %v, want %v (%s)", c.s, got, c.want, c.why)
		}
	}
}

// TestKEVCoverageEmitsVerifiedBulletinMetadata checks the metadata-driven
// half of this change actually carries the primary-source values, and
// that both CVEs of the pair are present.
func TestKEVCoverageEmitsVerifiedBulletinMetadata(t *testing.T) {
	if len(netscalerKEV2026) != 2 {
		t.Fatalf("expected exactly the 88771/88772 pair, got %d entries", len(netscalerKEV2026))
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	emitKEVCoverage(newLogger(""), 443)
	os.Stdout = orig
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	out := buf.String()

	for _, want := range []string{
		`"event":"netscaler_kev_exposure"`,
		`"path":"CVE-2026-88771"`,
		`"path":"CVE-2026-88772"`,
		"kev_added=2026-09-27",
		"kev_due=2026-09-30",
		"9.5",
		"cwe=CWE-20",
		"cwe=CWE-119",
		"AT:P", // 88771 is AC:L/AT:P
		"AC:H", // 88772 is AC:H
		"14.1-73.37",
		"13.1-64.23",
		"13.1-37.279",
		"DTLS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the emitted KEV coverage, got %q", want, out)
		}
	}
}

// TestKEVCoverageRecordsTheDTLSGapFor88772 is the honest-negative half of
// the KEV half. CVE-2026-88772's precondition is DTLS, and this decoy
// terminates no DTLS handshake, so the gap has to be recorded as queryable
// data rather than left as a comment. If this test ever starts failing
// because a UDP/DTLS listener was added, that is the moment the classifier
// work for 88772 becomes possible.
func TestKEVCoverageRecordsTheDTLSGapFor88772(t *testing.T) {
	var dtls netscalerKEVEntry
	for _, e := range netscalerKEV2026 {
		if e.CVE == "CVE-2026-88772" {
			dtls = e
		}
	}
	if dtls.CVE == "" {
		t.Fatal("CVE-2026-88772 missing from the KEV coverage set")
	}
	if dtls.decoyExercisesPrecondition {
		t.Error("CVE-2026-88772 claims the decoy exercises its DTLS precondition; " +
			"this sensor is TCP-only, so that claim would be false")
	}
	summary := dtls.summary()
	for _, want := range []string{
		"decoy_exercises_precondition=no",
		"precondition_gap=",
		"DTLS is a UDP transport",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("expected %q in the 88772 summary, got %q", want, summary)
		}
	}
}

// TestKEVCoverageMetadataClaimsNoPayloadSignature is an anti-fabrication
// guard, and the most important test in this file.
//
// Everything netscaler_kev_exposure asserts is transcribed from CTX697096
// and the CISA KEV catalog. As of this change neither source publishes a
// request path, payload byte sequence or wire-level indicator for either
// CVE, so a future edit that bolts an invented "signature" onto this
// metadata would be shipping a fabricated IoC into a honeypot -- the one
// failure mode this whole change is written to avoid. If a real primary
// source ever supplies one, this test is the thing to delete deliberately,
// in the same commit that cites the source.
func TestKEVCoverageMetadataClaimsNoPayloadSignature(t *testing.T) {
	banned := []string{
		"signature", "payload", "poc", "exploit_string", "magic",
		"detect these bytes", "known exploit",
	}
	for _, e := range netscalerKEV2026 {
		summary := e.summary()
		lower := strings.ToLower(summary)
		for _, b := range banned {
			if strings.Contains(lower, b) {
				t.Errorf("%s metadata contains %q -- the KEV entry and CTX697096 "+
					"publish no request shape or payload bytes, so any such claim is "+
					"fabricated: %q", e.CVE, b, summary)
			}
		}
	}
}

// TestKEVCoverageEventNamesTheInferenceWhereItBelongs is the other
// anti-fabrication guard. The event kind for the command-metacharacter
// classifier must keep carrying "inferred" in its name; a future tidy-up
// that renames it to something CVE-flavoured is exactly the drift this
// change is guarding against.
func TestKEVCoverageEventNamesTheInferenceWhereItBelongs(t *testing.T) {
	if !strings.Contains(netscalerCmdMetacharEvent, "inferred") {
		t.Errorf("event kind %q must keep 'inferred' in its name -- the pattern is "+
			"an inference from CVE-2026-88771's documented primitive, not a confirmed "+
			"indicator", netscalerCmdMetacharEvent)
	}
	if strings.Contains(netscalerCmdMetacharEvent, "2026_88771") ||
		strings.Contains(netscalerCmdMetacharEvent, "2026-88771") {
		t.Errorf("event kind %q must not name the CVE: no request shape for it is "+
			"published, and a CVE-named event reads as confirmed coverage", netscalerCmdMetacharEvent)
	}
}
