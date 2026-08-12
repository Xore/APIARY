package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// investigateTestMux builds a fresh, real http.ServeMux with only
// registerInvestigateRoutes' patterns on it -- Go's ServeMux only
// populates r.PathValue() for a request actually routed through
// ServeHTTP, so calling a handler function directly (this codebase's
// usual handler-test convention) can't exercise the double-decode fix at
// all. Every test below dispatches through this mux, not a bare handler
// call.
func investigateTestMux(t *testing.T, s *store) *http.ServeMux {
	t.Helper()
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := http.NewServeMux()
	s.registerInvestigateRoutes(mux, tmpl)
	return mux
}

func doGet(mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestInvestigateRoutesCoexistWithTheirLiteralSiblings (#1312 regression
// guard): net/http.ServeMux.HandleFunc PANICS at registration time --  not
// something go build/go vet/go test alone ever exercises -- when two
// patterns overlap without one being a strict subset of the other. This
// bit real production code: main.go registers five method-unrestricted
// literal siblings under the same prefixes registerInvestigateRoutes'
// GET-only wildcards now own (/investigate/ip/block, /sandbox/submit,
// /sandbox/vnc, /ghidra/submit, /github-analysis/submit). A bare
// "/sandbox/vnc" (every method) is NOT a subset of "GET /sandbox/{job}"
// (GET only) -- it additionally matches every other method for that one
// path, which the wildcard doesn't cover -- so the two conflict and
// ServeMux panics the instant both are registered on the same mux. This
// was invisible to every other test here (each builds its own mux with
// only registerInvestigateRoutes' own patterns on it, never these five
// siblings) and only surfaced when the real dashboard binary actually
// started in CI. Confirmed live: this test panicked before main.go's
// siblings were given matching method prefixes (POST for the block/
// submit actions, GET for the VNC page).
func TestInvestigateRoutesCoexistWithTheirLiteralSiblings(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := http.NewServeMux()
	s.registerInvestigateRoutes(mux, tmpl)

	siblings := []string{
		"POST /investigate/ip/block",
		"POST /sandbox/submit",
		"GET /sandbox/vnc",
		"POST /ghidra/submit",
		"POST /github-analysis/submit",
	}
	for _, pattern := range siblings {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {})
	}
}

// TestClusterDrillDownRoundTripsSpacesInKindAndValue (#1312, confirmed
// bug): "Autonomous system" and "Provider class" -- and any cluster value
// containing a literal space -- used to 404 because the drill-down link
// was built with query-style escaping (the template's urlquery func,
// "+" for space) but decoded with url.PathUnescape (path-style, which
// never turns "+" back into a space). kind/value are now separate query
// parameters, which use exactly one escaping convention end to end.
func TestClusterDrillDownRoundTripsSpacesInKindAndValue(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.10", ASN: 64500, Org: "Example Networks"},
		{SrcIP: "203.0.113.11", ASN: 64500, Org: "Example Networks"},
	}}
	es := httptest.NewServer(correlationSearchStub(t, new(string), `{"hits":{"total":{"value":0},"hits":[]}}`))
	defer es.Close()
	s.es = newESClient(es.URL, "")

	mux := investigateTestMux(t, s)
	// Encoded exactly the way ui/intel.html's {{.Kind | urlquery}}/
	// {{.Value | urlquery}} would produce it -- a literal space becomes "+".
	rec := doGet(mux, "/investigate/cluster?kind=Autonomous+system&value=AS64500+Example+Networks")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Autonomous system") {
		t.Fatalf("kind was not correctly decoded with its space intact: %s", body)
	}
	if !strings.Contains(body, "AS64500 Example Networks") {
		t.Fatalf("value was not correctly decoded with its spaces intact: %s", body)
	}
}

// TestClusterDrillDownReturns404ForAnUnknownCluster checks the not-found
// path still behaves sanely with no ES involved: a kind/value pair
// matching fewer than 2 IPs is "not a cluster", the same threshold
// clustersData itself uses.
func TestClusterDrillDownReturns404ForAnUnknownCluster(t *testing.T) {
	s := &store{}
	mux := investigateTestMux(t, s)
	rec := doGet(mux, "/investigate/cluster?kind=Fingerprint&value=nope")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestSessionPathValueIsDecodedExactlyOnce (#1312): a session ID
// containing a literal percent sign, correctly wire-encoded as a single
// %25, used to 404 unconditionally under the old code -- url.PathUnescape
// was called a SECOND time on r.URL.Path (which net/http already decodes
// once), and re-decoding "sess-100%" (the correct, once-decoded value)
// fails outright (a trailing "%" is not a valid escape sequence), taking
// the err != nil branch regardless of whether a matching session exists.
func TestSessionPathValueIsDecodedExactlyOnce(t *testing.T) {
	s := &store{events: []storedEvent{
		{Session: "sess-100%", SrcIP: "203.0.113.5", Sensor: "cowrie", Time: "2026-08-12 00:00"},
	}}
	mux := investigateTestMux(t, s)

	rec := doGet(mux, "/sessions/sess-100%25")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 -- a single-encoded literal %% must survive as part of the session id (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestSessionDoubleEncodedPercentIsNotSilentlyUnwrapped (#1312): the
// issue's own example of "ambiguous behavior" -- %252F becoming a literal
// "/". net/http's single decode turns the wire's "%252F" into the three
// literal characters "%2F" in r.URL.Path. The double-decoding bug would
// unescape that a SECOND time into an actual "/", silently changing which
// session the request resolves to. This proves no second decode happens:
// a session ID containing the literal substring "%2F" is looked up as
// exactly that, not as if it contained a slash.
func TestSessionDoubleEncodedPercentIsNotSilentlyUnwrapped(t *testing.T) {
	s := &store{events: []storedEvent{
		{Session: "sess-100%2F", SrcIP: "203.0.113.5", Sensor: "cowrie", Time: "2026-08-12 00:00"},
	}}
	mux := investigateTestMux(t, s)

	rec := doGet(mux, "/sessions/sess-100%252F")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 -- %%252F must decode to the literal substring %%2F exactly once, not be silently re-decoded into a slash (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestSessionExtraPathSegmentDoesNotMatch (#1312 acceptance criteria:
// "extra segments"): Go 1.22's {id} wildcard matches exactly one path
// segment -- a request with an unexpected extra segment after the id must
// not match this route at all (a clean 404 from the mux itself, not a
// handler silently accepting a mangled/partial id).
func TestSessionExtraPathSegmentDoesNotMatch(t *testing.T) {
	s := &store{events: []storedEvent{
		{Session: "sess-a", SrcIP: "203.0.113.5", Sensor: "cowrie", Time: "2026-08-12 00:00"},
	}}
	mux := investigateTestMux(t, s)

	rec := doGet(mux, "/sessions/sess-a/extra")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a path with an unexpected extra segment", rec.Code)
	}
}

// TestSessionUnsupportedMethodReturns405 (#1312 acceptance criteria:
// "unsupported methods return 405 with an appropriate Allow header"):
// registerInvestigateRoutes registers these as GET-only patterns.
func TestSessionUnsupportedMethodReturns405(t *testing.T) {
	s := &store{events: []storedEvent{
		{Session: "sess-a", SrcIP: "203.0.113.5", Sensor: "cowrie", Time: "2026-08-12 00:00"},
	}}
	mux := investigateTestMux(t, s)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sessions/sess-a", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if rec.Header().Get("Allow") == "" {
		t.Fatal("405 response must carry an Allow header")
	}
}

// TestHashKeyedRoutesRejectInvalidHashesAfterSingleDecode (#1312): every
// hash-keyed route still validates against hashName after extraction --
// these must reject non-hex input the same as before, now via
// r.PathValue() instead of a manually re-decoded path segment.
func TestHashKeyedRoutesRejectInvalidHashesAfterSingleDecode(t *testing.T) {
	s := &store{}
	mux := investigateTestMux(t, s)
	for _, path := range []string{"/ghidra/not-a-hash", "/revdeck/not-a-hash", "/cape/not-a-hash", "/github-analysis/not-a-hash"} {
		rec := doGet(mux, path)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404 for an invalid hash", path, rec.Code)
		}
	}
}

// TestCIDRWildcardCapturesTheEmbeddedSlash (#1312): CIDR notation always
// contains a literal "/" ("203.0.113.0/24"), which Go 1.22's plain {name}
// wildcard cannot span -- /investigate/cidr/{cidr...} uses the "rest of
// path" form specifically so a %2F-encoded slash (decoded exactly once by
// net/http into a real "/") is captured whole, not truncated at the first
// segment boundary.
func TestCIDRWildcardCapturesTheEmbeddedSlash(t *testing.T) {
	s := &store{}
	es := httptest.NewServer(correlationSearchStub(t, new(string), `{"hits":{"total":{"value":0},"hits":[]}}`))
	defer es.Close()
	s.es = newESClient(es.URL, "")

	mux := investigateTestMux(t, s)
	rec := doGet(mux, "/investigate/cidr/203.0.113.0%2F24")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 -- a %%2F-encoded slash must survive as part of the CIDR (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "203.0.113.0/24") {
		t.Fatalf("CIDR was not correctly captured with its slash intact: %s", rec.Body.String())
	}
}

// TestInvestigateIPRejectsUnsupportedMethod mirrors
// TestSessionUnsupportedMethodReturns405 for a second route, confirming
// the GET-only restriction isn't specific to one handler.
func TestInvestigateIPRejectsUnsupportedMethod(t *testing.T) {
	s := &store{}
	mux := investigateTestMux(t, s)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/investigate/ip/203.0.113.5", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
