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
// #1327/#1328 shell+hydrate moved the actual sessionData() lookup (and so
// this decode) to the fragment route -- the shell route below always 200s
// on any non-empty id, so the decode-fidelity assertion now has to be made
// against /sessions/{id}/fragment, the same way TestGhidraFragmentRoute
// checks ghidra's fragment rather than its shell.
func TestSessionPathValueIsDecodedExactlyOnce(t *testing.T) {
	s := &store{events: []storedEvent{
		{Session: "sess-100%", SrcIP: "203.0.113.5", Sensor: "cowrie", Time: "2026-08-12 00:00"},
	}}
	mux := investigateTestMux(t, s)

	rec := doGet(mux, "/sessions/sess-100%25/fragment")
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
// exactly that, not as if it contained a slash. See the fragment-route
// note on TestSessionPathValueIsDecodedExactlyOnce above.
func TestSessionDoubleEncodedPercentIsNotSilentlyUnwrapped(t *testing.T) {
	s := &store{events: []storedEvent{
		{Session: "sess-100%2F", SrcIP: "203.0.113.5", Sensor: "cowrie", Time: "2026-08-12 00:00"},
	}}
	mux := investigateTestMux(t, s)

	rec := doGet(mux, "/sessions/sess-100%252F/fragment")
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

// TestSessionShellRendersWithoutEventScan covers #1327/#1328's
// shell+hydrate conversion: /sessions/{id} must render a 200 shell for any
// non-empty id with no events in the store at all -- the old behavior
// synchronously scanned every cached event and 404'd here for an unknown
// id; that check now happens only on the client's own follow-up fetch to
// the fragment route below. The shell must carry the fragment URL for
// hp-session-detail.js to hydrate from and must not leak any content that
// would only be true for a real session.
func TestSessionShellRendersWithoutEventScan(t *testing.T) {
	s := &store{}
	mux := investigateTestMux(t, s)
	rec := doGet(mux, "/sessions/sess-unknown")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a shell render (it fetches events client-side)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-hp-session-fragment-url="/sessions/sess-unknown/fragment"`) {
		t.Errorf("shell is missing the fragment URL hp-session-detail.js hydrates from, got: %s", body)
	}
	if strings.Contains(body, "session-body") {
		t.Error("shell must not render the body template's own define name as literal text")
	}
}

// TestSessionFragmentRoute covers the fragment route's own two outcomes:
// a real session renders its full detail body, and an id matching no
// cached events 404s (moved here from the shell route above, which used
// to do this check synchronously before any response bytes were
// written).
func TestSessionFragmentRoute(t *testing.T) {
	s := &store{events: []storedEvent{
		{Session: "sess-a", SrcIP: "203.0.113.5", Sensor: "cowrie", Time: "2026-08-12 00:00", Command: "whoami"},
	}}
	mux := investigateTestMux(t, s)

	rec := doGet(mux, "/sessions/sess-a/fragment")
	if rec.Code != http.StatusOK {
		t.Fatalf("known session: status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "whoami") {
		t.Errorf("fragment missing the resolved command, got: %s", rec.Body.String())
	}

	rec = doGet(mux, "/sessions/sess-unknown/fragment")
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown session: status = %d, want 404", rec.Code)
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

// TestGhidraDetailShellRendersWithoutES covers #1288/#1285/#1286's
// shell+hydrate conversion: /ghidra/{sha} must render a 200 shell for any
// hash-format-valid hash with esResultsClient left nil (unconfigured) --
// the old behavior synchronously queried Elasticsearch and 404'd here for
// an unknown hash; that check now happens only on the client's own
// follow-up fetch to the fragment route below. The shell must carry the
// fragment URL for hp-ghidra-report.js to hydrate from and must not leak
// any card content that would only be true for a real result.
func TestGhidraDetailShellRendersWithoutES(t *testing.T) {
	s := &store{}
	mux := investigateTestMux(t, s)
	rec := doGet(mux, "/ghidra/"+shaA)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a shell render (it fetches ES client-side)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-hp-gh-fragment-url="/ghidra/`+shaA+`/fragment"`) {
		t.Errorf("shell is missing the fragment URL hp-ghidra-report.js hydrates from, got: %s", body)
	}
	if strings.Contains(body, "ghidra-detail-body") {
		t.Error("shell must not render the detail-body template's own define name as literal text")
	}
}

// TestGhidraFragmentRoute covers the fragment route's own two outcomes:
// a real result renders the full detail body, and an unknown hash 404s
// (moved here from the shell route above, which used to do this check
// synchronously before any response bytes were written).
func TestGhidraFragmentRoute(t *testing.T) {
	s := &store{}
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "exit_status": "success",
		"functions": []any{map[string]any{"address": "0x401000", "name": "main", "signature": "int main()"}},
	})
	mux := investigateTestMux(t, s)

	rec := doGet(mux, "/ghidra/"+shaA+"/fragment")
	if rec.Code != http.StatusOK {
		t.Fatalf("known hash: status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "0x401000") {
		t.Errorf("fragment missing the resolved function, got: %s", rec.Body.String())
	}

	unknown := "b" + shaA[1:]
	rec = doGet(mux, "/ghidra/"+unknown+"/fragment")
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown hash: status = %d, want 404", rec.Code)
	}
}

func TestSandboxDetailShellRendersWithoutES(t *testing.T) {
	s := &store{}
	mux := investigateTestMux(t, s)
	job := "windows-ghosts-20260810T185343Z-25b7e641f8b6"
	rec := doGet(mux, "/sandbox/"+job)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a shell render", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-hp-sandbox-fragment-url="/sandbox/`+job+`/fragment"`) {
		t.Errorf("shell is missing its fragment URL, got: %s", body)
	}
	if strings.Contains(body, `id="sandbox-detail-actions"`) {
		t.Error("shell must not render result-only actions before hydration")
	}
}

func TestSandboxFragmentRouteUsesJobScopedResult(t *testing.T) {
	job := "windows-ghosts-test"
	esResultsClientFor(t, map[string][]map[string]any{
		"sandbox-analysis-v1": {
			{"sandbox": map[string]any{
				"version": 2, "job": job, "sha256": shaA, "file_type": "PE32 fixture",
			}},
		},
	})
	s := &store{}
	mux := investigateTestMux(t, s)

	rec := doGet(mux, "/sandbox/"+job+"/fragment")
	if rec.Code != http.StatusOK {
		t.Fatalf("known job: status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `id="sandbox-detail-actions"`) || !strings.Contains(body, "PE32 fixture") {
		t.Errorf("fragment missing resolved sandbox detail, got: %s", body)
	}

	rec = doGet(mux, "/sandbox/no-such-job/fragment")
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown job: status = %d, want 404", rec.Code)
	}
}

func TestCapeDetailShellAndScopedFragment(t *testing.T) {
	s := &store{}
	mux := investigateTestMux(t, s)
	rec := doGet(mux, "/cape/"+shaA)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `data-hp-cape-fragment-url="/cape/`+shaA+`/fragment"`) {
		t.Fatalf("CAPE shell did not render without ES: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `id="cape-detail-actions"`) {
		t.Fatal("CAPE shell synchronously rendered result-only content")
	}

	esResultsClientFor(t, map[string][]map[string]any{"cape-analysis-v1": {{"cape": map[string]any{
		"version": 1, "sha256": shaA, "exit_status": "ok", "cape_status": "reported",
		"report": map[string]any{"debug": map[string]any{"log": "fixture analyzer line"}},
	}}}})
	mux = investigateTestMux(t, s)
	rec = doGet(mux, "/cape/"+shaA+"/fragment")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "fixture analyzer line") || !strings.Contains(rec.Body.String(), `aria-label="Analyzer log output"`) {
		t.Fatalf("CAPE fragment did not render the scoped visible log: status=%d body=%s", rec.Code, rec.Body.String())
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
