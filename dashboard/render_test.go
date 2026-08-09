package main

import (
	"html/template"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestRenderPageSendsCSPAndPerRequestNonce is #58's own required test:
// "asserts the header is present and that the nonce differs between two
// requests." It also checks the CSP nonce is the SAME value actually
// embedded in the rendered page's inline script -- a header with the right
// shape but a mismatched nonce would silently break every nonce'd inline
// block under CSP while still passing a header-only check.
func TestRenderPageSendsCSPAndPerRequestNonce(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))

	render := func() (*httptest.ResponseRecorder, string) {
		w := httptest.NewRecorder()
		data := snapshot{}
		renderPage(w, tmpl, "page", &data)
		return w, w.Body.String()
	}

	w1, html1 := render()
	w2, _ := render()

	csp1 := w1.Header().Get("Content-Security-Policy")
	csp2 := w2.Header().Get("Content-Security-Policy")
	if csp1 == "" {
		t.Fatal("renderPage did not send a Content-Security-Policy header")
	}
	if csp1 == csp2 {
		t.Fatalf("CSP nonce must differ between requests, got the same header twice: %q", csp1)
	}

	nonceRe := regexp.MustCompile(`'nonce-([\w-]+)'`)
	m := nonceRe.FindStringSubmatch(csp1)
	if m == nil {
		t.Fatalf("CSP header has no nonce directive: %q", csp1)
	}
	headerNonce := m[1]

	if !strings.Contains(html1, `nonce="`+headerNonce+`"`) {
		t.Fatalf("rendered page's inline script nonce does not match the CSP header's nonce (%q); "+
			"a header/markup mismatch means the browser silently drops the rule", headerNonce)
	}

	for _, want := range []string{
		"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
	} {
		if w1.Header().Get(want) == "" {
			t.Fatalf("renderPage did not send %q", want)
		}
	}
	if ct := w1.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("renderPage did not set Content-Type: %q", ct)
	}
}

func TestSecHeadersNeverAllowKeycloakAccountFraming(t *testing.T) {
	w := httptest.NewRecorder()
	secHeaders(w, nonce())
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src 'self'") {
		t.Fatalf("CSP must always send an explicit frame-src, got: %q", csp)
	}
	if strings.Contains(csp, "frame-src 'self' http") {
		t.Fatalf("dashboard must not allow a cross-origin account iframe: %q", csp)
	}
}

// TestOverviewRefreshTargetsTheCurrentPageContentSelector (#199): the
// overview page's in-place live-refresh script selects both the freshly-
// fetched and the currently-mounted page content by querySelector -- #184
// (commit 84bd9dc) renamed every page wrapper's class from .wrap to
// app-content/app-content--wide, updated every template and shell.css, but
// missed this one client-side selector. It kept matching nothing in the
// fresh document forever after, so refreshDashboard() silently no-opped on
// every SSE update and every 60s poll: the toolbar said LIVE, nothing ever
// moved. [data-hp-page-content] is the stable attribute every page wrapper
// actually carries (see shell_layout_test.go) -- pin both lookups to it so
// a future class rename can't quietly break this again.
func TestOverviewRefreshTargetsTheCurrentPageContentSelector(t *testing.T) {
	if strings.Contains(pageTemplate, `querySelector(".wrap")`) {
		t.Fatal(`overview's refresh script still queries the removed .wrap class -- ` +
			`it will silently stop finding page content the moment .wrap doesn't exist`)
	}
	if !strings.Contains(pageTemplate, `doc.querySelector("[data-hp-page-content]")`) {
		t.Fatal("overview's refresh script must select the freshly-fetched page content by [data-hp-page-content]")
	}
}

// TestOverviewRefreshNeverInsertsUnrenoncedMarkup (#347): refreshDashboard()
// used to fall back to a bare current.replaceWith(next) whenever
// window.replaceHoneypotPage (hp-app.js's mountPage, which re-nonces the
// fetched fragment's <style>/<script> tags against the live page's own CSP
// nonce before insertion) wasn't defined yet -- e.g. an SSE 'update' firing
// before the deferred hp-app.js script finishes executing. That fallback
// inserted markup carrying a fresh per-response nonce that never matches the
// CSP header already pinned to the live document, tripping style-src. The
// fix is to skip the refresh cycle entirely rather than insert unsafe
// markup; the next update or timer tick retries once hp-app.js is ready.
func TestOverviewRefreshNeverInsertsUnrenoncedMarkup(t *testing.T) {
	if strings.Contains(pageTemplate, "current.replaceWith(next)") {
		t.Fatal("overview's refresh script must not fall back to replaceWith(next) -- " +
			"that path skips reNonce and inserts markup carrying a mismatched CSP nonce")
	}
	if !strings.Contains(pageTemplate, "next&&current&&window.replaceHoneypotPage") {
		t.Fatal("overview's refresh script must gate the DOM swap on window.replaceHoneypotPage " +
			"being defined, so an early SSE update can't race hp-app.js's deferred load")
	}
}

// TestOverviewHasNoDuplicateLiveIndicator (#210): the overview header used
// to carry its own "Live telemetry" pill (#201) alongside the toolbar's
// global LIVE toggle -- two indicators that could show related-but-distinct
// state, and only one of which was actually clickable. The pill is gone;
// the overview's own EventSource must still report connection health, but
// into window.HoneypotLive's shared state rather than rendering anything
// itself.
func TestOverviewHasNoDuplicateLiveIndicator(t *testing.T) {
	for _, marker := range []string{`data-hp-live-pill`, `class="live-pill"`, `renderLivePill`, `sseHealthy`} {
		if strings.Contains(pageTemplate, marker) {
			t.Fatalf("overview header must not carry its own live-status pill any more, found %q", marker)
		}
	}
	if !strings.Contains(pageTemplate, `window.HoneypotLive.setConnectionHealthy(true)`) ||
		!strings.Contains(pageTemplate, `window.HoneypotLive.setConnectionHealthy(false)`) {
		t.Fatal("overview's EventSource must report open/error into window.HoneypotLive's shared connection state")
	}
	if !strings.Contains(pageTemplate, `es.onerror=`) || strings.Contains(pageTemplate, `es.onerror=()=>{};`) {
		t.Fatal("overview's EventSource must react to onerror instead of silently ignoring connection failures")
	}
}

// TestToolbarLiveToggleIsTheSingleGlobalIndicator (#210): the toolbar's
// [data-hp-live-toggle] is shared across every page (it lives in the
// "topbar" partial), so it -- not a page-local pill -- must be the one
// place that reflects both the paused switch and a stalled/reconnecting
// connection, and the one thing a click actually controls.
func TestToolbarLiveToggleIsTheSingleGlobalIndicator(t *testing.T) {
	if !strings.Contains(pageTemplate, `data-hp-live-toggle`) {
		t.Fatal("shared topbar must render the LIVE toggle")
	}
	appJS, err := staticAssets.ReadFile("static/hp-app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(appJS)
	for _, marker := range []string{
		`connectionHealthy:`,
		`setConnectionHealthy`,
		`onConnectionChange:`,
		`hp-live-state--stalled`,
		`window.HoneypotLive.onConnectionChange(renderLiveState)`,
	} {
		if !strings.Contains(js, marker) {
			t.Fatalf("hp-app.js missing %q -- the toolbar toggle must render paused AND stalled state", marker)
		}
	}
	if !strings.Contains(js, `stream.addEventListener("open", () => window.HoneypotLive.setConnectionHealthy(true));`) {
		t.Fatal("the non-overview EventSource must also report connection health, not just the overview's own")
	}
}

// TestLiveRefreshRenoncesFetchedContent (#220): mountPage splices DOM
// fetched via plain fetch() into the already-loaded page. That fetch is a
// fresh server response carrying its own freshly-generated per-request CSP
// nonce -- fetch never re-navigates, so the browser keeps enforcing the
// ORIGINAL page load's nonce. Any nonce'd element (e.g. the overview
// activity heatmap's per-cell <style> block) carried over from the fetched
// document therefore has the wrong nonce and gets silently rejected
// (confirmed live: this permanently blanked the heatmap after the first
// refresh, and toggling a tab's hidden attribute afterward can't
// resurrect CSS rules the browser never accepted). mountPage must rewrite
// every nonce'd element in a fetched subtree to the current page's own
// already-trusted nonce before inserting it.
func TestLiveRefreshRenoncesFetchedContent(t *testing.T) {
	appJS, err := staticAssets.ReadFile("static/hp-app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(appJS)
	if !strings.Contains(js, `.nonce || document.querySelector("style[nonce]")?.nonce`) &&
		!strings.Contains(js, `document.querySelector("script[nonce], style[nonce]")?.nonce`) {
		t.Fatal(`hp-app.js must read the CURRENT page's own trusted nonce via the .nonce IDL property -- ` +
			`getAttribute("nonce") is deliberately hidden by browsers as a CSP hardening measure and always returns ""`)
	}
	if !strings.Contains(js, "const reNonce") {
		t.Fatal("hp-app.js must define a helper that re-nonces fetched content before it is inserted into the live page")
	}
	if !strings.Contains(js, "reNonce(source)") {
		t.Fatal("mountPage must call reNonce on fetched content before either replacement path runs")
	}
}

// TestNoUnnoncedInlineScriptOrStyleRemains is the structural half of #58's
// completion criterion ("no un-nonced inline script or style remains"): a
// regression test that would fail the moment someone adds a new inline
// <script>/<style> block to any page template without either a nonce or an
// external file, across every route in one pass rather than per-template.
func TestNoUnnoncedInlineScriptOrStyleRemains(t *testing.T) {
	bareScript := regexp.MustCompile(`<script(\s[^>]*)?>`)
	bareStyle := regexp.MustCompile(`<style(\s[^>]*)?>`)

	for _, m := range bareScript.FindAllStringSubmatch(pageTemplate, -1) {
		attrs := m[1]
		if strings.Contains(attrs, " defer") || strings.Contains(attrs, "src=") {
			continue // external file, no inline content to nonce
		}
		if !strings.Contains(attrs, `nonce="{{.Nonce}}"`) {
			t.Fatalf("found an inline <script%s> with no nonce and no src=", attrs)
		}
	}
	for _, m := range bareStyle.FindAllStringSubmatch(pageTemplate, -1) {
		if !strings.Contains(m[1], `nonce="{{.Nonce}}"`) {
			t.Fatalf("found an inline <style%s> with no nonce", m[1])
		}
	}
}

// TestEveryPageDataStructCarriesTheNonceField (#58 scope item 1: "a nonce
// generated per request and threaded into every page data struct") --
// renderPage's nonceSetter constraint already enforces this at compile time
// for every call site; this test pins the actual set of routes it covers so
// a future route added straight to tmpl.ExecuteTemplate (bypassing
// renderPage) doesn't silently regress back to sending no CSP header.
func TestEveryFullPageRouteUsesRenderPage(t *testing.T) {
	var src strings.Builder
	for _, f := range []string{"main.go", "search.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src.Write(b)
	}
	routes := []string{
		`"page"`, `"events"`, `"search"`, `"ips"`, `"attacker"`, `"session"`, `"clusters"`,
		`"campaigns"`, `"cidr-correlation"`, `"cluster-correlation"`, `"history"`, `"dead-letters"`, `"source-health"`,
		`"alerts"`, `"reports"`, `"payloads"`, `"ghidra"`, `"sandbox"`,
		`"commands"`, `"payload-analysis"`, `"ml-anomalies"`, `"llm-analysis"`,
	}
	for _, route := range routes {
		if !strings.Contains(src.String(), "renderPage(w, tmpl, "+route) {
			t.Fatalf("route template %s is not rendered via renderPage() -- it will send no CSP header", route)
		}
	}
}

// TestFirstRebuildDoesNotBlockServerStartup (#353): rebuild() walks every
// log file under LOG_DIR and used to run synchronously in main(), before
// any route was registered or ListenAndServe was reached -- the process
// refused every connection, including /healthz, until that first full walk
// finished (confirmed live: tens of seconds on a busy host, occasionally
// long enough to flap the container's own healthcheck into "unhealthy" and
// trigger an unwanted autoheal restart). Every handler that reads
// s.get()/s.getEvents() already does so per-request, not at init time, so
// nothing between rebuild() and ListenAndServe() actually needs the first
// rebuild to have completed. main() itself isn't unit-testable (it starts a
// real listener and never returns), so this pins the structural fix
// instead: s.rebuild()'s first call must be backgrounded, not a top-level
// blocking statement.
func TestFirstRebuildDoesNotBlockServerStartup(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if strings.Contains(src, "\ts.rebuild()\n\tgo s.notifyLoop") {
		t.Fatal("main() calls s.rebuild() synchronously before registering routes -- " +
			"this blocks the server from accepting any connection, including /healthz, " +
			"until the first full log-directory walk completes")
	}
	// The first rebuild() call must be backgrounded (inside a goroutine) so
	// route registration and ListenAndServe are never blocked by it. Checks
	// the structural shape (rebuild() as the first statement of a
	// `go func() { ... }()` block, with notifyLoop reachable somewhere
	// after it in that same literal function body) rather than pinning the
	// exact adjacent line -- #266 inserted a background-loops env-gate
	// comment block between the two, which a stricter adjacency check would
	// have broken without the underlying invariant actually regressing.
	start := strings.Index(src, "go func() {\n\t\ts.rebuild()\n")
	if start == -1 {
		t.Fatal("the first rebuild() call must be the opening statement of a backgrounded goroutine " +
			"(go func() { s.rebuild() ... }()) so route registration and ListenAndServe are never blocked by it")
	}
	end := strings.Index(src[start:], "\n\t}()")
	if end == -1 {
		t.Fatal("could not find the closing of the goroutine that backgrounds the first rebuild() call")
	}
	body2 := src[start : start+end]
	if !strings.Contains(body2, "s.notifyLoop") {
		t.Fatal("notifyLoop must still be started from inside the same backgrounded goroutine as the first rebuild() call")
	}
}
