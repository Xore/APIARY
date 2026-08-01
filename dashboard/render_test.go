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

// TestSecHeadersFrameSrcMatchesAuthAccountOrigin (#196 follow-up): the
// dashboard's own CSP had no frame-src directive at all, so it fell back to
// default-src 'self' -- which silently blocked the settings iframe from
// ever framing auth-backend, no matter how permissive auth-backend's own
// frame-ancestors was (a relaxed frame-ancestors is the *embedded* page's
// opt-in for who may frame it; frame-src is the *embedding* page's own
// opt-in for what it may frame -- only the dashboard can grant itself that).
func TestSecHeadersFrameSrcMatchesAuthAccountOrigin(t *testing.T) {
	defer func(prev string) { authFrameOrigin = prev }(authFrameOrigin)

	authFrameOrigin = ""
	w := httptest.NewRecorder()
	secHeaders(w, nonce())
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src 'self'") {
		t.Fatalf("CSP must always send an explicit frame-src, got: %q", csp)
	}
	if strings.Contains(csp, "frame-src 'self' http") {
		t.Fatalf("frame-src must not name an origin when AUTH_ACCOUNT_URL is unset: %q", csp)
	}

	setAuthFrameOrigin("https://auth.example.test/auth/app?pane=account")
	w2 := httptest.NewRecorder()
	secHeaders(w2, nonce())
	csp2 := w2.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp2, "frame-src 'self' https://auth.example.test") {
		t.Fatalf("frame-src must include the auth account origin (path/query stripped), got: %q", csp2)
	}
	if strings.Contains(csp2, "/auth/app") {
		t.Fatalf("frame-src must be an origin, not the full account URL with its path: %q", csp2)
	}
}

// TestSetAuthFrameOriginRejectsUnusableInput ensures a malformed value
// (which validatedAuthAccountURL should already have filtered, but this
// function has no way to know that from a bare string) leaves the CSP at
// its safe default rather than emitting a broken frame-src directive.
func TestSetAuthFrameOriginRejectsUnusableInput(t *testing.T) {
	defer func(prev string) { authFrameOrigin = prev }(authFrameOrigin)
	for _, bad := range []string{"", "not a url", "/relative/path", "https://"} {
		authFrameOrigin = "sentinel"
		setAuthFrameOrigin(bad)
		if authFrameOrigin != "sentinel" {
			t.Fatalf("setAuthFrameOrigin(%q) must leave authFrameOrigin untouched, got %q", bad, authFrameOrigin)
		}
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
		`"campaigns"`, `"history"`, `"dead-letters"`, `"source-health"`,
		`"alerts"`, `"reports"`, `"payloads"`, `"ghidra"`, `"sandbox"`,
		`"commands"`, `"payload-analysis"`, `"ml-anomalies"`,
	}
	for _, route := range routes {
		if !strings.Contains(src.String(), "renderPage(w, tmpl, "+route) {
			t.Fatalf("route template %s is not rendered via renderPage() -- it will send no CSP header", route)
		}
	}
}
