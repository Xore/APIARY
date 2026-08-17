package main

import (
	"html/template"
	"os"
	"regexp"
	"strings"
	"testing"
)

// #1141: every page in the #1139 consolidated payload/results family must
// load hp-dynamic-nav.js -- one missed template silently falls back to a
// full page navigation for that page's own links (not a bug exactly, but
// defeats the point of #1141), so this is checked per-template rather than
// trusting a single spot-check to generalize.
func TestConsolidatedPayloadPagesLoadDynamicNavScript(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	render := func(name string, data any) string {
		t.Helper()
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, name, data); err != nil {
			t.Fatalf("%s page does not execute: %v", name, err)
		}
		return out.String()
	}

	cases := []struct {
		name string
		data any
	}{
		{"payloads", &payloadsPage{}},
		{"payload-analysis", &binaryAnalysis{}},
		{"payload-workbench", &workbenchPageData{}},
		{"workbench-results", &evidenceResultsPageData{}},
		{"sandbox", &sandboxPageData{}},
		{"github-analysis", &githubAnalysisPageData{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := render(c.name, c.data)
			if !strings.Contains(body, `/static/hp-dynamic-nav.js`) {
				t.Fatalf("%s page does not load hp-dynamic-nav.js", c.name)
			}
		})
	}
}

// extractFullNavRoutes parses hp-dynamic-nav.js's FULL_NAV_ROUTES array
// (the #1564 opt-out list -- every route not matching one of these patterns
// is dynamically navigated by default) and compiles each regex literal as a
// Go regexp, so tests can assert against real route-matching behavior
// instead of a brittle substring check on the source text. The patterns
// only use anchors, escaped slashes, character classes and non-capturing
// alternation -- no JS-only regex syntax -- so a straight `\/` -> `/`
// unescape is enough to make them valid Go (RE2) regexps too.
func extractFullNavRoutes(t *testing.T, src string) []*regexp.Regexp {
	t.Helper()
	start := strings.Index(src, "const FULL_NAV_ROUTES = [")
	if start < 0 {
		t.Fatal("hp-dynamic-nav.js does not define FULL_NAV_ROUTES")
	}
	end := strings.Index(src[start:], "\n  ];")
	if end < 0 {
		t.Fatal("hp-dynamic-nav.js's FULL_NAV_ROUTES array is not closed as expected")
	}
	block := src[start : start+end]

	literalRe := regexp.MustCompile(`/(\^[^\n]*?)/,`)
	matches := literalRe.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		t.Fatal("no route patterns found inside FULL_NAV_ROUTES")
	}
	patterns := make([]*regexp.Regexp, 0, len(matches))
	for _, m := range matches {
		goPattern := strings.ReplaceAll(m[1], `\/`, `/`)
		re, err := regexp.Compile(goPattern)
		if err != nil {
			t.Fatalf("FULL_NAV_ROUTES pattern %q does not compile as a Go regexp: %v", m[1], err)
		}
		patterns = append(patterns, re)
	}
	return patterns
}

func matchesAnyRoute(patterns []*regexp.Regexp, path string) bool {
	for _, re := range patterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// TestDynamicNavDefaultsToTheWholeShell (#1564): FULL_NAV_ROUTES is an
// opt-out list now, not an allow-list -- every real shell route not in it
// (including every route #1141/#1564 have already converted to the
// mount/unmount convention) must be dynamically navigable by default, and
// every route that is NOT yet convention-safe (or isn't a shell page at
// all) must still force a full navigation.
func TestDynamicNavDefaultsToTheWholeShell(t *testing.T) {
	body, err := os.ReadFile("static/hp-dynamic-nav.js")
	if err != nil {
		t.Fatal(err)
	}
	patterns := extractFullNavRoutes(t, string(body))

	mustStayDynamic := []string{
		"/", "/payloads", "/payload-analysis/abc123",
		"/payload-workbench/results", "/payload-workbench/run1",
		"/sandbox/job1", "/github-analysis/abc123",
		"/events", "/search", "/clusters", "/campaigns", "/history",
		"/dead-letters", "/source-health", "/alerts", "/auth-events",
		"/llm-analysis", "/agent-campaigns", "/recordings", "/sensors",
		"/ips", "/attackers",
	}
	for _, path := range mustStayDynamic {
		if matchesAnyRoute(patterns, path) {
			t.Errorf("FULL_NAV_ROUTES wrongly forces a full navigation for %q", path)
		}
	}

	mustStayFullNav := []string{
		"/api/whoami", "/static/hp-app.js", "/export/history.json",
		"/metrics", "/auth/login", "/admin/problem-reports", "/healthz",
		"/payload/abc123", "/tty/abc123", "/tty/abc123.cast",
		"/sandbox/vnc", "/payload-workbench", "/sandbox", "/github-analysis",
		"/kill-chain", "/commands", "/ml-anomalies", "/reports",
		"/canarytokens", "/settings", "/sessions/abc123",
		"/investigate/ip/203.0.113.9", "/investigate/cidr/203.0.113.0/24",
		"/investigate/cluster", "/ghidra", "/ghidra/abc123",
		"/revdeck/abc123", "/cape/abc123",
	}
	for _, path := range mustStayFullNav {
		if !matchesAnyRoute(patterns, path) {
			t.Errorf("FULL_NAV_ROUTES no longer forces a full navigation for %q -- "+
				"if its own script now supports mount/unmount, remove it from this test's "+
				"mustStayFullNav list too, not just the source", path)
		}
	}
}

// Sanity-checks the script's own navigation wiring directly against its
// source, the same pattern TestWorkbenchRunButtonGivesImmediateFeedback
// already uses for hp-workbench.js -- not a substitute for a real browser
// test (none exists in this Go suite), but catches a missing listener
// surviving an edit that a template-presence check alone wouldn't.
func TestDynamicNavScriptCoversTheConsolidatedRoutesAndWiring(t *testing.T) {
	body, err := os.ReadFile("static/hp-dynamic-nav.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	for _, want := range []string{
		`addEventListener("click"`,
		`addEventListener("popstate"`,
		"history.pushState",
		"replaceHoneypotPage",
		"initDashboardTabs",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("hp-dynamic-nav.js is missing expected wiring %q", want)
		}
	}

	// #1141 regression risk (see the script's own comment): a stale
	// window.honeypotDashboardTab from the previous page must not survive
	// a dynamic navigation and silently steer tab selection on the new one.
	if !strings.Contains(src, "window.honeypotDashboardTab = undefined") {
		t.Error("hp-dynamic-nav.js does not reset window.honeypotDashboardTab before re-deriving tab state on the new page")
	}

	// CSP: any script this file injects on demand must carry the live
	// page's own nonce, or the browser's script-src directive blocks it.
	if !strings.Contains(src, "el.nonce = pageNonce") {
		t.Error("hp-dynamic-nav.js does not nonce dynamically injected <script> elements")
	}
}

// TestTopbarPageLabelCoversEverySidebarRoute (#1564): the topbar's center
// label (data-hp-page-name) is synced client-side from hp-app.js's
// pageLabels map on every navigation (syncActiveNav). A sidebar route
// missing from that map silently falls back to a generic label -- this is
// exactly the bug #1564 reported ("the topbar reads Operations on most
// pages"): pageLabels' predecessor (navGroups) was a small hand-maintained
// table that fell out of sync with the sidebar's own real routes as the
// design refresh added Operations/Reports/Tools and several more
// Monitor/Investigate entries, so most pages silently fell through to the
// fallback string. This walks the REAL rendered sidebar rather than a
// second hand-maintained route list, so a future sidebar addition that
// forgets a pageLabels entry fails here instead of silently mislabeling
// the topbar again.
func TestTopbarPageLabelCoversEverySidebarRoute(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl, err := template.New("t").Funcs(funcs).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "page", snapshot{}); err != nil {
		t.Fatalf("overview page does not execute with an empty snapshot: %v", err)
	}
	html := out.String()

	navRe := regexp.MustCompile(`data-hp-nav="([^"]+)"`)
	routes := navRe.FindAllStringSubmatch(html, -1)
	if len(routes) == 0 {
		t.Fatal("no data-hp-nav routes found in the rendered shell")
	}

	appJS, err := staticAssets.ReadFile("static/hp-app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(appJS)

	seen := map[string]bool{}
	for _, m := range routes {
		route := m[1]
		if seen[route] {
			continue
		}
		seen[route] = true
		if !strings.Contains(js, `"`+route+`": "`) {
			t.Errorf("hp-app.js's pageLabels has no topbar label for sidebar route %q -- "+
				"it will fall back to the generic \"Dashboard\" label instead of naming the page", route)
		}
	}
}
