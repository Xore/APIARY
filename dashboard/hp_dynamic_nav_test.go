package main

import (
	"html/template"
	"os"
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

// Sanity-checks the script's own route list and navigation wiring directly
// against its source, the same pattern TestWorkbenchRunButtonGivesImmediateFeedback
// already uses for hp-workbench.js -- not a substitute for a real browser
// test (none exists in this Go suite), but catches a route regex or a
// missing listener surviving an edit that a template-presence check alone
// wouldn't.
func TestDynamicNavScriptCoversTheConsolidatedRoutesAndWiring(t *testing.T) {
	body, err := os.ReadFile("static/hp-dynamic-nav.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	for _, want := range []string{
		`/^\/payloads$/`,
		`/^\/payload-analysis\/`,
		`/^\/payload-workbench\/results$/`,
		`/^\/payload-workbench\/`,
		`/^\/sandbox\/`,
		`/^\/github-analysis\/`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("hp-dynamic-nav.js is missing the expected route pattern %q", want)
		}
	}

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
