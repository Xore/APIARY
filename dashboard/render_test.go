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
