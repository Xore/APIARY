package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestWebManifestUsesStandardContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/static/site.webmanifest", nil)
	response := httptest.NewRecorder()
	staticAssetHandler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("manifest status = %d, want 200", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/manifest+json" {
		t.Fatalf("manifest Content-Type = %q, want application/manifest+json", got)
	}
}

// Static assets are served immutable for a week, so the query string is the
// only thing that can ever make a browser fetch a changed script. It used to
// be a date typed into the template by hand; the failure is silent and only in
// one direction — forget the bump, and returning browsers run last week's
// JavaScript against today's HTML, so a newly added control renders and does
// nothing. Deriving it from the content is what makes that unforgettable.
func TestAssetURLsCarryAContentHash(t *testing.T) {
	modals := assetURL("/static/hp-modals.js")
	if !regexp.MustCompile(`^/static/hp-modals\.js\?v=[0-9a-f]{12}$`).MatchString(modals) {
		t.Fatalf("assetURL = %q, want the path with a content-hash query", modals)
	}
	if app := assetURL("/static/hp-app.js"); strings.SplitN(app, "?v=", 2)[1] == strings.SplitN(modals, "?v=", 2)[1] {
		t.Fatal("two different assets share a version; the query is not derived from content")
	}
	if again := assetURL("/static/hp-modals.js"); again != modals {
		t.Fatalf("assetURL is not stable across calls: %q then %q", modals, again)
	}
	// A caching hint is never worth a broken page.
	if got := assetURL("/static/does-not-exist.js"); got != "/static/does-not-exist.js" {
		t.Fatalf("assetURL(missing) = %q, want the bare path", got)
	}
}

// The regression guard proper: a hand-written version anywhere in the markup
// reintroduces the bug, so fail on the pattern rather than trusting review to
// catch the next one.
func TestNoHandWrittenAssetVersionsRemain(t *testing.T) {
	if match := regexp.MustCompile(`/static/[^"'\s]+\?v=`).FindString(pageTemplate); match != "" {
		t.Fatalf("%q pins a version by hand; use {{asset \"/static/...\"}} so the query follows the file", match)
	}
	if !strings.Contains(pageTemplate, `{{asset "/static/hp-modals.js"}}`) {
		t.Fatal("the shared page template no longer loads hp-modals.js through asset()")
	}
}
