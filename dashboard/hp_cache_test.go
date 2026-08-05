package main

import (
	"strings"
	"testing"
)

// #486: the per-tab cache the overview page's map/heatmap/attack-vectors
// fetches route through must actually ship with the dashboard and be wired
// into the shell before hp-app.js, which calls window.HoneypotCache at
// script-load time (both are `defer`, so document order is execution order).
func TestHoneypotCacheIsEmbeddedAndWiredBeforeAppScript(t *testing.T) {
	data, err := staticAssets.ReadFile("static/hp-cache.js")
	if err != nil {
		t.Fatal("static/hp-cache.js must be embedded with the dashboard assets")
	}
	js := string(data)
	for _, want := range []string{"window.HoneypotCache", "cachedJSON", "invalidate"} {
		if !strings.Contains(js, want) {
			t.Fatalf("hp-cache.js missing expected surface %q", want)
		}
	}

	partial := mustReadUI("partials/dashboard.html")
	cacheIdx := strings.Index(partial, `/static/hp-cache.js`)
	appIdx := strings.Index(partial, `/static/hp-app.js`)
	if cacheIdx == -1 {
		t.Fatal("dashboard shell must load /static/hp-cache.js")
	}
	if appIdx == -1 {
		t.Fatal("dashboard shell must load /static/hp-app.js")
	}
	if cacheIdx > appIdx {
		t.Fatal("hp-cache.js must be declared before hp-app.js: both are deferred, so document order is execution order, and hp-app.js calls window.HoneypotCache at its top level")
	}
}

func TestOverviewFetchesRouteThroughHoneypotCache(t *testing.T) {
	data, err := staticAssets.ReadFile("static/hp-app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(data)
	for _, want := range []string{
		`window.HoneypotCache.cachedJSON("/api/map-points")`,
		`window.HoneypotCache.cachedJSON("/api/heatmap?sensor="`,
		`window.HoneypotCache.cachedJSON("/api/attack-vectors?sensor="`,
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("hp-app.js must fetch %q through the per-tab cache", want)
		}
	}
}
