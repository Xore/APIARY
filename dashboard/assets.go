package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
)

// The compiled Tailwind stylesheet, the hp-app.js enhancement layer,
// Leaflet, Cytoscape.js (#1203's attacker graph, see attackers_graph.go),
// and ECharts (#1224's kill-chain analytics, see kill_chain.go) are
// vendored so the dashboard UI does not depend on a third-party JavaScript
// CDN. Map tiles remain separately configurable at runtime.
//
//go:embed static
var staticAssets embed.FS

var assetQueries sync.Map

func staticAssetHandler() http.Handler {
	files := http.FileServer(http.FS(staticAssets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if strings.HasSuffix(r.URL.Path, ".webmanifest") {
			w.Header().Set("Content-Type", "application/manifest+json")
		}
		files.ServeHTTP(w, r)
	})
}

// assetURL appends a content hash to a /static reference so a browser fetches
// the file again exactly when it has changed.
//
// The versions used to be hand-written date strings in the template. That
// silently fails in one direction only: forget the bump and every returning
// browser keeps running the previous script against the new HTML, so a new
// control renders and does nothing at all — which is how the bulk alert
// acknowledge button shipped dead. A hash cannot be forgotten, and it also
// stops the pointless refetches a date bump forces on unchanged assets.
//
// An unreadable asset yields the bare path: a missing hash is a caching
// question, never a reason to fail a page render.
func assetURL(path string) string {
	if cached, ok := assetQueries.Load(path); ok {
		return cached.(string)
	}
	url := path
	if data, err := staticAssets.ReadFile(strings.TrimPrefix(path, "/")); err == nil {
		sum := sha256.Sum256(data)
		url = path + "?v=" + hex.EncodeToString(sum[:])[:12]
	}
	assetQueries.Store(path, url)
	return url
}
