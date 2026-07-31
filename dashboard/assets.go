package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"strings"
	"sync"
)

// The compiled Tailwind stylesheet, the hp-app.js enhancement layer, and
// Leaflet are vendored so the dashboard UI does not depend on a third-party
// JavaScript CDN. Map tiles remain separately configurable at runtime.
//
//go:embed static
var staticAssets embed.FS

var assetQueries sync.Map

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
