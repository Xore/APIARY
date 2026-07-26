package main

import "embed"

// AdminLTE, Bootstrap Icons, the frontend adapter, and Leaflet are vendored so
// the dashboard UI does not depend on a third-party JavaScript CDN. Map tiles
// remain separately configurable at runtime.
//
//go:embed static
var staticAssets embed.FS
