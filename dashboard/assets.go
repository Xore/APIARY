package main

import "embed"

// The compiled Tailwind stylesheet, the hp-app.js enhancement layer, and
// Leaflet are vendored so the dashboard UI does not depend on a third-party
// JavaScript CDN. Map tiles remain separately configurable at runtime.
//
//go:embed static
var staticAssets embed.FS
