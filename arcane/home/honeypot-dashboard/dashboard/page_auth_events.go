package main

// /auth-events (#1066): auth-events-worker's Keycloak/gateway
// authentication-failure telemetry, delivered to the dashboard by
// Elasticsearch polling (see auth_events.go's package comment for the
// transport decision). Markup follows the read-only diagnostics pages
// (ml-anomalies, source-health): server-rendered from a cache, refreshed
// on page load.
var pageAuthEvents = mustReadUI("auth_events.html")
