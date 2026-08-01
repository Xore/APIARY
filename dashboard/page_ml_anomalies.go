package main

// /ml-anomalies (#64): ml-worker's scored anomalies, delivered to the
// dashboard by Elasticsearch polling (see ml_anomalies.go's package
// comment for the transport decision). Markup follows the read-only
// diagnostics pages (source-health, dead-letters): server-rendered from a
// cache, refreshed on page load.
var pageMLAnomalies = mustReadUI("ml_anomalies.html")
