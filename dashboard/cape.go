package main

// cape.go — Workbench registry wiring for the CAPE sandbox route (#319).
//
// Only the spool-directory helpers and the workbenchRegistry entry are
// built here, deliberately. #319's own issue text is explicit that the
// full result page ("A cape entry ... + /cape result page") depends on "a
// real result shape" from #318 -- and #318's worker (sandbox/cape/worker/
// cape-worker.py) has never submitted a real sample, because #315's golden
// image doesn't exist yet, so there is no live {sha256}_cape.json this
// dashboard could load, parse, or design a detail page against without
// guessing. Guessing here is exactly what ghidra-worker.py's own header
// warns against: "the endpoints originally taken from the plan documents
// were wrong."
//
// What IS buildable now, honestly: whether the spool is configured at all
// (the same directoryUsable() signal every other analyzer in
// workbenchRegistry uses), so "cape" can appear in the Workbench selector
// as correctly unavailable rather than not appearing at all. The
// ResultLinkShape below ("/cape/{sha256}") is therefore a real ROUTE
// PROMISE, not yet a real handler -- there is no /cape/{sha256} page in
// this dashboard yet. Follow-up work once #318 has a live result to design
// the page's own loadCapeResults()/ES-mirror pair against, mirroring
// revdeck.go's shape (revdeckRequestDir/revdeckResultsDir ->
// loadRevdeckResults -> revdeckPageData) rather than ghidra.go's larger one.
func capeRequestDir() string { return getenv("CAPE_REQUEST_DIR", "") }
func capeResultsDir() string { return getenv("CAPE_RESULTS_DIR", "") }
