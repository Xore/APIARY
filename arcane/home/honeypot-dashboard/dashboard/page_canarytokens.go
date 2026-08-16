package main

// page_canarytokens.go -- #1487: the Canarytokens page (Tokens / Create bait
// / Reports tabs). Creation, listing, and download are already served by
// canarytokens_api.go's /api/settings/canarytokens* endpoints (#1508); this
// page is a new, dedicated surface for them instead of the Settings modal
// pane, plus a Reports tab reusing the existing /api/events?sensor=
// canarytokens endpoint (classify.go already classifies canarytokens-adapter
// events, #1426) for fired-token activity. All three tabs render an instant
// skeleton and hydrate client-side via static/hp-canarytokens.js -- no
// server-side query on page load, same shape as attackersShell (attackers.go).
//
// The markup itself lives in the embedded ui tree; see
// docs/DASHBOARD-RENDER-ENGINE-GUIDE.md §6 step 3.
var pageCanarytokens = mustReadUI("canarytokens.html")
