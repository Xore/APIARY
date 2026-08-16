package main

// The four operations routes are the first page templates to move out of Go
// string constants and into the embedded ui tree, per
// docs/DASHBOARD-RENDER-ENGINE-GUIDE.md §6 step 3. Markup is unchanged; only
// its storage moved, so every route keeps its current output and data
// contract. Remaining pages follow one at a time.
var pageOps = mustReadUI("history.html") +
	mustReadUI("dead_letters.html") +
	mustReadUI("source_health.html") +
	mustReadUI("alerts.html")
