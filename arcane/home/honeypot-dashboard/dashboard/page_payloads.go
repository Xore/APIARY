package main

// Route templates live in the embedded ui tree; see
// docs/DASHBOARD-RENDER-ENGINE-GUIDE.md §6 step 3. Markup is unchanged.
// payloads.html carries the inventory, its lazy row fragments, and the
// per-hash analysis page, exactly as the Go constant did.
var pagePayloads = mustReadUI("payloads.html")
