package main

// Route templates live in the embedded ui tree; see
// docs/DASHBOARD-RENDER-ENGINE-GUIDE.md §6 step 3. Markup is unchanged.
// ips.html carries the /ips list, its lazy row fragments, and the attacker
// profile, exactly as the Go constant did.
var pageIPs = mustReadUI("ips.html")
