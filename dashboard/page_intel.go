package main

// Route templates live in the embedded ui tree; see
// docs/DASHBOARD-RENDER-ENGINE-GUIDE.md §6 step 3. Markup is unchanged.
// intel.html still bundles the clusters, campaigns, and commands routes as the
// Go constant did; splitting it into one file per route is a later rename.
var pageIntel = mustReadUI("intel.html")
