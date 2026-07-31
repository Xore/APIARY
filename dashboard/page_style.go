package main

// The shared dashboard head, shell, and reusable partials live in the embedded
// ui tree, as does every route template — the migration is finished. The
// page_*.go files hold page data only; TestRouteTemplatesRenderFromEmbeddedUI
// fails the build on any {{define}} that reappears in a .go file here.
var pageStyle = mustReadUI("partials/dashboard.html")
