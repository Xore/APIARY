package main

// The shared dashboard head, shell, and reusable partials now live in the
// embedded ui tree. Route templates remain in page_*.go while the render-engine
// migration proceeds one page at a time.
var pageStyle = mustReadUI("partials/dashboard.html")
