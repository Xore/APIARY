package main

// pageRevdeck is /revdeck/{sha256}: a standalone Rev·Deck run (#78), distinct
// from the "Rev·Deck automated triage" card on /ghidra, which is an
// enrichment embedded inside a full Ghidra analysis rather than its own
// submission. Markup lives in ui/revdeck.html, not here -- see
// page_ghidra.go's own comment for why.
var pageRevdeck = mustReadUI("revdeck.html")
