package main

// pageGhidra is /ghidra: headless Ghidra analysis results, list and detail.
// Markup lives in ui/ghidra.html, not here — see frontend/README.md for why
// (the Tailwind @source scan only reads ui/, so a tw: class in a .go file is
// silently dropped from the bundle).
var pageGhidra = mustReadUI("ghidra.html")
