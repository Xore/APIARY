package main

import (
	"html/template"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEarliestEventByShasum (#205): the /payloads list and payload-analysis
// detail page both need "which event produced this capture", recovered by
// matching a file's hash against the event feed's Shasum field. Several
// events can share a hash (the same payload downloaded more than once) --
// the earliest one is the one that actually brought the file in, so that is
// the one that must win, regardless of feed order.
func TestEarliestEventByShasum(t *testing.T) {
	t0 := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	events := []storedEvent{
		{Shasum: "aaa", Sensor: "cowrie", Session: "sess-2", when: t0.Add(2 * time.Hour)},
		{Shasum: "aaa", Sensor: "cowrie", Session: "sess-1", when: t0},
		{Shasum: "bbb", Sensor: "dionaea", when: t0.Add(time.Hour)},
		{Shasum: "", Sensor: "cowrie", when: t0}, // no shasum: must not appear in the result
	}
	origins := earliestEventByShasum(events)

	if len(origins) != 2 {
		t.Fatalf("expected 2 hashes with an origin, got %d: %+v", len(origins), origins)
	}
	got, ok := origins["aaa"]
	if !ok {
		t.Fatal(`missing origin for "aaa"`)
	}
	if got.Session != "sess-1" || !got.when.Equal(t0) {
		t.Fatalf("earliest event for %q must win, got session=%q when=%v", "aaa", got.Session, got.when)
	}
	if got2 := origins["bbb"]; got2.Sensor != "dionaea" {
		t.Fatalf(`expected "bbb"'s origin sensor to be dionaea, got %q`, got2.Sensor)
	}
	if _, ok := origins[""]; ok {
		t.Fatal("an event with no shasum must not produce an origin entry")
	}
}

// TestPayloadsPageDropsRedundantActionButtons (#205): the standalone
// Analyze-in-sandbox and Disassemble-with-Ghidra buttons on /payloads and
// /payload-analysis/{hash} duplicated what the analysis workbench already
// does -- they were removed in favor of the workbench link plus a per-row
// kebab menu for the remaining secondary actions (preview/download/related
// events/publish). This pins that removal so it cannot silently regress.
func TestPayloadsPageDropsRedundantActionButtons(t *testing.T) {
	for _, gone := range []string{`action="/sandbox/submit"`, `action="/ghidra/submit"`} {
		if strings.Contains(pagePayloads, gone) {
			t.Fatalf("payloads/payload-analysis templates still post to %q -- "+
				"this action belongs in the analysis workbench now, not a standalone button", gone)
		}
	}
	if !strings.Contains(pagePayloads, `class="action-menu"`) {
		t.Fatal("payloads list row is missing the per-row action-menu kebab that replaced the flat button row")
	}
	// The list moved from a <table> to a .project-card grid (#213 phase 4),
	// so there is no "origin event" column header left to check for -- the
	// origin session link itself (title text below) is the thing #205 needs
	// to still be present.
	if !strings.Contains(pagePayloads, "Open the session this payload was captured in") {
		t.Fatal("payloads card is missing the origin-session link (#205)")
	}
}

// The /payloads list renders as a .project-grid/.project-card grid (#213
// phase 4), not the old <table>. Unlike a single-destination card (e.g.
// Ghidra results), a payload has several distinct actions -- the whole
// card cannot be one link (HTML forbids nesting the action menu's
// <details>/<button>/<form> inside an <a>) -- so only the hash title
// itself links out, to the same /payload-analysis/ destination the old
// table's hash cell used, and every other action stays in the kebab menu.
func TestPayloadsPageRendersAsCardGrid(t *testing.T) {
	dir := t.TempDir()
	hash := strings.Repeat("c", 64)
	if err := os.WriteFile(filepath.Join(dir, hash), []byte("#!/bin/sh\necho hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{payloadDirs: []string{dir}, es: newESClient("http://127.0.0.1:1", "")}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	page := s.payloadsData(payloadsFilter{})
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "payloads", &page); err != nil {
		t.Fatalf("payloads page does not render: %v", err)
	}
	html := out.String()

	if strings.Contains(html, `<table class="recent data-table">`) {
		t.Fatal("payloads list still renders the old table markup, want a card grid")
	}
	if !strings.Contains(html, "project-grid") || !strings.Contains(html, "project-card") {
		t.Fatal("payloads list is missing the .project-grid/.project-card markup")
	}
	if !strings.Contains(html, `href="/payload-analysis/`+hash+`"`) {
		t.Fatalf("card for %s does not link its title to the static analysis page", hash)
	}
	if !strings.Contains(html, `class="action-menu"`) {
		t.Fatal("payloads card is missing the action-menu kebab")
	}
	if !strings.Contains(html, "project-card__icon") {
		t.Fatal("payloads card is missing its leading icon")
	}
}

// The lazy-load container is a plain <div>, not a <table>, so it must use
// the generic data-hp-lazy-list contract (with a remote page URL for the
// same offset-based /api/payload-rows pagination the table used), not the
// table-specific tbody attributes.
func TestPayloadsPageResultsUseGenericLazyListContract(t *testing.T) {
	dir := t.TempDir()
	hash := strings.Repeat("d", 64)
	if err := os.WriteFile(filepath.Join(dir, hash), []byte("#!/bin/sh\necho hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{payloadDirs: []string{dir}, es: newESClient("http://127.0.0.1:1", "")}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	page := s.payloadsData(payloadsFilter{})
	page.RowsURL = payloadsRowsURL(httptest.NewRequest("GET", "/payloads", nil))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "payloads", &page); err != nil {
		t.Fatalf("payloads page does not render: %v", err)
	}
	html := out.String()

	if !strings.Contains(html, `data-hp-lazy-list`) {
		t.Fatal("payloads results container is missing data-hp-lazy-list")
	}
	if !strings.Contains(html, `data-hp-page-url="/api/payload-rows`) {
		t.Fatal("payloads results container is missing its remote page URL")
	}
}
