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

// #301: /payloads gains sensor/since/q (hash-contains) filters alongside the
// existing source chips.

func writeTestPayload(t *testing.T, dir, hash string, mtime time.Time) {
	t.Helper()
	path := filepath.Join(dir, hash)
	if err := os.WriteFile(path, []byte("payload-"+hash), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestPayloadsDataFiltersBySensor(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	hashA, hashB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	writeTestPayload(t, dir, hashA, now)
	writeTestPayload(t, dir, hashB, now)

	s := &store{payloadDirs: []string{dir}}
	s.events = []storedEvent{
		{Shasum: hashA, Sensor: "cowrie", Session: "sess-a", when: now},
		{Shasum: hashB, Sensor: "dionaea", when: now},
	}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	page := s.payloadsData(payloadsFilter{Sensor: "cowrie"})
	if len(page.Files) != 1 || page.Files[0].Hash != hashA {
		t.Fatalf("expected only the cowrie-origin file, got %+v", page.Files)
	}
	if page.Files[0].Sensor != "cowrie" {
		t.Errorf("Sensor field not populated: %+v", page.Files[0])
	}
}

// A capture with no matching event at all (normal for Dionaea) has an empty
// Sensor and must be excluded by a sensor filter, not treated as a wildcard
// match.
func TestPayloadsDataSensorFilterExcludesUnattributedCaptures(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	hash := strings.Repeat("c", 64)
	writeTestPayload(t, dir, hash, now)

	s := &store{payloadDirs: []string{dir}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	page := s.payloadsData(payloadsFilter{Sensor: "cowrie"})
	if len(page.Files) != 0 {
		t.Fatalf("expected no files (no origin event at all), got %+v", page.Files)
	}
}

func TestPayloadsDataFiltersBySince(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	recent, old := strings.Repeat("d", 64), strings.Repeat("e", 64)
	writeTestPayload(t, dir, recent, now)
	writeTestPayload(t, dir, old, now.Add(-48*time.Hour))

	s := &store{payloadDirs: []string{dir}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	page := s.payloadsData(payloadsFilter{Since: "24h"})
	if len(page.Files) != 1 || page.Files[0].Hash != recent {
		t.Fatalf("expected only the recent capture, got %+v", page.Files)
	}
}

func TestPayloadsDataFiltersByHashSubstring(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	hashA := strings.Repeat("a", 60) + "1234"
	hashB := strings.Repeat("b", 64)
	writeTestPayload(t, dir, hashA, now)
	writeTestPayload(t, dir, hashB, now)

	s := &store{payloadDirs: []string{dir}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	page := s.payloadsData(payloadsFilter{Hash: "1234"})
	if len(page.Files) != 1 || page.Files[0].Hash != hashA {
		t.Fatalf("expected only the matching-substring hash, got %+v", page.Files)
	}

	// Case-insensitive, matching the rest of this codebase's substring filters.
	page = s.payloadsData(payloadsFilter{Hash: "BBBB"})
	if len(page.Files) != 1 || page.Files[0].Hash != hashB {
		t.Fatalf("hash substring filter is not case-insensitive: %+v", page.Files)
	}
}

// Source (the existing chip filter), sensor, since, and hash all narrow the
// same result set together (AND, matching every other filter on this
// dashboard), not just individually.
func TestPayloadsDataCombinesAllFilters(t *testing.T) {
	root := t.TempDir()
	dionaeaDir, cowrieDir := filepath.Join(root, "dionaea"), filepath.Join(root, "cowrie")
	if err := os.MkdirAll(dionaeaDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cowrieDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	match := strings.Repeat("f", 60) + "9999"
	writeTestPayload(t, cowrieDir, match, now)
	writeTestPayload(t, cowrieDir, strings.Repeat("a", 64), now)         // wrong hash
	writeTestPayload(t, dionaeaDir, strings.Repeat("b", 60)+"9999", now) // wrong source

	s := &store{payloadDirs: []string{dionaeaDir, cowrieDir}}
	s.events = []storedEvent{{Shasum: match, Sensor: "cowrie", when: now}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	page := s.payloadsData(payloadsFilter{Source: "cowrie", Sensor: "cowrie", Since: "1h", Hash: "9999"})
	if len(page.Files) != 1 || page.Files[0].Hash != match {
		t.Fatalf("combined filters did not narrow to exactly the matching file: %+v", page.Files)
	}
}

func TestPayloadsRowsURLCarriesEveryActiveFilter(t *testing.T) {
	r := httptest.NewRequest("GET", "/payloads?source=cowrie&sensor=cowrie&since=24h&q=abc", nil)
	got := payloadsRowsURL(r)
	if !strings.HasPrefix(got, "/api/payload-rows?") {
		t.Fatalf("RowsURL = %q, want /api/payload-rows? prefix", got)
	}
	for _, want := range []string{"source=cowrie", "sensor=cowrie", "since=24h", "q=abc"} {
		if !strings.Contains(got, want) {
			t.Errorf("RowsURL %q is missing %q -- a filter would silently stop applying past the first lazy-loaded page", got, want)
		}
	}
}

// The sandbox/Ghidra/GitHub-analysis "just queued" redirect notice
// (?analysis=queued&hash=...) must not be misread as the ?q= hash-substring
// filter -- they are deliberately different query params (see
// payloadsFilter's own doc comment).
func TestPayloadsFilterDoesNotCollideWithQueuedNoticeHashParam(t *testing.T) {
	r := httptest.NewRequest("GET", "/payloads?analysis=queued&hash="+strings.Repeat("a", 64)+"&target=sandbox", nil)
	f := parsePayloadsFilter(r)
	if f.Hash != "" {
		t.Errorf("parsePayloadsFilter read the queued-notice's hash= as a filter: %+v", f)
	}
}

func TestPayloadsFilterBarPreFillsFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/payloads?sensor=cowrie&since=24h&q=abc&source=dionaea", nil)
	bar := buildFilterBar(r, "/payloads", [2]string{"sensor", "Sensor"}, [2]string{"since", "Since (e.g. 24h)"}, [2]string{"q", "Hash contains"})
	if bar.FilterAction != "/payloads" {
		t.Fatalf("FilterAction = %q, want /payloads", bar.FilterAction)
	}
	names := map[string]string{}
	for _, f := range bar.FilterFields {
		names[f.Name] = f.Value
	}
	if names["sensor"] != "cowrie" || names["since"] != "24h" || names["q"] != "abc" {
		t.Fatalf("filter fields not pre-filled: %+v", bar.FilterFields)
	}
	// source= is the existing chip filter, not one of this filter bar's own
	// fields -- it must round-trip as a hidden field, same reasoning as
	// filter_bar_test.go's page= check.
	foundHidden := false
	for _, h := range bar.FilterHidden {
		if h.Key == "source" && h.Value == "dionaea" {
			foundHidden = true
		}
	}
	if !foundHidden {
		t.Fatalf("expected source=dionaea preserved as a hidden field, got %+v", bar.FilterHidden)
	}
}

// End-to-end through the real template: the filter bar disclosure renders,
// pre-filled, and the lazy-list's remote page URL carries the active filter.
func TestPayloadsPageRendersFilterBarAndCarriesFilterIntoRowsURL(t *testing.T) {
	dir := t.TempDir()
	hash := strings.Repeat("1", 64)
	writeTestPayload(t, dir, hash, time.Now())

	s := &store{payloadDirs: []string{dir}, es: newESClient("http://127.0.0.1:1", "")}
	s.events = []storedEvent{{Shasum: hash, Sensor: "cowrie", when: time.Now()}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	r := httptest.NewRequest("GET", "/payloads?sensor=cowrie", nil)
	page := s.payloadsData(parsePayloadsFilter(r))
	page.filterBar = buildFilterBar(r, "/payloads", [2]string{"sensor", "Sensor"}, [2]string{"since", "Since (e.g. 24h)"}, [2]string{"q", "Hash contains"})
	page.RowsURL = payloadsRowsURL(r)

	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "payloads", &page); err != nil {
		t.Fatalf("payloads page does not render: %v", err)
	}
	html := out.String()

	if !strings.Contains(html, `name="sensor" value="cowrie"`) {
		t.Errorf("sensor filter field not pre-filled in rendered HTML")
	}
	if !strings.Contains(html, `data-hp-page-url="/api/payload-rows?sensor=cowrie"`) {
		t.Errorf("RowsURL in rendered HTML does not carry the active sensor filter: %s", html)
	}
}
