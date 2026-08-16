package main

import (
	"html/template"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad test prefix %q: %v", s, err)
	}
	return p
}

// #244 acceptance: a synthetic fixture with deliberately overlapping
// categories must resolve to the highest-severity label, not file order.
func TestGeoDBIntelLookupPrioritizesSeverityOverFileOrder(t *testing.T) {
	g := &geoDB{intel: []intelPrefix{
		// Listed benign-first on purpose -- if lookup ever regresses to
		// first-match-wins, this ordering would surface it immediately.
		{mustPrefix(t, "203.0.113.0/24"), "cloud:aws"},
		{mustPrefix(t, "203.0.113.0/28"), "tor-exit"},
		{mustPrefix(t, "203.0.113.0/32"), "blocklist:spamhaus"},
	}}
	if got := g.lookup("203.0.113.0").Intel; got != "blocklist:spamhaus" {
		t.Errorf("Intel = %q, want blocklist:spamhaus (highest severity)", got)
	}
	// An address only inside the two broader ranges (not the /32) must fall
	// back to the next-highest severity present, not the least specific.
	if got := g.lookup("203.0.113.5").Intel; got != "tor-exit" {
		t.Errorf("Intel = %q, want tor-exit", got)
	}
	// An address only inside the broadest range gets the only label that
	// covers it.
	if got := g.lookup("203.0.113.99").Intel; got != "cloud:aws" {
		t.Errorf("Intel = %q, want cloud:aws", got)
	}
	// No matching prefix at all.
	if got := g.lookup("198.51.100.1").Intel; got != "" {
		t.Errorf("Intel = %q, want empty for an address outside every range", got)
	}
}

// On an exact tie in severity, the more specific prefix wins -- ordinary
// CIDR routing semantics, not first-in-file.
func TestGeoDBIntelLookupTiesBreakOnSpecificity(t *testing.T) {
	g := &geoDB{intel: []intelPrefix{
		{mustPrefix(t, "192.0.2.0/24"), "blocklist:firehol"},
		{mustPrefix(t, "192.0.2.128/25"), "blocklist:spamhaus"},
	}}
	if got := g.lookup("192.0.2.200").Intel; got != "blocklist:spamhaus" {
		t.Errorf("Intel = %q, want the more specific blocklist:spamhaus", got)
	}
	if got := g.lookup("192.0.2.5").Intel; got != "blocklist:firehol" {
		t.Errorf("Intel = %q, want blocklist:firehol (only the broader range covers this address)", got)
	}
}

func TestIntelCategoryRank(t *testing.T) {
	cases := map[string]int{
		"blocklist:spamhaus": 2,
		"blocklist:firehol":  2,
		"tor-exit":           1,
		"cloud:aws":          0,
		"cloud:gcp":          0,
		"scanner":            0,
		"":                   0,
	}
	for label, want := range cases {
		if got := intelCategoryRank(label); got != want {
			t.Errorf("intelCategoryRank(%q) = %d, want %d", label, got, want)
		}
	}
}

func TestIntelBadgeClass(t *testing.T) {
	cases := map[string]string{
		"blocklist:spamhaus": "badge--danger",
		"blocklist:firehol":  "badge--danger",
		"tor-exit":           "badge--warning",
		"cloud:aws":          "badge--muted",
		"scanner":            "badge--muted",
		"":                   "badge--muted",
	}
	for label, want := range cases {
		if got := intelBadgeClass(label); got != want {
			t.Errorf("intelBadgeClass(%q) = %q, want %q", label, got, want)
		}
	}
}

func TestLoadIntelCIDRsParsesCIDRLabelPairs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "threat-cidrs.csv")
	content := "# comment\n192.0.2.0/24,blocklist:spamhaus\nbad-line\n198.51.100.5/32,tor-exit\n\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadIntelCIDRs(path)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].label != "blocklist:spamhaus" || got[1].label != "tor-exit" {
		t.Errorf("unexpected labels: %+v", got)
	}
}

func TestLoadIntelCIDRsEmptyPath(t *testing.T) {
	if got := loadIntelCIDRs(""); got != nil {
		t.Errorf("empty path should return nil, got %+v", got)
	}
}

// #244: a scheduled refresh-threat-cidrs.sh run must reach the running
// dashboard without a restart.
func TestReloadIntelIfChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "threat-cidrs.csv")
	if err := os.WriteFile(path, []byte("192.0.2.0/24,blocklist:spamhaus\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &geoDB{intelPath: path}
	g.reloadIntelIfChanged()
	if len(g.intel) != 1 || g.intel[0].label != "blocklist:spamhaus" {
		t.Fatalf("initial load failed: %+v", g.intel)
	}

	// Unchanged mtime: a second call must be a no-op.
	before := g.intel
	g.reloadIntelIfChanged()
	if len(g.intel) != len(before) {
		t.Error("reload ran again despite an unchanged mtime")
	}

	// A real change, with an mtime that has actually moved forward.
	newer := time.Now().Add(time.Minute)
	if err := os.WriteFile(path, []byte("192.0.2.0/24,blocklist:spamhaus\n203.0.113.0/24,tor-exit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, newer, newer); err != nil {
		t.Fatal(err)
	}
	g.reloadIntelIfChanged()
	if len(g.intel) != 2 {
		t.Fatalf("reload did not pick up the new entry: %+v", g.intel)
	}
}

func TestReloadIntelIfChangedNoopWithoutPath(t *testing.T) {
	g := &geoDB{}
	g.reloadIntelIfChanged() // must not panic
	if g.intel != nil {
		t.Error("no intelPath configured should never populate intel")
	}
}

// #244: events.html must actually render the severity-styled badge, not
// just carry the plain .lnk it used before -- a struct-level assertion on
// storedEvent.Intel alone wouldn't catch a template that never adopted
// intelBadgeClass.
func TestEventsPageRendersIntelSeverityBadge(t *testing.T) {
	s := &store{}
	s.events = []storedEvent{
		{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9", Intel: "blocklist:spamhaus"},
		{Time: "2026-08-01 10:01", Sensor: "cowrie", SrcIP: "203.0.113.10", Intel: "tor-exit"},
		{Time: "2026-08-01 10:02", Sensor: "cowrie", SrcIP: "203.0.113.11", Provider: "cloud"},
	}
	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	page := s.eventsData(httptest.NewRequest("GET", "/events", nil))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "events", &page); err != nil {
		t.Fatalf("events page does not render: %v", err)
	}
	html := out.String()

	if !strings.Contains(html, `class="badge badge--danger" href="/events?provider=blocklist%3Aspamhaus"`) {
		t.Error("blocklist Intel did not render as a badge--danger badge")
	}
	if !strings.Contains(html, `class="badge badge--warning" href="/events?provider=tor-exit"`) {
		t.Error("tor-exit Intel did not render as a badge--warning badge")
	}
	if !strings.Contains(html, `class="badge badge--muted" href="/events?provider=cloud"`) {
		t.Error("a Provider-only classification did not render as a badge--muted badge")
	}
}
