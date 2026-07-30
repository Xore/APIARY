package main

import (
	"bytes"
	"html/template"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

var (
	evidenceTrigger = regexp.MustCompile(`data-hp-evidence="([^"]+)"`)
	evidenceBody    = regexp.MustCompile(`data-hp-evidence-body="([^"]+)"`)
	panelName       = regexp.MustCompile(`data-dashboard-panel="([^"]+)"`)
	tabName         = regexp.MustCompile(`data-dashboard-tab="([^"]+)"`)
)

func keys(matches [][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

func renderSandboxDetail(t *testing.T, windows bool) string {
	t.Helper()
	tmpl, err := template.New("dashboard").Funcs(templateFuncs(nil, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	detail := &sandboxResult{
		Job: "linux-20260730T120000Z-abcdef012345", SHA256: strings.Repeat("a", 64),
		CaptureAvailable: true,
		ChangedFiles:     []string{"/tmp/stage2"},
		Stdout:           "out", Stderr: "err",
		SocketsBefore: []string{"before"}, SocketsAfter: []string{"after"},
		NetworkSummary: sandboxNetwork{
			Packets: 4, Events: []string{"event"}, GuestEvents: []string{"guest"},
			Attempts: []string{"attempt"}, DNSQueries: []string{"drop.example"},
			DNSEvents: []string{"A drop.example"},
		},
	}
	detail.Windows.Detected = windows
	if windows {
		detail.Windows.Exports = []string{"Export"}
		detail.Windows.Warnings = []string{"Warning"}
		detail.Windows.ASCIIStrings = []string{"ascii"}
		detail.Windows.UTF16Strings = []string{"utf16"}
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "sandbox", sandboxPageData{Generated: time.Now(), Detail: detail}); err != nil {
		t.Fatalf("sandbox detail does not render (windows=%v): %v", windows, err)
	}
	return buf.String()
}

// A trigger whose body was renamed or dropped silently does nothing when
// clicked, so the pairing is the invariant worth pinning.
func TestEveryEvidenceTriggerHasABody(t *testing.T) {
	for _, windows := range []bool{false, true} {
		html := renderSandboxDetail(t, windows)
		triggers := keys(evidenceTrigger.FindAllStringSubmatch(html, -1))
		bodies := map[string]bool{}
		for _, key := range keys(evidenceBody.FindAllStringSubmatch(html, -1)) {
			bodies[key] = true
		}
		if len(triggers) == 0 {
			t.Fatalf("windows=%v: sandbox detail offers no evidence viewer at all", windows)
		}
		for _, key := range triggers {
			if !bodies[key] {
				t.Fatalf("windows=%v: evidence trigger %q has no matching body", windows, key)
			}
		}
	}
}

// Tabs only work when every button names a panel that exists, and the page
// must not fall back to one flat wall of cards again.
func TestSandboxDetailIsGroupedIntoTabs(t *testing.T) {
	for _, windows := range []bool{false, true} {
		html := renderSandboxDetail(t, windows)
		tabs := keys(tabName.FindAllStringSubmatch(html, -1))
		panels := map[string]bool{}
		for _, name := range keys(panelName.FindAllStringSubmatch(html, -1)) {
			panels[name] = true
		}
		wantTabs := 4
		if windows {
			wantTabs = 5
		}
		if len(tabs) != wantTabs {
			t.Fatalf("windows=%v: sandbox detail has %d tabs (%v), want %d", windows, len(tabs), tabs, wantTabs)
		}
		for _, tab := range tabs {
			if !panels[tab] {
				t.Fatalf("windows=%v: tab %q has no panel", windows, tab)
			}
		}
		// Exactly one panel starts visible; the rest are hidden until selected,
		// so the page is usable before hp-app.js runs.
		visible := 0
		for _, panel := range strings.Split(html, `role="tabpanel"`)[1:] {
			head, _, _ := strings.Cut(panel, ">")
			if !strings.Contains(head, " hidden") {
				visible++
			}
		}
		if visible != 1 {
			t.Fatalf("windows=%v: %d panels are visible on load, want exactly 1", windows, visible)
		}
	}
}

// The PE tab and its evidence only exist for a Windows sample.
func TestWindowsForensicsAppearOnlyForPESamples(t *testing.T) {
	linux := renderSandboxDetail(t, false)
	for _, absent := range []string{`data-dashboard-tab="file"`, `data-hp-evidence="sb-authenticode"`, "Windows PE forensics"} {
		if strings.Contains(linux, absent) {
			t.Fatalf("a non-PE sample must not render %q", absent)
		}
	}
	windows := renderSandboxDetail(t, true)
	for _, want := range []string{`data-dashboard-tab="file"`, `data-hp-evidence="sb-authenticode"`, "Windows PE forensics"} {
		if !strings.Contains(windows, want) {
			t.Fatalf("a PE sample is missing %q", want)
		}
	}
}
