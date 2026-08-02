package main

import (
	"bytes"
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Templates are long single-line HTML strings assembled by hand, so an
// unbalanced <div> is easy to introduce and invisible in review: the browser
// silently re-parents everything after it, which quietly breaks descendant
// selectors and the modal containment the theme contract depends on. Balance
// every container element of every rendered page.

var containerTag = regexp.MustCompile(`<(/?)(div|form|section|article|main|aside|header|footer|nav|table|tbody|thead|tr|td|th|ul|ol|li|details|dialog|button|label|select|textarea|pre)\b[^>]*>`)

// voidOrSelfClosing skips tags written as <div …/> (none today) and anything
// inside a comment, which the sandbox and reports pages both use.
var htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

func assertBalanced(t *testing.T, name, html string) {
	t.Helper()
	html = htmlComment.ReplaceAllString(html, "")
	var stack []string
	for _, m := range containerTag.FindAllStringSubmatchIndex(html, -1) {
		closing := html[m[2]:m[3]] == "/"
		tag := strings.ToLower(html[m[4]:m[5]])
		if !closing {
			stack = append(stack, tag)
			continue
		}
		if len(stack) == 0 {
			t.Fatalf("%s: stray closing </%s> at byte %d", name, tag, m[0])
		}
		top := stack[len(stack)-1]
		if top != tag {
			t.Fatalf("%s: </%s> closes an open <%s> at byte %d (context: %s)",
				name, tag, top, m[0], excerpt(html, m[0]))
		}
		stack = stack[:len(stack)-1]
	}
	if len(stack) != 0 {
		t.Fatalf("%s: %d unclosed element(s): %v", name, len(stack), stack)
	}
}

func excerpt(html string, at int) string {
	start := at - 90
	if start < 0 {
		start = 0
	}
	return strings.ReplaceAll(html[start:at], "\n", " ")
}

func TestRenderedPagesHaveBalancedMarkup(t *testing.T) {
	s := searchTestStore(t)
	tmpl, err := template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}

	now := time.Now()
	sandboxDetail := &sandboxResult{Job: "job-1", SHA256: strings.Repeat("a", 64), CaptureAvailable: true}
	windowsDetail := &sandboxResult{Job: "job-2", SHA256: strings.Repeat("b", 64)}
	windowsDetail.Windows.Detected = true
	// Populated rather than zero-valued: several ghidra.html sections only
	// render when their slice is non-empty, and an empty fixture would walk
	// the "no results" branch of every one of them.
	stripped := true
	revdeckSteps := 4
	ghidraDetail := &ghidraResult{
		SHA256:     strings.Repeat("c", 64),
		ExitStatus: "ok",
		Functions:  []ghidraFunction{{Address: "0x401000", Name: "sub_401000"}},
		Strings:    []string{"evil.example"},
		Imports:    []string{"kernel32.dll!CreateProcessA"},
		FindCrypt:  []ghidraCrypto{{Address: "0x402a10", Constant: "AES Te0", Algorithm: "AES"}},
		AITriage: &ghidraTriage{
			Workflow: "program_triage", RiskLevel: "high",
			Behaviors:     []string{"spawns a process"},
			Model:         "qwen3:8b",
			EvidenceShown: "12/312 imports, 200/11482 strings (longest first, deduplicated, >=6 chars), 40/40 functions (largest first)",
		},
		FuzzyHashes: &ghidraFuzzyHashes{SSDeep: "3:stub:stub", TLSH: "T1STUB"},
		Lief: &ghidraLief{
			Format: "ELF", Architecture: "X86_64", Entrypoint: "0x401000", IsPIE: true,
			SectionCount: 1, Sections: []ghidraSection{{Name: ".text", Size: 100}},
			Libraries: []string{"libc.so.6"}, Stripped: &stripped,
		},
		Capa: &ghidraCapa{
			Arch: "amd64", OS: "linux", Format: "elf",
			Capabilities: []ghidraCapability{{Name: "create TCP socket", Namespace: "communication/socket/tcp", Matches: 2}},
			Attack:       []ghidraAttack{{ID: "T1071.001", Tactic: "COMMAND_AND_CONTROL", Technique: "Application Layer Protocol", Subtechnique: "Web Protocols"}},
			MBC:          []ghidraMBC{{ID: "C0001", Objective: "Communication", Behavior: "Socket Communication", Method: "Send Data"}},
		},
		RevDeck: &ghidraRevDeck{
			Workflow: "program_triage", Status: "max_turns", Answer: "This binary looks benign.",
			Steps: &revdeckSteps, ToolCalls: 3,
			Citations: &ghidraRevDeckCitations{Valid: []string{"func@0x401000"}, Invalid: []string{"func@0xdead"}},
			Warnings:  []string{"capped tool budget"},
		},
	}
	// Populated rather than zero-valued, same reasoning as ghidraDetail:
	// every optional field is set so every template branch (scanner table,
	// provenance links, artifacts list) renders instead of its empty state.
	githubAnalysisDetail := &githubAnalysisResult{
		SHA256: strings.Repeat("d", 64), ExitStatus: "ok",
		RequestedAt: "2026-07-31T09:00:00+00:00", StartedAt: "2026-07-31T09:00:05+00:00",
		CompletedAt: "2026-07-31T09:05:00+00:00", RequestedBy: "xore",
		Commit: "0123456789abcdef0123456789abcdef01234567", RunID: 42,
		RunURL:     "https://github.com/Xore/honeypot/actions/runs/42",
		SamplePath: "samples/" + strings.Repeat("d", 64), Family: "mirai",
		Verdict:       &githubAnalysisVerdict{Malicious: 3, Suspicious: 1, Total: 5, Level: "malicious"},
		Scanners:      []githubAnalysisScanner{{Source: "clamav", OK: true, Positives: 1, Total: 1, Permalink: "https://example.invalid/report"}, {Source: "yara", OK: false, Error: "timed out"}},
		YARAAutoRules: []string{"rules/auto/mirai_" + strings.Repeat("d", 8) + ".yar"},
		ReportPDF:     "reports/" + strings.Repeat("d", 64) + ".pdf",
		ExportURL:     "/export/github-analysis/" + strings.Repeat("d", 64),
	}

	pages := []struct {
		name string
		data any
	}{
		{"page", snapshot{}},
		{"events", eventsPage{Generated: now}},
		{"ips", ipsPage{Generated: now}},
		{"search", s.searchData("wp-login", filter{})},
		{"reports", snapshot{}},
		{"sandbox", sandboxPageData{Generated: now, Detail: sandboxDetail}},
		{"sandbox-windows", sandboxPageData{Generated: now, Detail: windowsDetail}},
		{"sandbox-list", sandboxPageData{Generated: now}},
		{"ghidra", ghidraPageData{Generated: now, Detail: ghidraDetail}},
		{"ghidra-list", ghidraPageData{Generated: now}},
		{"github-analysis", githubAnalysisPageData{Generated: now, Detail: githubAnalysisDetail}},
		{"github-analysis-list", githubAnalysisPageData{Generated: now}},
		{"payload-analysis", binaryAnalysis{}},
		{"payload-workbench-index", payloadsPage{Generated: now, Enabled: true, Files: []capturedFile{{Hash: strings.Repeat("e", 64), Kind: "Binary", Platform: "Linux", MIME: "application/octet-stream", SizeH: "1 KiB", Sources: []string{"dionaea"}}}}},
		{"workbench-results", workbenchResultsPageData{
			Generated: now,
			Runs: []workbenchRun{{
				ID: "run_1234567890abcdef", PayloadSHA256: strings.Repeat("e", 64), PayloadKind: "binary",
				RecipeName: "Static first", RecipeRevision: 1, State: "completed", CreatedAt: now,
				Children: []workbenchChild{{AnalyzerID: "deterministic", DisplayName: "Deterministic", State: "completed", UpdatedAt: now, ResultURL: "/payload-analysis/" + strings.Repeat("e", 64)}},
			}},
		}},
		{"payload-workbench", workbenchPageData{Generated: now, SHA256: strings.Repeat("e", 64), Classification: payloadKind("binary", "Binary", "Unknown", "binary", "Static", false), Analyzers: workbenchRegistry(payloadKind("binary", "Binary", "Unknown", "binary", "Static", false)), ModelStatus: workbenchModelStatus{Overall: "unavailable", AdvisoryOnly: true}}},
		{"payloads", payloadsPage{Generated: now}},
		{"source-health", snapshot{}},
		{"commands", commandsPage{Generated: now}},
		{"clusters", clustersPage{Generated: now}},
		{"campaigns", campaignsPage{Generated: now}},
		{"ml-anomalies", mlAnomaliesPage{Generated: now, Enabled: true}},
		{"alerts", snapshot{}},
	}
	for _, page := range pages {
		name := page.name
		// The "-windows"/"-list" suffixes name a *variant* of a page — the
		// same template rendered against data that takes a different branch —
		// so both modes get their markup checked, not just whichever one a
		// zero-valued fixture happens to reach.
		if name == "sandbox-windows" || name == "sandbox-list" {
			name = "sandbox"
		}
		if name == "ghidra-list" {
			name = "ghidra"
		}
		if name == "github-analysis-list" {
			name = "github-analysis"
		}
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, page.data); err != nil {
			t.Fatalf("%s does not render: %v", page.name, err)
		}
		assertBalanced(t, page.name, buf.String())
	}
}

// Every tab must own a panel and vice versa, on every page that groups cards.
func TestTabsAndPanelsAgreeOnEveryPage(t *testing.T) {
	tmpl, err := template.New("dashboard").Funcs(templateFuncs(nil, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	now := time.Now()
	detail := &sandboxResult{Job: "job-1", SHA256: strings.Repeat("a", 64)}
	detail.Windows.Detected = true
	ghidraDetail := &ghidraResult{
		SHA256:     strings.Repeat("c", 64),
		ExitStatus: "ok",
		Functions:  []ghidraFunction{{Address: "0x401000", Name: "sub_401000"}},
		Strings:    []string{"evil.example"},
		Imports:    []string{"kernel32.dll!CreateProcessA"},
		FindCrypt:  []ghidraCrypto{{Address: "0x402a10", Constant: "AES Te0", Algorithm: "AES"}},
		AITriage:   &ghidraTriage{Workflow: "program_triage", RiskLevel: "high"},
	}
	githubAnalysisDetail := &githubAnalysisResult{
		SHA256: strings.Repeat("d", 64), ExitStatus: "ok",
		Verdict:  &githubAnalysisVerdict{Malicious: 3, Total: 5, Level: "malicious"},
		Scanners: []githubAnalysisScanner{{Source: "clamav", OK: true, Positives: 1, Total: 1}},
	}

	for _, page := range []struct {
		template string
		label    string
		data     any
	}{
		{"page", "overview", snapshot{}},
		{"sandbox", "sandbox detail", sandboxPageData{Generated: now, Detail: detail}},
		{"ghidra", "ghidra detail", ghidraPageData{Generated: now, Detail: ghidraDetail}},
		{"github-analysis", "github analysis detail", githubAnalysisPageData{Generated: now, Detail: githubAnalysisDetail}},
		{"payload-analysis", "payload analysis", binaryAnalysis{}},
		{"reports", "reports studio", snapshot{}},
	} {
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, page.template, page.data); err != nil {
			t.Fatalf("%s does not render: %v", page.label, err)
		}
		html := buf.String()
		tabs := map[string]bool{}
		for _, m := range tabName.FindAllStringSubmatch(html, -1) {
			tabs[m[1]] = true
		}
		panels := map[string]bool{}
		for _, m := range panelName.FindAllStringSubmatch(html, -1) {
			panels[m[1]] = true
		}
		if len(tabs) == 0 {
			t.Fatalf("%s renders no tabs", page.label)
		}
		if diff := symmetricDifference(tabs, panels); diff != "" {
			t.Fatalf("%s: %s", page.label, diff)
		}
	}
}

func symmetricDifference(tabs, panels map[string]bool) string {
	var problems []string
	for tab := range tabs {
		if !panels[tab] {
			problems = append(problems, fmt.Sprintf("tab %q has no panel", tab))
		}
	}
	for panel := range panels {
		if !tabs[panel] {
			problems = append(problems, fmt.Sprintf("panel %q has no tab", panel))
		}
	}
	return strings.Join(problems, "; ")
}
