package main

import (
	"bytes"
	"encoding/json"
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
		SHA256:            strings.Repeat("c", 64),
		ExitStatus:        "ok",
		Functions:         []ghidraFunction{{Address: "0x401000", Name: "sub_401000", Callers: []ghidraXref{{Addr: "0x400f00", Name: "start"}}}},
		FunctionsDeepened: 1,
		Strings:           []string{"evil.example"},
		Imports:           []string{"kernel32.dll!CreateProcessA"},
		FindCrypt:         []ghidraCrypto{{Address: "0x402a10", Constant: "AES Te0", Algorithm: "AES"}},
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
			Citations: &ghidraRevDeckCitations{
				Valid:   []ghidraRevDeckCitation{{Kind: "function", Raw: "[function:0x401000]", Value: "0x401000", Valid: true}},
				Invalid: []ghidraRevDeckCitation{{Kind: "function", Raw: "[function:0xdead]", Value: "0xdead", Valid: false}},
			},
			Warnings: []string{"capped tool budget"},
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
	// Populated with a real report shape (#318/#319): the "report" field is
	// raw JSON, matching what cape-worker.py actually writes -- these
	// nested keys are the ones capeData()'s own parseCapeReportSummary()
	// reads, confirmed live against task 9 in #318's own verification run.
	capeScore := 42.0
	capeTaskID := 9
	capeDetail := &capeResult{
		SHA256: strings.Repeat("c", 64), ExitStatus: "ok",
		RequestedAt: "2026-08-08T17:11:00Z", StartedAt: "2026-08-08T17:11:05Z", CompletedAt: "2026-08-08T17:16:22Z",
		TaskID: &capeTaskID, CapeStatus: "reported", Route: "drop",
		Score: &capeScore, Category: "file",
		Signatures: []capeSignature{{Name: "network_http", Description: "Performs some HTTP requests", Severity: 2}},
		Report: json.RawMessage(`{
			"info": {"machine": {"label": "win11-cape"}, "package": "generic", "route": "drop", "timeout": false, "duration": 317},
			"malscore": 42.0, "malstatus": "malicious",
			"behavior": {
				"summary": {"files": ["C:\\Windows\\Temp\\x.dat"], "keys": ["HKLM\\Software\\x"]},
				"processes": [{"process_id": 1000, "process_name": "sample.exe", "parent_id": 500, "module_path": "C:\\Users\\analyst\\sample.exe", "first_seen": "2026-08-08 17:11:06", "calls": [{"api": "NtOpenKey"}]}]
			},
			"CAPE": {"payloads": [], "configs": []},
			"debug": {"log": "2026-08-08 17:11:06 [root] INFO: analysis running", "errors": []}
		}`),
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
		{"sandbox-vnc", sandboxVNCPageData{SHA256: strings.Repeat("f", 64), BridgeWS: "wss://sandbox-vnc.example.invalid/vnc"}},
		{"ghidra", ghidraPageData{Generated: now, Detail: ghidraDetail}},
		// #1288/#1285/#1286 shell+hydrate: "ghidra" above is now just the
		// skeleton shell -- the real cards/tabs/evidence bodies (and their
		// own risk of an unbalanced tag) only exist in "ghidra-detail-body",
		// rendered separately by the fragment route.
		{"ghidra-detail-body", ghidraPageData{Generated: now, Detail: ghidraDetail}},
		{"ghidra-list", ghidraPageData{Generated: now}},
		{"github-analysis", githubAnalysisPageData{Generated: now, Detail: githubAnalysisDetail}},
		{"github-analysis-list", githubAnalysisPageData{Generated: now}},
		{"cape", capePageData{Generated: now, Detail: capeDetail, Summary: parseCapeReportSummary(capeDetail.Report)}},
		{"cape-list", capePageData{Generated: now}},
		{"payload-analysis", binaryAnalysis{}},
		{"payloads-with-files", payloadsPage{Generated: now, Enabled: true, Files: []capturedFile{{Hash: strings.Repeat("e", 64), Kind: "Binary", Platform: "Linux", MIME: "application/octet-stream", SizeH: "1 KiB", Sources: []string{"dionaea"}}}}},
		{"workbench-results", evidenceResultsPageData{
			Generated: now,
			Workbench: workbenchResultsPageData{
				Generated: now,
				Runs: []workbenchRun{{
					ID: "run_1234567890abcdef", PayloadSHA256: strings.Repeat("e", 64), PayloadKind: "binary",
					RecipeName: "Static first", RecipeRevision: 1, State: "completed", CreatedAt: now,
					Children: []workbenchChild{{AnalyzerID: "deterministic", DisplayName: "Deterministic", State: "completed", UpdatedAt: now, ResultURL: "/payload-analysis/" + strings.Repeat("e", 64)}},
				}},
			},
			Sandbox: sandboxPageData{Generated: now, Detail: sandboxDetail},
			GitHub:  githubAnalysisPageData{Generated: now, Detail: githubAnalysisDetail},
		}},
		{"payload-workbench", workbenchPageData{Generated: now, SHA256: strings.Repeat("e", 64), Classification: payloadKind("binary", "Binary", "Unknown", "binary", "Static", false), Analyzers: workbenchRegistry(payloadKind("binary", "Binary", "Unknown", "binary", "Static", false)), ModelStatus: workbenchModelStatus{Overall: "unavailable", AdvisoryOnly: true}}},
		{"payloads", payloadsPage{Generated: now}},
		{"source-health", snapshot{}},
		{"commands", commandsPage{Generated: now}},
		{"clusters", clustersPage{Generated: now}},
		{"campaigns", campaignsPage{Generated: now}},
		{"ml-anomalies", mlAnomaliesPage{Generated: now, Enabled: true}},
		{"llm-analysis", llmAnalysisPage{Generated: now, Enabled: true, Docs: []llmAnalysisDoc{
			{Timestamp: now.Format(time.RFC3339), DocType: "session", Severity: "high", Confidence: "medium", Summary: "brute-forced ssh then ran whoami", SessionID: "sess-1"},
			{Timestamp: now.Format(time.RFC3339), DocType: "error", ErrorCode: "model_timeout", Error: "ollama request timed out"},
		}}},
		{"alerts", alertsPageData{snapshot: snapshot{}}},
		{"session", sessionShell("sess-1")},
		// #1327/#1328 shell+hydrate: "session" above is now just the
		// skeleton shell -- the real tables and chronological replay only
		// exist in "session-body", rendered separately by the fragment
		// route.
		{"session-body", sessionPage{Generated: now, ID: "sess-1", Total: 1}},
		{"attackers", attackersPage{Generated: now, Selected: &attackerRow{ID: "entity-1"}}},
		// #1327 shell+hydrate: "attackers" above is now just the shell
		// (plus the entity graph/fusion cards, which need only the
		// selected id) -- the identity counts and full entity table only
		// exist in "attackers-body", rendered separately by the fragment
		// route.
		{"attackers-body", attackersPage{Generated: now, Rows: []attackerRow{{ID: "entity-1", Link: "/attackers?id=entity-1"}}, Total: 1, Selected: &attackerRow{ID: "entity-1"}}},
		// #1538: "sensors-populated" exercises both tabs' non-empty branch
		// (session table rows, request table rows, and the <details>
		// preview/headers blocks each row can carry) -- "sensors" (in the
		// pages loop's own name, mapped below) covers the Enabled-but-empty
		// branch of both tabs.
		{"sensors", sensorDetailPage{Generated: now, Enabled: true}},
		{"sensors-populated", sensorDetailPage{Generated: now, Enabled: true,
			Mailoney: []mailoneySession{{
				SessionID: "sess-1", When: now.Format(time.RFC3339), IP: "203.0.113.9", Port: "51000",
				LoggedIn: true, User: "admin", Pass: "hunter2",
				MailFrom: []string{"mail from:<attacker@evil.example>"}, RcptTo: []string{"rcpt to:<victim@example.invalid>"},
				BodySize: 128, Truncated: true, BodyPath: "/data/mail/sess-1.eml", BodyPreview: "Subject: test\r\n\r\nbody",
			}},
			HTTPRequests: []httpHoneypotRequest{{
				When: now.Format(time.RFC3339), IP: "198.51.100.7", Method: "POST", Host: "example.invalid",
				Path: "/wp-login.php", Query: "action=login", UserAgent: "curl/8.0",
				Headers: map[string]string{"x-ja4": "t13d..."}, Body: "log=admin&pwd=hunter2",
				Username: "admin", Password: "hunter2", AuthType: "form", Status: 200, Category: "wordpress",
				Tarpitted: true, TarpitBytes: 4096, TarpitMS: 1500,
			}},
		}},
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
		if name == "cape-list" {
			name = "cape"
		}
		if name == "payloads-with-files" {
			name = "payloads"
		}
		if name == "sensors-populated" {
			name = "sensors"
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
		SHA256:            strings.Repeat("c", 64),
		ExitStatus:        "ok",
		Functions:         []ghidraFunction{{Address: "0x401000", Name: "sub_401000", Callers: []ghidraXref{{Addr: "0x400f00", Name: "start"}}}},
		FunctionsDeepened: 1,
		Strings:           []string{"evil.example"},
		Imports:           []string{"kernel32.dll!CreateProcessA"},
		FindCrypt:         []ghidraCrypto{{Address: "0x402a10", Constant: "AES Te0", Algorithm: "AES"}},
		AITriage:          &ghidraTriage{Workflow: "program_triage", RiskLevel: "high"},
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
		// #1288/#1285/#1286 shell+hydrate: the "ghidra" template is now
		// just the shell (no tabs -- those, and everything else ES-derived,
		// only exist in "ghidra-detail-body", rendered by the fragment
		// route hp-ghidra-report.js fetches client-side).
		{"ghidra-detail-body", "ghidra detail", ghidraPageData{Generated: now, Detail: ghidraDetail}},
		{"github-analysis", "github analysis detail", githubAnalysisPageData{Generated: now, Detail: githubAnalysisDetail}},
		{"payload-analysis", "payload analysis", binaryAnalysis{}},
		{"reports", "reports studio", snapshot{}},
		{"payloads", "captured payloads", payloadsPage{Generated: now}},
		{"workbench-results", "analysis results", evidenceResultsPageData{Generated: now}},
		{"sensors", "sensor detail", sensorDetailPage{Generated: now, Enabled: true}},
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
