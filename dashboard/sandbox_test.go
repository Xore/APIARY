package main

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSandboxResultsAreBoundedAndValidated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	valid := `{"version":1,"job":"linux-test","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","completed_at":"2026-01-01T00:00:00Z","stdout":"<script>"}`
	if err := os.WriteFile(filepath.Join(dir, "linux-test.json"), []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	windows := `{"version":2,"job":"windows-test","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","completed_at":"2026-01-02T00:00:00Z","windows_forensics":{"detected":true,"execution_mode":"wine","pe_type":"PE32+","imphash":"test"},"network_summary":{"dns_queries":["raw.githubusercontent.com"],"guest_packets":12}}`
	if err := os.WriteFile(filepath.Join(dir, "windows-test.json"), []byte(windows), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "linux-invalid.json"), []byte(`{"job":"bad","sha256":"../escape"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	failed := `{"version":2,"job":"linux-timeout","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","completed_at":"2026-01-03T00:00:00Z","exit_status":"unknown","timeout_reason":"host deadline","risk_score":20,"risk_level":"low"}`
	if err := os.WriteFile(filepath.Join(dir, "linux-timeout.json"), []byte(failed), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := loadSandboxResults()
	if len(rows) != 3 || rows[0].Job != "linux-timeout" || !rows[0].Incomplete ||
		rows[0].RunStatus != "failed" || rows[0].FailureReason == "" ||
		rows[0].ExitStatus != "host-timeout" || rows[0].RiskScore != 0 || rows[0].RiskLevel != "unrated" ||
		rows[1].Job != "windows-test" || !rows[1].Windows.Detected ||
		rows[1].Windows.ExecutionMode != "wine" || len(rows[1].NetworkSummary.DNSQueries) != 1 ||
		rows[2].Job != "linux-test" || rows[2].Stdout != "<script>" {
		t.Fatalf("unexpected sandbox rows: %#v", rows)
	}
	data, err := sandboxData("linux-test", "")
	if err != nil || data.Detail == nil {
		t.Fatalf("detail lookup failed: %v", err)
	}
	filtered, err := sandboxData("", "does-not-match")
	if err != nil || len(filtered.Rows) != 0 {
		t.Fatalf("sandbox search was not applied: %#v %v", filtered.Rows, err)
	}
}

// sandboxArtifactFile is the choke point for two CodeQL go/path-injection
// alerts (#4, #21): https://github.com/Xore/apiary/issues/80. The
// property has to hold at the join itself, not be argued from the callers
// three frames away.
func TestSandboxArtifactFileRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.pcap")
	if err := os.WriteFile(secret, []byte("do-not-serve"), 0o600); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"../" + filepath.Base(outside) + "/secret.pcap",
		rel,
		"..",
		"sub/../../escape",
		"/" + secret,
	} {
		if _, _, ok := sandboxArtifactFile(name); ok {
			t.Fatalf("sandboxArtifactFile(%q) resolved outside the results directory", name)
		}
	}

	legit := filepath.Join(dir, "linux-test.host.pcap")
	if err := os.WriteFile(legit, []byte("pcap"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := sandboxArtifactFile("linux-test.host.pcap"); !ok {
		t.Fatal("sandboxArtifactFile rejected a legitimate basename")
	}
}

func TestSandboxStatusAndTemplate(t *testing.T) {
	dir := t.TempDir()
	requests := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	t.Setenv("SANDBOX_REQUEST_DIR", requests)
	status := `{"updated_at":"2026-01-01T00:00:00Z","worker_state":"idle","counts":{"queued":2,"running":0,"completed":4,"failed":1},"jobs":[]}`
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded := loadSandboxStatus()
	if loaded.WorkerState != "idle" || loaded.Counts.Queued != 2 || loaded.Counts.Failed != 1 {
		t.Fatalf("unexpected status: %#v", loaded)
	}
	hash := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(requests, hash+".request"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded = loadSandboxStatus(); loaded.Handoff != 1 {
		t.Fatalf("handoff=%d want=1", loaded.Handoff)
	}
	funcs := templateFuncs(nil, "")
	if _, err := template.New("dashboard").Funcs(funcs).Parse(pageTemplate); err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
}

// The Windows guest writes to its own spool and its own export directory. The
// sandbox page is a single list, so both have to merge into one view without
// either backend's absence breaking the other's.
func TestSandboxMergesBothBackends(t *testing.T) {
	linuxResults, windowsResults := t.TempDir(), t.TempDir()
	linuxRequests, windowsRequests := t.TempDir(), t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", linuxResults)
	t.Setenv("WINDOWS_SANDBOX_RESULTS_DIR", windowsResults)
	t.Setenv("SANDBOX_REQUEST_DIR", linuxRequests)
	t.Setenv("WINDOWS_SANDBOX_REQUEST_DIR", windowsRequests)

	write := func(dir, name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(linuxResults, "linux-a.json",
		`{"version":2,"job":"linux-a","sha256":"`+strings.Repeat("a", 64)+`","completed_at":"2026-01-01T00:00:00Z","platform":"Linux"}`)
	write(windowsResults, "windows-b.json",
		`{"version":2,"job":"windows-b","sha256":"`+strings.Repeat("b", 64)+`","completed_at":"2026-01-02T00:00:00Z","platform":"Windows"}`)

	rows := loadSandboxResults()
	if len(rows) != 2 || rows[0].Job != "windows-b" || rows[1].Job != "linux-a" {
		t.Fatalf("results did not merge in completion order: %#v", rows)
	}
	if _, err := sandboxData("windows-b", ""); err != nil {
		t.Fatalf("a Windows run is not reachable by job id: %v", err)
	}

	// A Windows worker that is configured but has never run has no status
	// file. Reporting the whole queue as unavailable because of that would
	// call a healthy Linux stack broken.
	write(linuxResults, "status.json",
		`{"updated_at":"2026-01-01T00:00:00Z","worker_state":"idle","counts":{"queued":1,"running":0,"completed":2,"failed":0},"jobs":[]}`)
	if got := loadSandboxStatus(); got.WorkerState != "idle" || got.Counts.Completed != 2 {
		t.Fatalf("a missing Windows status poisoned the merge: %#v", got)
	}

	write(windowsResults, "status.json",
		`{"updated_at":"2026-01-02T00:00:00Z","worker_state":"running","counts":{"queued":3,"running":1,"completed":5,"failed":2},"jobs":[]}`)
	got := loadSandboxStatus()
	if got.Counts.Queued != 4 || got.Counts.Completed != 7 || got.Counts.Failed != 2 {
		t.Fatalf("counts did not sum across backends: %#v", got.Counts)
	}
	// The Windows file claims "running" but its timestamp is far in the past,
	// so the per-backend staleness check demotes it before the merge, and the
	// merge then prefers it over the healthy Linux "idle". Both halves matter:
	// a wedged backend must not hide behind a working one.
	if got.WorkerState != "stale" {
		t.Fatalf("worker_state=%q, want the degraded backend's state to win", got.WorkerState)
	}
	if got.UpdatedAt != "2026-01-02T00:00:00Z" {
		t.Fatalf("updated_at=%q, want the most recent report", got.UpdatedAt)
	}

	// Both spools feed one handoff count, so a backlog on either one is
	// visible on the page.
	write(linuxRequests, strings.Repeat("a", 64)+".request", "")
	write(windowsRequests, strings.Repeat("b", 64)+".request", "")
	if got = loadSandboxStatus(); got.Handoff != 2 {
		t.Fatalf("handoff=%d, want both spools counted", got.Handoff)
	}
}

// Exports resolve per artifact rather than from a single directory, or every
// Windows run's PCAP and diagnostics bundle would 404.
func TestSandboxExportsResolveAcrossBackends(t *testing.T) {
	linuxResults, windowsResults := t.TempDir(), t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", linuxResults)
	t.Setenv("WINDOWS_SANDBOX_RESULTS_DIR", windowsResults)
	body := `{"version":2,"job":"windows-c","sha256":"` + strings.Repeat("c", 64) + `","completed_at":"2026-01-03T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(windowsResults, "windows-c.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pcap := append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, make([]byte, 64)...)
	if err := os.WriteFile(filepath.Join(windowsResults, "windows-c.host.pcap"), pcap, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := sandboxData("windows-c", "")
	if err != nil || data.Detail == nil {
		t.Fatalf("detail lookup failed: %v", err)
	}
	if data.Detail.HostPCAPURL != "/export/sandbox/windows-c.host.pcap" || data.Detail.HostPCAPSize != int64(len(pcap)) {
		t.Fatalf("host PCAP was not found in the Windows results directory: %#v", data.Detail)
	}
}

// The sandbox results list renders as a .project-grid/.project-card grid
// (#227, following #221/#226), not the old <table>. Each card links
// straight to /sandbox/{job} -- the same destination the old "investigate"
// link used, not the hash cell's /payload-analysis/ link.
func TestSandboxResultsPageRendersAsCardGrid(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	shaOK := strings.Repeat("e", 64)
	data := sandboxPageData{
		Generated: time.Now(),
		Rows: []sandboxResult{
			{
				Job: "job-1", SHA256: shaOK, Source: "dionaea", CompletedAt: "2026-08-01T10:00:00Z",
				RiskScore: 80, RiskLevel: "high", Duration: 42.5, ExitStatus: "ok",
				NetworkSummary: sandboxNetwork{Packets: 12},
			},
			{
				Job: "job-2", SHA256: strings.Repeat("f", 64), Source: "cowrie", CompletedAt: "2026-08-01T09:00:00Z",
				ExitStatus: "error",
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "sandbox", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if strings.Contains(body, `id="sandbox-results"><p`) && strings.Contains(body, "<table") {
		t.Fatal("sandbox results still render as a table, want a card grid")
	}
	if !strings.Contains(body, "project-grid") || !strings.Contains(body, "project-card") {
		t.Fatal("sandbox results are missing the .project-grid/.project-card markup")
	}
	if !strings.Contains(body, `href="/sandbox/job-1"`) {
		t.Fatalf("card for %s does not link to /sandbox/job-1", shaOK)
	}
	if strings.Contains(body, `href="/payload-analysis/`+shaOK+`"`) {
		t.Fatal("sandbox card should no longer link the hash to /payload-analysis/ -- that is a click away from the detail page")
	}
	if !strings.Contains(body, ">error<") {
		t.Fatal("exit-status badge for the failed run is missing")
	}
}
