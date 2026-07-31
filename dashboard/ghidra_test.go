package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeGhidraResult(t *testing.T, dir, sha string, row map[string]any) {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sha+"_ghidra.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

const shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// A return path that leaves the dashboard must never be honored. "//evil" is
// the case a bare strings.HasPrefix(raw, "/") check lets through, which is
// exactly why safeReturnPath exists and is shared with sandbox submission.
func TestGhidraReturnURLRejectsOffsiteRedirects(t *testing.T) {
	for _, raw := range []string{
		"//evil.example/path",
		"https://evil.example/",
		"http://evil.example/payloads",
		"/etc/passwd",
		"/admin",
		"javascript:alert(1)",
		"",
		"   ",
	} {
		got := ghidraReturnURL(raw, shaA)
		if !strings.HasPrefix(got, "/payloads?") {
			t.Errorf("ghidraReturnURL(%q) = %q, want the /payloads fallback", raw, got)
		}
		if strings.Contains(got, "evil.example") {
			t.Errorf("ghidraReturnURL(%q) leaked an offsite host: %q", raw, got)
		}
	}
}

func TestGhidraReturnURLKeepsAllowedPaths(t *testing.T) {
	got := ghidraReturnURL("/ghidra/"+shaA, shaA)
	if !strings.HasPrefix(got, "/ghidra/"+shaA) {
		t.Fatalf("allowed path was not preserved: %q", got)
	}
	for _, want := range []string{"analysis=queued", "hash=" + shaA, "target=ghidra"} {
		if !strings.Contains(got, want) {
			t.Errorf("return URL %q is missing %q", got, want)
		}
	}
}

// The same guard backs sandbox submission; assert it directly so a future
// change to one caller cannot quietly weaken the other.
func TestSafeReturnPathAllowlist(t *testing.T) {
	if _, ok := safeReturnPath("/payloads", []string{"/payloads"}); !ok {
		t.Error("allowlisted prefix was rejected")
	}
	if _, ok := safeReturnPath("/payloads", []string{"/sandbox/"}); ok {
		t.Error("path outside the allowlist was accepted")
	}
	if _, ok := safeReturnPath("//evil.example", []string{"/"}); ok {
		t.Error("protocol-relative URL was accepted")
	}
}

func TestLoadGhidraResults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)

	writeGhidraResult(t, dir, shaA, map[string]any{
		"version": 1, "exit_status": "ok", "completed_at": "2026-07-31T10:00:00+00:00",
		"imports": []string{"kernel32.dll!CreateProcessA"},
	})
	writeGhidraResult(t, dir, shaB, map[string]any{
		"version": 1, "exit_status": "error", "error": "boom",
		"completed_at": "2026-07-31T12:00:00+00:00",
	})
	// Malformed JSON must not hide the valid results alongside it.
	if err := os.WriteFile(filepath.Join(dir, "c"+strings.Repeat("c", 63)+"_ghidra.json"),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-result file in the same directory must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	rows := loadGhidraResults()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// Newest first.
	if rows[0].SHA256 != shaB {
		t.Errorf("rows are not newest-first: got %s first", rows[0].SHA256[:8])
	}
	// A failed analysis is still a visible result, with its reason.
	if rows[0].ExitStatus != "error" || rows[0].Error != "boom" {
		t.Errorf("failed result lost its status/reason: %+v", rows[0])
	}
}

// Identity comes from the filename, which the worker derived from a validated
// request — not from the document body, which could disagree with it.
func TestLoadGhidraResultsTrustsFilenameOverBody(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	writeGhidraResult(t, dir, shaA, map[string]any{"sha256": shaB, "exit_status": "ok"})

	rows := loadGhidraResults()
	if len(rows) != 1 || rows[0].SHA256 != shaA {
		t.Fatalf("body sha256 overrode the filename: %+v", rows)
	}
}

func TestLoadGhidraStatus(t *testing.T) {
	t.Run("unconfigured", func(t *testing.T) {
		t.Setenv("GHIDRA_RESULTS_DIR", "")
		if s := loadGhidraStatus(); s.Configured {
			t.Error("unset results dir should report Configured=false")
		}
	})

	t.Run("configured but never run", func(t *testing.T) {
		t.Setenv("GHIDRA_RESULTS_DIR", t.TempDir())
		s := loadGhidraStatus()
		// "Nothing queued" and "nothing is running" look identical without
		// this, and they mean very different things.
		if !s.Configured || !s.Stale {
			t.Errorf("missing status.json should be Configured+Stale, got %+v", s)
		}
	})

	t.Run("fresh status", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GHIDRA_RESULTS_DIR", dir)
		raw := `{"version":1,"queued":2,"running":1,"failed":0,"done":5}`
		if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		s := loadGhidraStatus()
		if s.Queued != 2 || s.Running != 1 || s.Done != 5 {
			t.Errorf("counts not parsed: %+v", s)
		}
		if s.Stale {
			t.Error("a just-written status.json should not be stale")
		}
	})

	t.Run("stale status", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GHIDRA_RESULTS_DIR", dir)
		path := filepath.Join(dir, "status.json")
		if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * ghidraStatusStaleAfter)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		if s := loadGhidraStatus(); !s.Stale {
			t.Error("an old status.json should be reported stale")
		}
	})
}

// The worker writes report_pdf, but it lands in a filesystem path, so it is
// re-validated as a bare filename regardless of who produced it.
func TestAttachGhidraDownloadRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../secret", "../../etc/passwd", "sub/dir.pdf"} {
		row := ghidraResult{SHA256: shaA, ReportPDF: bad}
		attachGhidraDownload(&row)
		if row.ExportURL != "" {
			t.Errorf("traversal %q produced an export URL", bad)
		}
	}
}

func TestServeGhidraExportRejectsBadHash(t *testing.T) {
	t.Setenv("GHIDRA_RESULTS_DIR", t.TempDir())
	for _, path := range []string{
		"/export/ghidra/../../etc/passwd",
		"/export/ghidra/not-a-hash",
		"/export/ghidra/",
	} {
		w := httptest.NewRecorder()
		serveGhidraExport(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, w.Code)
		}
	}
}

// Until phase 5 generates PDFs there is nothing to export; that must be a
// clear 404, not a zero-byte download.
func TestServeGhidraExportWithoutReport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	writeGhidraResult(t, dir, shaA, map[string]any{"exit_status": "ok"})

	w := httptest.NewRecorder()
	serveGhidraExport(w, httptest.NewRequest(http.MethodGet, "/export/ghidra/"+shaA, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

func TestServeGhidraAPI(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	writeGhidraResult(t, dir, shaA, map[string]any{
		"exit_status": "ok", "imports": []string{"ws2_32.dll!connect"},
	})

	t.Run("list", func(t *testing.T) {
		w := httptest.NewRecorder()
		serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra", nil))
		var rows []ghidraResult
		if err := json.NewDecoder(w.Body).Decode(&rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].SHA256 != shaA {
			t.Fatalf("unexpected list payload: %+v", rows)
		}
	})

	t.Run("detail", func(t *testing.T) {
		w := httptest.NewRecorder()
		serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra/"+shaA, nil))
		var row ghidraResult
		if err := json.NewDecoder(w.Body).Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row.SHA256 != shaA {
			t.Fatalf("unexpected detail payload: %+v", row)
		}
	})

	t.Run("unknown hash is 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra/"+shaB, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("got %d, want 404", w.Code)
		}
	})

	t.Run("malformed hash is 404, not a directory read", func(t *testing.T) {
		w := httptest.NewRecorder()
		serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra/../../etc", nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("got %d, want 404", w.Code)
		}
	})

	t.Run("status", func(t *testing.T) {
		w := httptest.NewRecorder()
		serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra/status", nil))
		var s ghidraQueueStatus
		if err := json.NewDecoder(w.Body).Decode(&s); err != nil {
			t.Fatal(err)
		}
		if !s.Configured {
			t.Error("status should report Configured with a results dir set")
		}
	})
}

// Search must not match on the string table: nearly every binary contains
// nearly every short substring, which would make the filter useless.
func TestGhidraDataQueryIgnoresStrings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	writeGhidraResult(t, dir, shaA, map[string]any{
		"exit_status": "ok",
		"strings":     []string{"needle"},
		"imports":     []string{"ws2_32.dll!connect"},
	})

	data, err := ghidraData("", "needle")
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 0 {
		t.Errorf("query matched the string table: %+v", data.Rows)
	}

	data, err = ghidraData("", "ws2_32")
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 1 {
		t.Errorf("query did not match imports: %+v", data.Rows)
	}
}

func ghidraAlertMessages(t *testing.T, dir string) []string {
	t.Helper()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	var messages []string
	// s.alerts nil means "no dedupe sink configured", which makes every check
	// emit — exactly what a unit test wants.
	ghidraAlerts(&store{}, &messages, false)
	return messages
}

func hasAlert(messages []string, substr string) bool {
	for _, m := range messages {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

// An unconfigured host has not opted into Ghidra at all; alerting about a
// subsystem nobody deployed is pure noise.
func TestGhidraAlertsSilentWhenUnconfigured(t *testing.T) {
	t.Setenv("GHIDRA_RESULTS_DIR", "")
	var messages []string
	ghidraAlerts(&store{}, &messages, false)
	if len(messages) != 0 {
		t.Fatalf("unconfigured host produced alerts: %v", messages)
	}
}

func TestGhidraAlertsOnStaleWorker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"queued":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * ghidraStatusStaleAfter)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	messages := ghidraAlertMessages(t, dir)
	if !hasAlert(messages, "not draining") {
		t.Fatalf("no stale-worker alert: %v", messages)
	}
	// The queue depth belongs in the message; "the worker is stuck" without it
	// does not tell the reader whether anything is actually waiting.
	if !hasAlert(messages, "3 queued") {
		t.Errorf("stale alert omits the queue depth: %v", messages)
	}
}

func TestGhidraAlertsOnFailedResult(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"),
		[]byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeGhidraResult(t, dir, shaA, map[string]any{
		"exit_status": "error", "error": "analysis exceeded 4200s",
	})
	messages := ghidraAlertMessages(t, dir)
	if !hasAlert(messages, "analysis failed") || !hasAlert(messages, "exceeded 4200s") {
		t.Fatalf("failed result did not alert with its reason: %v", messages)
	}
}

// Crypto constants alone must not page: a stock AES table is in a great deal
// of benign software, and an alert people learn to ignore is worse than none.
func TestGhidraCryptoAloneDoesNotAlertByDefault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"),
		[]byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeGhidraResult(t, dir, shaA, map[string]any{
		"exit_status": "ok",
		"findcrypt":   []map[string]string{{"address": "0x1", "constant": "AES Te0", "algorithm": "AES"}},
	})

	if messages := ghidraAlertMessages(t, dir); hasAlert(messages, "flagged") {
		t.Fatalf("crypto alone alerted with the default config: %v", messages)
	}

	t.Setenv("GHIDRA_ALERT_ON_CRYPTO", "true")
	if messages := ghidraAlertMessages(t, dir); !hasAlert(messages, "flagged") {
		t.Fatalf("opting in did not enable the crypto alert: %v", messages)
	}
}

func TestGhidraAlertsOnHighAIRisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"),
		[]byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeGhidraResult(t, dir, shaA, map[string]any{
		"exit_status": "ok",
		"ai_triage":   map[string]any{"risk_level": "high", "model": "qwen3:8b"},
	})
	messages := ghidraAlertMessages(t, dir)
	if !hasAlert(messages, "flagged") {
		t.Fatalf("high AI risk did not alert: %v", messages)
	}
	// The reader must be told this is a model's guess, in the alert itself —
	// the detail page's disclaimer is not visible from a webhook.
	if !hasAlert(messages, "UNVERIFIED") {
		t.Errorf("AI-risk alert does not mark itself unverified: %v", messages)
	}

	// A level outside the configured set stays quiet.
	t.Setenv("GHIDRA_ALERT_RISK_LEVELS", "critical")
	if messages := ghidraAlertMessages(t, dir); hasAlert(messages, "flagged") {
		t.Errorf("risk level outside the configured set alerted: %v", messages)
	}
}

// The call-graph SVG carries function names recovered from the sample, so the
// filename is re-validated even though the worker produced it.
func TestAttachGhidraCallGraphRejectsBadNames(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "secret.svg"), []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../secret.svg", "sub/x.svg", "notsvg.txt", "../../etc/passwd"} {
		row := ghidraResult{SHA256: shaA, CallGraphSVG: bad}
		attachGhidraCallGraph(&row)
		if row.CallGraphURL != "" {
			t.Errorf("%q produced a call-graph URL", bad)
		}
	}
}

func TestServeGhidraCallGraph(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><text>f</text></svg>`
	if err := os.WriteFile(filepath.Join(dir, shaA+"_callgraph.svg"), []byte(svg), 0o600); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	serveGhidraExport(w, httptest.NewRequest(http.MethodGet,
		"/export/ghidra/"+shaA+"/callgraph.svg", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("Content-Type = %q", ct)
	}
	// Attacker-influenced content rendered as a document: the CSP and nosniff
	// headers are the reason navigating straight to this URL is not a script
	// execution path.
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("missing restrictive CSP, got %q", csp)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}

	// A hash with no rendered graph must 404, not serve someone else's file.
	w = httptest.NewRecorder()
	serveGhidraExport(w, httptest.NewRequest(http.MethodGet,
		"/export/ghidra/"+shaB+"/callgraph.svg", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("missing graph: got %d, want 404", w.Code)
	}

	// Traversal in the hash position must not escape the results directory.
	w = httptest.NewRecorder()
	serveGhidraExport(w, httptest.NewRequest(http.MethodGet,
		"/export/ghidra/../../etc/passwd/callgraph.svg", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("traversal: got %d, want 404", w.Code)
	}
}
