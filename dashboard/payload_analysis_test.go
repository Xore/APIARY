package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPayloadAnalysisShellDoesNoFileAnalysis (#1157): even measured against
// a small file (nothing here needs a multi-megabyte sample to prove the
// point -- the live measurement that motivated this fix, 567ms against a
// real 5.26MB captured DLL, is in analyzePayloadFast's own comment),
// payloadAnalysisShell must return with every file-bytes-derived field left
// zero-valued. analyzePayloadFast populates every one of these from the
// same file; if payloadAnalysisShell ever starts doing the same work, this
// regresses back to the exact bug this issue fixes (main.go's route handler
// blocking on file analysis before it can write anything to the browser).
func TestPayloadAnalysisShellDoesNoFileAnalysis(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("a", 64)
	content := []byte("MZ fake PE content, irrelevant -- the shell must never read this")
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{payloadDirs: []string{dir}}
	shell, err := s.payloadAnalysisShell(name)
	if err != nil {
		t.Fatalf("payloadAnalysisShell: %v", err)
	}
	if shell.Hash != name {
		t.Fatalf("shell.Hash = %q, want %q", shell.Hash, name)
	}
	for field, got := range map[string]string{
		"SHA256": shell.SHA256, "MD5": shell.MD5, "SHA1": shell.SHA1,
		"MIME": shell.MIME, "Magic": shell.Magic, "Size": shell.Size,
		"Entropy": shell.Entropy, "Hexdump": shell.Hexdump, "RiskLevel": shell.RiskLevel,
	} {
		if got != "" {
			t.Fatalf("payloadAnalysisShell populated %s = %q -- the shell must stay zero-valued; that field belongs to servePayloadStaticAnalysis's async hydration instead", field, got)
		}
	}
	if shell.RiskScore != 0 || len(shell.ASCII) != 0 || len(shell.UTF16) != 0 || len(shell.IOCs) != 0 || len(shell.YARAMatches) != 0 {
		t.Fatalf("payloadAnalysisShell populated slice/score fields it must leave zero: %+v", shell)
	}

	// An invalid or unresolvable hash must still fail exactly like
	// analyzePayloadFast's own equivalent checks -- the shell keeps that
	// validation, it only drops the file-bytes work after it.
	if _, err := s.payloadAnalysisShell(strings.Repeat("f", 64)); err == nil {
		t.Fatal("payloadAnalysisShell for a hash matching no file should fail, not silently succeed")
	}
	if _, err := s.payloadAnalysisShell("not-a-hash"); err == nil {
		t.Fatal("payloadAnalysisShell for a malformed hash should fail")
	}
}

// TestPayloadAnalysisPageRendersShellSkeletonForEveryHydratedField (#1157):
// the initial /payload-analysis/<hash> render (payloadAnalysisShell's
// output through the "payload-analysis" template) must show skeleton
// placeholders for every field servePayloadStaticAnalysis now hydrates
// in asynchronously, and must not render any real analysis content -- a
// blank binaryAnalysis rendered directly is exactly what the shell
// produces, so this doubles as proof the page never leaks stale zero
// values (e.g. "risk score 0/100") in place of a loading state.
func TestPayloadAnalysisPageRendersShellSkeletonForEveryHydratedField(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	shell := binaryAnalysis{Hash: shaA}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "payload-analysis", &shell); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if !strings.Contains(body, "skeleton") {
		t.Fatal("shell render must show skeleton placeholders while static analysis is still loading")
	}
	// The old direct-render fields must not leak zero values in place of a
	// loading state (e.g. "0 / 100" for an unset RiskScore, or an empty
	// SHA-256 cell rendered as if it were the real, resolved answer).
	for _, gone := range []string{"0 / 100", "not indicated<", `class="metric__value">0<`} {
		if strings.Contains(body, gone) {
			t.Fatalf("shell render must not leak a zero-valued field as if it were real data (found %q)", gone)
		}
	}
	for _, want := range []string{
		`data-hp-pl-hash="` + shaA + `"`,
		"data-hp-pl-risk", "data-hp-pl-packed", "data-hp-pl-iocs-count",
		"data-hp-pl-identity", "data-hp-pl-more-hashes",
		"data-hp-pl-script", "data-hp-pl-yara", "data-hp-pl-rules", "data-hp-pl-ioc-list",
		"data-hp-pl-bytes-actions", "data-hp-pl-text", "data-hp-pl-decoded",
		"data-hp-pl-classification-note",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("shell render is missing %q -- hp-payload-analysis.js's static-analysis hydration needs this target", want)
		}
	}
}

// TestServePayloadStaticAnalysisReturnsFullAnalysisJSON (#1157): the new
// hydration endpoint must return the same analysis analyzePayloadFast (and,
// before this issue, the synchronous route handler) always produced --
// hashes, entropy, hex dump, strings, and risk scoring included -- just
// reachable over HTTP instead of blocking the page render.
func TestServePayloadStaticAnalysisReturnsFullAnalysisJSON(t *testing.T) {
	dir := t.TempDir()
	content := []byte("MZ.... powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABlAHMAdAAnAA==")
	sum := sha256.Sum256(content)
	name := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{payloadDirs: []string{dir}}
	req := httptest.NewRequest("GET", "/api/payload-analysis/"+name+"/static", nil)
	w := httptest.NewRecorder()
	s.servePayloadStaticAnalysis(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got payloadStaticAnalysisResult
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v (body=%s)", err, w.Body.String())
	}
	if got.SHA256 != name || got.Hexdump == "" || got.MIME == "" {
		t.Fatalf("incomplete static analysis JSON: %+v", got)
	}

	// A malformed hash and an action other than "static" must both 404,
	// same as servePayloadAggregation's own validation.
	badReq := httptest.NewRequest("GET", "/api/payload-analysis/not-a-hash/static", nil)
	badW := httptest.NewRecorder()
	s.servePayloadStaticAnalysis(badW, badReq)
	if badW.Code != 404 {
		t.Fatalf("malformed hash: status = %d, want 404", badW.Code)
	}

	wrongActionReq := httptest.NewRequest("GET", "/api/payload-analysis/"+name+"/aggregation", nil)
	wrongActionW := httptest.NewRecorder()
	s.servePayloadStaticAnalysis(wrongActionW, wrongActionReq)
	if wrongActionW.Code != 404 {
		t.Fatalf("wrong action segment: status = %d, want 404", wrongActionW.Code)
	}
}
