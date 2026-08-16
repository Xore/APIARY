package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestGitHubAnalysisSmokeEndToEnd is the deep integration check the unit
// tests above cannot be: it drives the real HTTP handler, then runs the
// real analysis/github/process-github-requests.sh against the exact spool
// directory the handler wrote to, and asserts a result comes back. Go and
// bash were built against the same roadmap document but never against each
// other — this is what actually proves the contract between them (request
// filename format, hash length, directory layout) rather than each side's
// own idea of it. It is exactly the kind of seam where #74's earlier
// GITHUB_ANALYSIS_PENDING_DIR bug lived, undetected by either language's own
// tests, until this test existed.
//
// Skips (not fails) when the host is missing bash/jq/sha256sum, since a unit
// test run should not require a specific shell environment to pass.
func TestGitHubAnalysisSmokeEndToEnd(t *testing.T) {
	for _, bin := range []string{"bash", "jq", "sha256sum", "find"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("smoke test needs %s on PATH: %v", bin, err)
		}
	}
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(repoRoot, "analysis", "github", "process-github-requests.sh")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("process-github-requests.sh not found at %s: %v", script, err)
	}

	// --- Step 1: the real dashboard handler, exactly as a browser would drive it. ---
	payloads := t.TempDir()
	sampleBody := "smoke-test fixture, not a real sample, " + t.Name()
	if err := os.WriteFile(filepath.Join(payloads, "fixture-before-hash"), []byte(sampleBody), 0o600); err != nil {
		t.Fatal(err)
	}
	// classifyPayload/hashName don't care what the file is named on disk here;
	// the dashboard resolves by matching the hash argument to a filename it
	// already knows. Name the fixture what the handler will look up: its own
	// SHA-256, computed once, matching resolve-sample.sh's own preference for
	// the strongest hash it's given.
	hash, err := sha256File(filepath.Join(payloads, "fixture-before-hash"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(payloads, "fixture-before-hash"), filepath.Join(payloads, hash)); err != nil {
		t.Fatal(err)
	}

	requestDir := t.TempDir()
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requestDir)
	s := &store{payloadDirs: []string{payloads}}

	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
		strings.NewReader("hash="+hash+"&confirm=publish"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisSubmit(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("dashboard handler: status=%d body=%s", w.Code, w.Body.String())
	}
	requestFile := filepath.Join(requestDir, hash+".request")
	if _, err := os.Stat(requestFile); err != nil {
		t.Fatalf("dashboard handler did not write the marker the shell side expects: %v", err)
	}

	// --- Step 2: the real host publisher, pointed at that exact spool. ---
	// A separate directory from `payloads` above: resolve-sample.sh searches
	// its own configured roots, not the dashboard's payloadDirs -- they are
	// two different processes on two different sides of the trust boundary,
	// and this test is precisely about not assuming they agree by
	// construction. Copying the fixture across proves they agree in fact.
	cowrieDownloads := t.TempDir()
	if err := os.WriteFile(filepath.Join(cowrieDownloads, hash), []byte(sampleBody), 0o600); err != nil {
		t.Fatal(err)
	}
	resultsDir := t.TempDir()
	pendingDir := t.TempDir()

	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(),
		"GITHUB_ANALYSIS_REQUEST_DIR="+requestDir,
		"GITHUB_ANALYSIS_RESULTS_DIR="+resultsDir,
		"GITHUB_ANALYSIS_PENDING_DIR="+pendingDir,
		"GITHUB_ANALYSIS_LOCK="+filepath.Join(t.TempDir(), "publish.lock"),
		"COWRIE_DOWNLOADS_DIR="+cowrieDownloads,
		"GITHUB_ANALYSIS_DAILY_CAP=20",
		// Point the script at a guaranteed-nonexistent path instead of its
		// default /etc/honeypot-github.env -- on any host that's also a
		// real deployment target (including this repo's own self-hosted CI
		// runner, which shares the physical homeserver), that path is a
		// real production secrets file the test has no business touching,
		// readable or not. Every other stateful path above is already
		// isolated the same way; this one was missed, and only surfaced
		// once this test ran somewhere the file actually existed with
		// permissions denying the CI user (harmless "permission denied",
		// but for the wrong reason -- this test isn't supposed to know
		// that file exists at all).
		"GITHUB_ANALYSIS_ENV_FILE="+filepath.Join(t.TempDir(), "unused.env"),
		// GITHUB_PUBLISH_ENABLED deliberately absent: this test proves the
		// request round-trips correctly, not that a real publish works --
		// that would need a live GH_PAT and network access, which no
		// automated test in this repository is permitted to use.
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("process-github-requests.sh failed: %v\n%s", err, output)
	}

	// --- Step 3: the round trip. ---
	if _, err := os.Stat(requestFile); !os.IsNotExist(err) {
		t.Fatalf("request marker still present after the host script ran (stat err=%v)", err)
	}
	resultFile := filepath.Join(resultsDir, hash+".json")
	waitDeadline := time.Now().Add(5 * time.Second)
	var resultBytes []byte
	for time.Now().Before(waitDeadline) {
		if b, err := os.ReadFile(resultFile); err == nil {
			resultBytes = b
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resultBytes == nil {
		entries, _ := os.ReadDir(resultsDir)
		t.Fatalf("no result appeared at %s within 5s; results dir has: %v\nscript output:\n%s", resultFile, entries, output)
	}
	body := string(resultBytes)
	if !strings.Contains(body, `"exit_status":"dry_run"`) {
		t.Fatalf("result did not carry exit_status dry_run: %s", body)
	}
	if !strings.Contains(body, hash) {
		t.Fatalf("result does not reference the submitted hash %s: %s", hash, body)
	}
}

func sha256File(path string) (string, error) {
	out, err := exec.Command("sha256sum", path).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", os.ErrInvalid
	}
	return fields[0], nil
}
