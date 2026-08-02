package main

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #149: the /payloads inventory surfaces GitHub-analysis's scanner-derived
// family attribution as its own badge, distinct from the existing verdict
// badge, linking to the /events?family= pivot.
func TestPayloadsDataSurfacesFamilyAttribution(t *testing.T) {
	payloadDir := t.TempDir()
	hash := strings.Repeat("c", 64)
	if err := os.WriteFile(filepath.Join(payloadDir, hash), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	resultsDir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", resultsDir)
	writeGitHubAnalysisResult(t, resultsDir, hash, map[string]any{
		"exit_status": "ok", "family": "Mirai",
		"verdict": map[string]any{"malicious": 12, "suspicious": 1, "total": 20, "level": "malicious"},
	})

	s := &store{payloadDirs: []string{payloadDir}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	page := s.payloadsData("")
	if len(page.Files) != 1 {
		t.Fatalf("expected 1 file, got %d: %+v", len(page.Files), page.Files)
	}
	file := page.Files[0]
	if file.Family != "Mirai" {
		t.Errorf("Family = %q, want %q", file.Family, "Mirai")
	}
	wantLink := eventsURL(url.Values{"family": {"Mirai"}})
	if file.FamilyLink != wantLink {
		t.Errorf("FamilyLink = %q, want %q", file.FamilyLink, wantLink)
	}
	// The pre-existing verdict badge must be untouched -- Family is additive,
	// not a replacement for GitHubAnalysisLabel.
	if file.GitHubAnalysisLabel == "" {
		t.Error("adding Family must not clobber the existing verdict badge")
	}
}

// A payload with no GitHub-analysis record (or one that never got a family
// attribution) must leave Family/FamilyLink empty -- no badge, not an empty
// or misleading one.
func TestPayloadsDataLeavesFamilyEmptyWithoutAttribution(t *testing.T) {
	payloadDir := t.TempDir()
	hash := strings.Repeat("d", 64)
	if err := os.WriteFile(filepath.Join(payloadDir, hash), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", "")

	s := &store{payloadDirs: []string{payloadDir}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	page := s.payloadsData("")
	if len(page.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(page.Files))
	}
	if file := page.Files[0]; file.Family != "" || file.FamilyLink != "" {
		t.Errorf("expected no family attribution, got Family=%q FamilyLink=%q", file.Family, file.FamilyLink)
	}
}

// #149: the payload-analysis detail page's GitHub analysis card links its
// family value to the /events?family= pivot, and shows the bounded display
// value rather than the raw GitHubAnalysis.Family the template used to
// render directly.
func TestAnalyzePayloadSurfacesFamilyAttribution(t *testing.T) {
	payloadDir := t.TempDir()
	content := []byte("MZ fake PE content for a family-attributed capture")
	sum := sha256.Sum256(content)
	sha256hex := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(payloadDir, sha256hex), content, 0o600); err != nil {
		t.Fatal(err)
	}

	resultsDir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", resultsDir)
	writeGitHubAnalysisResult(t, resultsDir, sha256hex, map[string]any{
		"exit_status": "ok", "family": "Qbot",
	})

	s := &store{payloadDirs: []string{payloadDir}}
	a, err := s.analyzePayload(sha256hex)
	if err != nil {
		t.Fatal(err)
	}
	if a.Family != "Qbot" {
		t.Errorf("Family = %q, want %q", a.Family, "Qbot")
	}
	wantLink := eventsURL(url.Values{"family": {"Qbot"}})
	if a.FamilyLink != wantLink {
		t.Errorf("FamilyLink = %q, want %q", a.FamilyLink, wantLink)
	}
	if a.GitHubAnalysis == nil || a.GitHubAnalysis.Family != "Qbot" {
		t.Error("GitHubAnalysis record itself must still carry the raw family")
	}
}

// A pathologically long family label must not reach the page unbounded --
// analyzePayload's Family is the bounded display value, distinct from the
// raw GitHubAnalysis.Family the record itself still carries in full.
func TestAnalyzePayloadBoundsLongFamilyLabel(t *testing.T) {
	payloadDir := t.TempDir()
	content := []byte("payload content for a long family label")
	sum := sha256.Sum256(content)
	sha256hex := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(payloadDir, sha256hex), content, 0o600); err != nil {
		t.Fatal(err)
	}

	long := strings.Repeat("x", familyDisplayCap+50)
	resultsDir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", resultsDir)
	writeGitHubAnalysisResult(t, resultsDir, sha256hex, map[string]any{
		"exit_status": "ok", "family": long,
	})

	s := &store{payloadDirs: []string{payloadDir}}
	a, err := s.analyzePayload(sha256hex)
	if err != nil {
		t.Fatal(err)
	}
	if a.Family == long {
		t.Fatal("Family must be the bounded display value, not the raw pipeline text")
	}
	if !strings.HasSuffix(a.Family, "…") {
		t.Errorf("bounded Family should end in an ellipsis, got %q", a.Family)
	}
	// The link must carry the full, untruncated value -- truncating first
	// would pivot to the wrong (truncated) family.
	if a.FamilyLink != eventsURL(url.Values{"family": {long}}) {
		t.Error("FamilyLink must use the untruncated family value")
	}
}

// The family badge on the /payloads card grid must actually render, linking
// to the /events?family= pivot -- a struct-level assertion alone wouldn't
// catch a template that never references the new fields.
func TestPayloadsPageRendersFamilyBadge(t *testing.T) {
	payloadDir := t.TempDir()
	hash := strings.Repeat("e", 64)
	if err := os.WriteFile(filepath.Join(payloadDir, hash), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	resultsDir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", resultsDir)
	writeGitHubAnalysisResult(t, resultsDir, hash, map[string]any{"exit_status": "ok", "family": "Mirai"})

	s := &store{payloadDirs: []string{payloadDir}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	page := s.payloadsData("")
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "payloads", &page); err != nil {
		t.Fatalf("payloads page does not render: %v", err)
	}
	html := out.String()

	if !strings.Contains(html, ">Mirai<") {
		t.Fatal("payloads card grid is missing the family badge text")
	}
	if !strings.Contains(html, `href="/events?family=Mirai"`) {
		t.Fatal("family badge does not link to the /events?family= pivot")
	}
}
