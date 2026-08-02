package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hashCorrelationSample = `{
  "hits": {
    "total": {"value": 2},
    "hits": [
      {"_index": "honeypot-v2-2026.08.02", "_source": {"@timestamp": "2026-08-02T12:00:00Z", "event": {"sensor": "cowrie"}}},
      {"_index": "honeypot-v2-2026.08.01", "_source": {"@timestamp": "2026-08-01T09:00:00Z", "event": {"sensor": "dionaea"}}}
    ]
  }
}`

// TestCorrelateHashChecksEverySourceIncludingGhidra (#354): correlateHash is
// the first place Ghidra, sandbox, GitHub-analysis, and Elasticsearch
// sighting history are all checked together for one hash -- previously
// Ghidra results weren't surfaced on /payload-analysis at all.
func TestCorrelateHashChecksEverySourceIncludingGhidra(t *testing.T) {
	ghidraDir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", ghidraDir)
	writeGhidraResult(t, ghidraDir, shaA, map[string]any{
		"version": 1, "sha256": shaA, "exit_status": "ok", "completed_at": "2026-08-02T10:00:00Z",
	})

	sandboxDir := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", sandboxDir)
	if err := os.WriteFile(filepath.Join(sandboxDir, "linux-x.json"),
		[]byte(`{"version":1,"job":"linux-x","sha256":"`+shaA+`","completed_at":"2026-08-02T11:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	githubDir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", githubDir)
	writeGitHubAnalysisResult(t, githubDir, shaA, map[string]any{"exit_status": "ok", "family": "Mirai"})

	var gotPath string
	es := httptest.NewServer(correlationSearchStub(t, &gotPath, hashCorrelationSample))
	defer es.Close()

	// altID simulates a Dionaea capture's on-disk MD5 identity, distinct
	// from its true content SHA-256 (shaA) -- the bug this two-argument
	// signature exists to fix: an earlier version of this code only ever
	// queried Elasticsearch with the true SHA-256, silently missing every
	// Dionaea sighting (which Elasticsearch only ever has under
	// file.hash.md5, keyed by the MD5, not the SHA-256).
	altID := "0123456789abcdef0123456789abcdef"
	s := &store{es: newESClient(es.URL, "")}
	result := s.correlateHash(shaA, altID)

	if !result.Known {
		t.Fatal("expected Known=true when every source has a result")
	}
	if result.Ghidra == nil || result.Ghidra.ExitStatus != "ok" {
		t.Fatalf("Ghidra result not found: %+v", result.Ghidra)
	}
	if len(result.Sandbox) != 1 || result.Sandbox[0].Job != "linux-x" {
		t.Fatalf("sandbox result not found: %+v", result.Sandbox)
	}
	if result.GitHub == nil || result.GitHub.Family != "Mirai" {
		t.Fatalf("GitHub-analysis result not found: %+v", result.GitHub)
	}
	if !result.ESAvailable || result.ESSightings != 2 {
		t.Fatalf("ES sightings not found: available=%v sightings=%d", result.ESAvailable, result.ESSightings)
	}
	for _, want := range []string{`file.hash.sha256:"` + shaA + `"`, `file.hash.md5:"` + shaA + `"`, `file.hash.sha256:"` + altID + `"`, `file.hash.md5:"` + altID + `"`} {
		if !strings.Contains(gotPath, url.QueryEscape(want)) {
			t.Fatalf("query is missing %q -- both identifiers must be checked against both hash fields: %s", want, gotPath)
		}
	}
}

// TestCorrelateHashReportsUnknownWhenNothingMatches (#354): a hash with no
// results anywhere must report Known=false, not a false positive from an
// empty-but-truthy struct.
func TestCorrelateHashReportsUnknownWhenNothingMatches(t *testing.T) {
	t.Setenv("GHIDRA_RESULTS_DIR", t.TempDir())
	t.Setenv("SANDBOX_RESULTS_DIR", t.TempDir())
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())

	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	result := s.correlateHash(shaB, "")
	if result.Known {
		t.Fatalf("expected Known=false with no matches anywhere, got %+v", result)
	}
}

// TestCorrelateHashRejectsMalformedInputWithoutQuerying (#354): mirrors the
// IP-correlation defense (#354 phase 2) -- a malformed value must never
// reach the Lucene query string.
func TestCorrelateHashRejectsMalformedInputWithoutQuerying(t *testing.T) {
	called := false
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	for _, bad := range []string{"", "not-a-hash", `abc" OR "1`, "toolong" + strings.Repeat("a", 200)} {
		if result := s.correlateHash(bad, ""); result.Known {
			t.Errorf("correlateHash(%q) should never report Known=true for malformed input, got %+v", bad, result)
		}
	}
	if called {
		t.Fatal("malformed primary must never reach the Elasticsearch query")
	}
}

// TestCorrelateHashRejectsMalformedAltID (#354): a well-formed primary must
// still be queried, but a malformed altID (or one that happens to equal
// primary) must never be added as a second query clause.
func TestCorrelateHashRejectsMalformedAltID(t *testing.T) {
	var gotPath string
	es := httptest.NewServer(correlationSearchStub(t, &gotPath, `{"hits":{"total":{"value":0},"hits":[]}}`))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	for _, bad := range []string{"not-a-hash", `abc" OR "1`, shaA} {
		gotPath = ""
		s.correlateHash(shaA, bad)
		if gotPath == "" {
			t.Fatal("a well-formed primary must still be queried even when altID is malformed")
		}
		if strings.Count(gotPath, "file.hash.sha256") != 1 {
			t.Fatalf("altID %q must not add a second query clause (malformed, or a no-op duplicate of primary): %s", bad, gotPath)
		}
	}
}

// TestPayloadAnalysisPageRendersKnownElsewhereCard (#354): the advisory card
// must show Ghidra and Elasticsearch sighting summary when known, and a
// clear "not seen elsewhere" state when not -- never blocking anything
// either way.
func TestPayloadAnalysisPageRendersKnownElsewhereCard(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	known := binaryAnalysis{
		Hash: shaA, SHA256: shaA,
		Correlation: hashCorrelation{
			Known:       true,
			Ghidra:      &ghidraResult{ExitStatus: "ok", CompletedAt: "2026-08-02T10:00:00Z"},
			ESAvailable: true, ESSightings: 3, ESFirstSeen: "2026-08-01 09:00:00", ESLastSeen: "2026-08-02 12:00:00",
			ESSensors: []kv{{Key: "cowrie", Count: 2}},
		},
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "payload-analysis", &known); err != nil {
		t.Fatalf("render known: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "already analyzed") || !strings.Contains(body, "3 event(s)") {
		t.Fatalf("known-elsewhere card missing expected content: %s", body)
	}

	unknown := binaryAnalysis{Hash: shaB, SHA256: shaB, Correlation: hashCorrelation{}}
	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "payload-analysis", &unknown); err != nil {
		t.Fatalf("render unknown: %v", err)
	}
	if !strings.Contains(buf.String(), "not seen elsewhere") {
		t.Fatal("unknown hash must render the not-seen-elsewhere state")
	}
}

// TestWorkbenchPageRendersKnownElsewhereBannerOnlyWhenKnown (#354): the
// workbench is the actual "about to submit new work" decision point, so the
// advisory banner belongs there too -- present when known, absent (not an
// empty banner) when not, and never disabling analyzer selection either way.
func TestWorkbenchPageRendersKnownElsewhereBannerOnlyWhenKnown(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	known := workbenchPageData{
		SHA256: shaA,
		Correlation: hashCorrelation{
			Known: true, Sandbox: []sandboxResult{{Job: "linux-x"}},
		},
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "payload-workbench", &known); err != nil {
		t.Fatalf("render known: %v", err)
	}
	if !strings.Contains(buf.String(), "wb-known-elsewhere") || !strings.Contains(buf.String(), "Sandbox: 1 run(s)") {
		t.Fatalf("known-elsewhere banner missing or incomplete: %s", buf.String())
	}

	unknown := workbenchPageData{SHA256: shaB, Correlation: hashCorrelation{}}
	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "payload-workbench", &unknown); err != nil {
		t.Fatalf("render unknown: %v", err)
	}
	if strings.Contains(buf.String(), "wb-known-elsewhere") {
		t.Fatal("banner must not render when Correlation.Known is false")
	}
}
