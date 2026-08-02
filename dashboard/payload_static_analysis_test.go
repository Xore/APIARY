package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAnalyzePayloadCachesStaticWorkButRefreshesDynamicData (#352):
// analyzePayload used to recompute hashes, entropy, and regex-based
// artifact/IOC extraction over the full file on every single call, even for
// the exact same, unchanged file -- real, bounded-but-nontrivial work
// (reading and hashing the whole file three times over) wasted on a repeat
// view, which is the common case (a payload looked at more than once across
// workbench, reports, and events pages). The static half must be cached
// per-file; the dynamic half (YARA/sandbox/GitHub-analysis/origin, which
// can change over time for the same file) must still be read fresh on
// every call.
func TestAnalyzePayloadCachesStaticWorkButRefreshesDynamicData(t *testing.T) {
	payloadDir := t.TempDir()
	content := []byte("MZ fake PE content for a cache correctness check")
	sum := sha256.Sum256(content)
	sha256hex := hex.EncodeToString(sum[:])
	path := filepath.Join(payloadDir, sha256hex)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	resultsDir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", resultsDir)
	writeGitHubAnalysisResult(t, resultsDir, sha256hex, map[string]any{
		"exit_status": "ok", "family": "Qbot",
	})

	s := &store{payloadDirs: []string{payloadDir}}
	first, err := s.analyzePayload(sha256hex)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 != sha256hex || first.Family != "Qbot" {
		t.Fatalf("first analysis = %+v, want SHA256=%q Family=Qbot", first, sha256hex)
	}

	s.staticAnalysisMu.Lock()
	_, cached := s.staticAnalysisCache[path]
	s.staticAnalysisMu.Unlock()
	if !cached {
		t.Fatal("static analysis was not cached after the first call")
	}

	// Overwrite the GitHub-analysis result (dynamic data) without touching
	// the payload file itself -- the second call must reflect the new
	// family attribution, proving the whole binaryAnalysis wasn't cached,
	// only the static half.
	writeGitHubAnalysisResult(t, resultsDir, sha256hex, map[string]any{
		"exit_status": "ok", "family": "Emotet",
	})
	second, err := s.analyzePayload(sha256hex)
	if err != nil {
		t.Fatal(err)
	}
	if second.Family != "Emotet" {
		t.Fatalf("second analysis Family = %q, want Emotet (dynamic data must not be cached)", second.Family)
	}
	if second.SHA256 != first.SHA256 || second.MD5 != first.MD5 || second.Entropy != first.Entropy {
		t.Fatalf("static fields changed across calls to the same unmodified file: first=%+v second=%+v", first, second)
	}

	// Modifying the file itself must invalidate the static cache -- a stale
	// hash for changed content would be a worse bug than the slow path it
	// replaces.
	if err := os.WriteFile(path, []byte("completely different content, different hash"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, time.Now().Add(time.Minute), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	third, err := s.staticAnalysisFor(path)
	if err != nil {
		t.Fatal(err)
	}
	if third.SHA256 == first.SHA256 {
		t.Fatal("static analysis cache was not invalidated after the underlying file changed")
	}
}
