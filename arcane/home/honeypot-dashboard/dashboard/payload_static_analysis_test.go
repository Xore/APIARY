package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
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

	esGitHubAnalysisResult(t, map[string]any{"sha256": sha256hex, "exit_status": "ok", "family": "Qbot"})

	esStore := newMemESDocStore()
	esSrv := httptest.NewServer(esStore.handler())
	defer esSrv.Close()
	s := &store{payloadDirs: []string{payloadDir}, es: newESClient(esSrv.URL, "")}
	first, err := s.analyzePayload(sha256hex)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 != sha256hex || first.Family != "Qbot" {
		t.Fatalf("first analysis = %+v, want SHA256=%q Family=Qbot", first, sha256hex)
	}

	if _, found, err := s.es.docGet(staticAnalysisIndex, sha256hex); err != nil || !found {
		t.Fatalf("static analysis was not cached in Elasticsearch after the first call: found=%v err=%v", found, err)
	}

	// Overwrite the GitHub-analysis result (dynamic data) without touching
	// the payload file itself -- the second call must reflect the new
	// family attribution, proving the whole binaryAnalysis wasn't cached,
	// only the static half. esGitHubAnalysisResult repoints esResultsClient
	// at a fresh stub server, same as writing a new local file used to.
	esGitHubAnalysisResult(t, map[string]any{"sha256": sha256hex, "exit_status": "ok", "family": "Emotet"})
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

// TestStaticAnalysisPrefersESMirrorOverDiskOnCacheMiss is the #1103 hybrid
// item's own regression guard: on a staticAnalysisIndex cache miss, the
// source bytes must come from the already-ES-mirrored dashboard-payload-
// bytes-v1 copy when its recorded fingerprint still matches the local file,
// not from a fresh disk read -- proven here by mirroring content that
// deliberately differs from what's actually on disk (tagged with the local
// file's own real fingerprint) and confirming the analysis reflects the
// mirrored content, not the disk content.
func TestStaticAnalysisPrefersESMirrorOverDiskOnCacheMiss(t *testing.T) {
	payloadDir := t.TempDir()
	hash := "f" + hex.EncodeToString(make([]byte, 31)) // 64 hex chars, valid hashName format
	diskContent := []byte("disk content -- must NOT be what analysis reflects")
	path := filepath.Join(payloadDir, hash)
	if err := os.WriteFile(path, diskContent, 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	realFingerprint := fileFingerprint(fi)

	esStore := newMemESDocStore()
	esSrv := httptest.NewServer(esStore.handler())
	defer esSrv.Close()
	s := &store{payloadDirs: []string{payloadDir}, es: newESClient(esSrv.URL, "")}

	mirroredContent := []byte("mirrored ES content -- analysis MUST reflect this instead")
	mirroredMD5 := md5.Sum(mirroredContent)
	doc := storedPayloadBytes{
		Hash:        hash,
		SizeBytes:   int64(len(mirroredContent)),
		DataBase64:  base64.StdEncoding.EncodeToString(mirroredContent),
		Fingerprint: realFingerprint,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.es.docIndex(payloadBytesIndex, hash, body, true, 0, 0); err != nil {
		t.Fatal(err)
	}

	got, err := s.staticAnalysisFor(path)
	if err != nil {
		t.Fatal(err)
	}
	wantMD5 := hex.EncodeToString(mirroredMD5[:])
	if got.MD5 != wantMD5 {
		t.Fatalf("static analysis MD5 = %q, want %q (the ES-mirrored copy's hash) -- read disk instead of the ES mirror on a cache miss", got.MD5, wantMD5)
	}
}
