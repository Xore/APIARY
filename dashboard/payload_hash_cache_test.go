package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestPayloadPathBySHA256CachesAndInvalidates (#364): payloadPathBySHA256 is
// the only resolution path for a payload source (Dionaea) that names
// captured files by MD5 rather than SHA-256 -- every SHA-256-addressed
// request for such a file reads and hashes the FULL content of every file
// under every payloadDirs entry until a match turns up. Confirmed live as a
// 45s+ hang for one real captured PE/DLL. A resolved hash must be cached so
// a repeat request for the same payload (the reported pattern: clicking
// into the same workbench result more than once) is instant, and a cache
// hit must not be trusted once the underlying file is gone.
func TestPayloadPathBySHA256CachesAndInvalidates(t *testing.T) {
	dir := t.TempDir()
	content := []byte("simulated captured PE/DLL content")
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	// Named like Dionaea's own convention (MD5-shaped, unrelated to the
	// SHA-256 being requested) so the fast filename-match path in
	// payloadPath necessarily misses and this fallback is what resolves it.
	mdNamed := filepath.Join(dir, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
	if err := os.WriteFile(mdNamed, content, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{payloadDirs: []string{dir}}

	path, err := s.payloadPathBySHA256(want)
	if err != nil || path != mdNamed {
		t.Fatalf("first resolution: path=%q err=%v, want %q", path, err, mdNamed)
	}

	s.hashPathMu.Lock()
	cached, ok := s.hashPathCache[want]
	s.hashPathMu.Unlock()
	if !ok || cached != mdNamed {
		t.Fatalf("resolved hash was not cached: cache=%v", s.hashPathCache)
	}

	// A second call must return the same answer via the cache -- deleting
	// every OTHER file first proves this isn't accidentally re-scanning and
	// getting lucky.
	if err := os.Remove(mdNamed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mdNamed, content, 0o600); err != nil {
		t.Fatal(err)
	}
	path, err = s.payloadPathBySHA256(want)
	if err != nil || path != mdNamed {
		t.Fatalf("cached resolution: path=%q err=%v, want %q", path, err, mdNamed)
	}

	// Once the underlying file is actually gone, a cache hit must not be
	// trusted blindly -- it has to fall back to a fresh scan (which finds
	// nothing) rather than keep returning a path that no longer exists.
	if err := os.Remove(mdNamed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.payloadPathBySHA256(want); err == nil {
		t.Fatal("stale cache entry for a deleted file must not resolve successfully")
	}
	s.hashPathMu.Lock()
	_, stillCached := s.hashPathCache[want]
	s.hashPathMu.Unlock()
	if stillCached {
		t.Fatal("cache entry for a deleted file must be evicted, not left dangling")
	}
}
