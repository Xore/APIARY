package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoggerRotatesRapidlyWithoutCollidingOnTimestamp covers #1403: the
// same rotation pattern this file originated (rotate()'s rename target was
// a second-granularity timestamp with no collision check) was later copied
// into ip-enrichment-worker/rotate.go and dionaea/log_rotation_patch.py,
// where testing caught real data loss when two rotations land in the same
// wall-clock second -- the second os.Rename silently replaced the first
// rotated file. Both copies were fixed with a counter suffix; this proves
// the fix applied back here to the original.
func TestLoggerRotatesRapidlyWithoutCollidingOnTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multipot.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	l := &logger{out: io.Discard, path: path, f: f, max: 1}
	t.Cleanup(func() { l.f.Close() })

	const n = 20
	for i := 0; i < n; i++ {
		l.emit(event{Proto: "test", Event: "test", Data: strings.Repeat("x", 20)})
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, fi := range files {
		data, err := os.ReadFile(filepath.Join(dir, fi.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line != "" {
				total++
			}
		}
	}
	if total != n {
		t.Fatalf("want all %d lines preserved across every rotation, got %d (files: %v)", n, total, files)
	}
}
