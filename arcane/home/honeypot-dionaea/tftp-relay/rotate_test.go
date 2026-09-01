package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLogSessionRotatesWithoutLosingLines covers #2216: this writer opened
// its session log once at startup and never rotated. Proves
// rotateSessionLog() (ported from multipot's logger.rotate(), see that
// package's rotate_test.go) closes, renames and reopens without dropping any
// written line.
func TestLogSessionRotatesWithoutLosingLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")
	f := openSessionLog(path)
	if f == nil {
		t.Fatal("openSessionLog returned nil")
	}
	r := &relay{sessionLog: f, sessionLogPath: path, sessionLogMax: 1}
	t.Cleanup(func() {
		if r.sessionLog != nil {
			r.sessionLog.Close()
		}
	})

	const n = 20
	for i := 0; i < n; i++ {
		r.logSession(69, "198.51.100."+strings.Repeat("9", 1))
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Fatalf("want more than one file after %d writes with max=1, got %v", n, files)
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
		t.Fatalf("want all %d lines preserved across rotation, got %d (files: %v)", n, total, files)
	}
}
