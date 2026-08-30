package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoggerRotatesRapidlyWithoutCollidingOnTimestamp covers #2326: rotate()'s
// rename target was a second-granularity timestamp with no collision check,
// the same bug fixed in multipot's logger under #1403. Two rotations landing
// in the same wall-clock second made the second os.Rename silently replace
// the first rotated file, losing that segment. This proves the counter-suffix
// fix ported from multipot applies here too.
func TestLoggerRotatesRapidlyWithoutCollidingOnTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http-honeypot.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	l := &logger{out: io.Discard, path: path, f: f, max: 1}
	t.Cleanup(func() { l.f.Close() })

	const n = 20
	for i := 0; i < n; i++ {
		l.log(event{Method: "GET", Path: "/test", Body: strings.Repeat("x", 20)})
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

// TestRotateTwiceInSameSecondProducesDistinctFiles is the direct regression
// test for the issue: calling rotate() twice back-to-back (well within the
// same wall-clock second) must not let the second rotation overwrite the
// first segment.
func TestRotateTwiceInSameSecondProducesDistinctFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http-honeypot.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("first-segment\n"); err != nil {
		t.Fatal(err)
	}
	l := &logger{out: io.Discard, path: path, f: f}

	l.rotate()
	if _, err := l.f.WriteString("second-segment\n"); err != nil {
		t.Fatal(err)
	}
	l.rotate()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotated []string
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			rotated = append(rotated, e.Name())
		}
	}
	if len(rotated) != 2 {
		t.Fatalf("want 2 distinct rotated segments, got %d: %v", len(rotated), rotated)
	}

	contents := map[string]bool{}
	for _, name := range rotated {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		contents[strings.TrimSpace(string(data))] = true
	}
	if !contents["first-segment"] || !contents["second-segment"] {
		t.Fatalf("want both segments preserved distinctly, got %v", contents)
	}
}
