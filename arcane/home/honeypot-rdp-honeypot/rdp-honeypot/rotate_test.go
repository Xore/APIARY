package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoggerRotatesWithoutLosingLines covers #2216: this writer held its log
// file open for the process lifetime with no rotation at all. Proves the
// ported rotate() (from multipot, see that package's rotate_test.go) closes,
// renames and reopens without dropping any emitted line.
func TestLoggerRotatesWithoutLosingLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rdp-honeypot.json")
	l := newLogger(path)
	l.max = 1
	t.Cleanup(func() {
		if l.out != nil {
			l.out.Close()
		}
	})

	const n = 20
	for i := 0; i < n; i++ {
		l.emit(event{Data: strings.Repeat("x", 20)})
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
