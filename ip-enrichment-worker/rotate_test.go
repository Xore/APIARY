package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOutputWriterRotatesAtMaxBytesWithoutLosingLines covers #1389: this
// output previously grew unbounded (3.86GB/2.18GB after 6 days on the live
// homeserver) because it had no rotation at all, unlike every raw sensor
// writer it reads from.
func TestOutputWriterRotatesAtMaxBytesWithoutLosingLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	w, err := newOutputWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })

	if !w.write("cowrie", [][]byte{[]byte(`{"a":1}`)}) {
		t.Fatal("first write failed")
	}
	if !w.write("cowrie", [][]byte{[]byte(`{"a":2}`)}) {
		t.Fatal("second write failed")
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotated, current int
	for _, f := range files {
		switch {
		case f.Name() == "cowrie.json":
			current++
		case strings.HasPrefix(f.Name(), "cowrie.json."):
			rotated++
		}
	}
	if rotated != 1 {
		t.Fatalf("want exactly 1 rotated file after 2 writes with max=1, got %d (files: %v)", rotated, files)
	}
	if current != 1 {
		t.Fatalf("want the original path still present and receiving writes, got %d", current)
	}

	var lines []string
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line != "" {
				lines = append(lines, line)
			}
		}
	}
	if len(lines) != 2 {
		t.Fatalf("want both lines present across original + rotated file, got %d: %v", len(lines), lines)
	}
}

// TestOutputWriterRotatesRapidlyWithoutCollidingOnTimestamp covers a real
// bug found while testing #1389's Dionaea-side fix: rotate()'s rename
// target was a second-granularity timestamp with no collision check, so
// two rotations landing in the same wall-clock second silently replaced
// the first rotated file with the second, losing every line in it.
func TestOutputWriterRotatesRapidlyWithoutCollidingOnTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	w, err := newOutputWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })

	const n = 20
	for i := 0; i < n; i++ {
		if !w.write("cowrie", [][]byte{[]byte(strings.Repeat("x", 20))}) {
			t.Fatalf("write %d failed", i)
		}
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
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

// TestOutputWriterZeroMaxNeverRotates matches newLogger's own "0 disables
// rotation" contract (multipot/main.go) -- OUTPUT_MAX_BYTES=0 should mean
// "no bound", not "rotate on every write" (size starts at 0 too, so a naive
// `size >= max` with max=0 would rotate immediately).
func TestOutputWriterZeroMaxNeverRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	w, err := newOutputWriter(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })

	for i := 0; i < 5; i++ {
		if !w.write("cowrie", [][]byte{[]byte(`{"a":1}`)}) {
			t.Fatalf("write %d failed", i)
		}
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("want no rotation at all with max=0, got %d files: %v", len(files), files)
	}
}

// TestOutputWriterResumesAppendingExistingFileSize covers the reopen-after-
// worker-restart path: a fresh newOutputWriter against a file that already
// has content must start its size accounting from the real on-disk size, not
// 0 -- otherwise a restart right after a near-full file resets the rotation
// countdown and the file keeps growing well past max.
func TestOutputWriterResumesAppendingExistingFileSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	w, err := newOutputWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	if w.size == 0 {
		t.Fatal("newOutputWriter must seed size from the existing file, not start at 0")
	}

	if !w.write("cowrie", [][]byte{[]byte(`{"a":2}`)}) {
		t.Fatal("write failed")
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotated int
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "cowrie.json.") {
			rotated++
		}
	}
	if rotated != 1 {
		t.Fatalf("want the pre-existing content rotated aside on the very next write, got %d rotated files: %v", rotated, files)
	}
}
