package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailerReadsNewLinesOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	st, err := openStore(filepath.Join(dir, "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tl := newTailer(st)

	if err := os.WriteFile(path, []byte("line1\nline2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := tl.poll(path, func(l []byte) { got = append(got, string(l)) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "line1" || got[1] != "line2" {
		t.Fatalf("first poll: got %v", got)
	}

	// Second poll with no new data: nothing new should be delivered.
	got = nil
	if err := tl.poll(path, func(l []byte) { got = append(got, string(l)) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("second poll with no new data: got %v, want none", got)
	}

	// Append: only the new line should come through.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("line3\n")
	f.Close()
	got = nil
	if err := tl.poll(path, func(l []byte) { got = append(got, string(l)) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "line3" {
		t.Fatalf("after append: got %v, want [line3]", got)
	}
}

// TestTailerHandlesRotation is the property that matters most given #120:
// several sensor logs now self-rotate (close, rename aside, reopen fresh at
// the same path). A tailer that only tracks a byte offset would seek past
// the end of the new, shorter file and silently stop advancing. Tracking
// inode alongside offset must detect the file changed and start over from 0.
func TestTailerHandlesRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multipot.json")
	st, err := openStore(filepath.Join(dir, "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tl := newTailer(st)

	if err := os.WriteFile(path, []byte("old-line-1\nold-line-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tl.poll(path, func(l []byte) {}); err != nil {
		t.Fatal(err)
	}

	// Simulate the self-rotation the Go sensors now do: rename the old file
	// aside, create a brand new (smaller) file at the same path.
	if err := os.Rename(path, path+".20260802-000000"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new-line-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var got []string
	if err := tl.poll(path, func(l []byte) { got = append(got, string(l)) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "new-line-1" {
		t.Fatalf("after rotation: got %v, want [new-line-1] -- inode change was not detected", got)
	}
}

// TestTailerPollGlobHandlesRotatingFilenames (#69): eve.json doesn't
// rename-and-reopen at a fixed path the way #120's Go sensors do -- it
// rotates by writing a brand new eve-<timestamp>.json file each time
// (vps/suricata/suricata.yaml). pollGlob has to pick up a new file created
// after the first poll, and never re-deliver a line already consumed from
// an earlier file.
func TestTailerPollGlobHandlesRotatingFilenames(t *testing.T) {
	dir := t.TempDir()
	st, err := openStore(filepath.Join(dir, "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tl := newTailer(st)
	pattern := filepath.Join(dir, "eve-*.json")

	if err := os.WriteFile(filepath.Join(dir, "eve-2026-08-01-00.json"), []byte("first-file-line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := tl.pollGlob(pattern, func(l []byte) { got = append(got, string(l)) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "first-file-line" {
		t.Fatalf("first poll: got %v, want [first-file-line]", got)
	}

	// Re-polling with no new file/data must not re-deliver anything.
	got = nil
	if err := tl.pollGlob(pattern, func(l []byte) { got = append(got, string(l)) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("second poll with nothing new: got %v, want none", got)
	}

	// Suricata's own rotation: a brand new filename, not a rename of the
	// old one. The old file must not be re-read; only the new file's line
	// should come through.
	if err := os.WriteFile(filepath.Join(dir, "eve-2026-08-01-01.json"), []byte("second-file-line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := tl.pollGlob(pattern, func(l []byte) { got = append(got, string(l)) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "second-file-line" {
		t.Fatalf("after rotation to a new filename: got %v, want [second-file-line]", got)
	}
}

// TestTailerSkipsAnOversizedLineInsteadOfStallingForever (#890): before this
// fix, a scan error (bufio.ErrTooLong for a line over the 1MB buffer) left
// offset unmoved with no further handling, so a second poll re-opened the
// file, seeked to the identical byte, and hit the same oversized line again
// -- deterministically forever, silently dropping every later line in that
// file.
func TestTailerSkipsAnOversizedLineInsteadOfStallingForever(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	st, err := openStore(filepath.Join(dir, "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tl := newTailer(st)

	huge := strings.Repeat("A", 2<<20) // 2MB, over the 1MB scanner cap
	content := "before\n" + huge + "\nafter\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var got []int // lengths only -- never print the 2MB line itself
	record := func(l []byte) { got = append(got, len(l)) }

	if err := tl.poll(path, record); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != len("before") {
		t.Fatalf("first poll: got %d line(s) with lengths %v (want just \"before\")", len(got), got)
	}

	// The oversized line is now fully on disk (it ends in \n), so the very
	// next poll must skip past it and pick up "after" -- not stall.
	got = nil
	if err := tl.poll(path, record); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != len("after") {
		t.Fatalf("second poll: got %d line(s) with lengths %v, want [after] (len %d) -- tailer is stuck re-reading the oversized line", len(got), got, len("after"))
	}

	// A third poll must not re-deliver anything: offset has caught up to EOF.
	got = nil
	if err := tl.poll(path, record); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("third poll: got %d line(s) with lengths %v, want none", len(got), got)
	}
}

func TestTailerMissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	st, err := openStore(filepath.Join(dir, "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tl := newTailer(st)

	if err := tl.poll(filepath.Join(dir, "does-not-exist.json"), func(l []byte) {}); err != nil {
		t.Fatalf("a missing sensor log should not be a fatal error: %v", err)
	}
}
