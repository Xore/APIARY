package main

import (
	"os"
	"path/filepath"
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
