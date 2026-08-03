package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadNewLinesReturnsOnlyCompleteLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.json")
	os.WriteFile(path, []byte(`{"a":1}`+"\n"+`{"a":2}`+"\n"+`{"a":3}`), 0o640) // trailing partial line

	lines, offset, err := readNewLines(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (trailing partial line must not be consumed)", len(lines))
	}
	if string(lines[0]) != `{"a":1}` || string(lines[1]) != `{"a":2}` {
		t.Fatalf("unexpected lines: %s", lines)
	}

	// A second read from the returned offset must pick up nothing new until
	// the partial line completes.
	more, offset2, err := readNewLines(path, offset)
	if err != nil {
		t.Fatal(err)
	}
	if len(more) != 0 || offset2 != offset {
		t.Fatalf("expected no new complete lines yet, got %d (offset %d -> %d)", len(more), offset, offset2)
	}

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\n")
	f.Close()

	final, _, err := readNewLines(path, offset)
	if err != nil {
		t.Fatal(err)
	}
	if len(final) != 1 || string(final[0]) != `{"a":3}` {
		t.Fatalf("expected the now-complete third line, got %s", final)
	}
}

func TestReadNewLinesResumesFromZeroOnRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.json")
	os.WriteFile(path, []byte(`{"a":1}`+"\n"+`{"a":2}`+"\n"), 0o640)

	_, offset, err := readNewLines(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Rename-based rotation: a brand-new, shorter file reopened at the same
	// path (cowrie's own daily CowrieDailyLogFile behavior).
	os.WriteFile(path, []byte(`{"a":3}`+"\n"), 0o640)

	lines, _, err := readNewLines(path, offset)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || string(lines[0]) != `{"a":3}` {
		t.Fatalf("expected to resume from the start of the rotated file, got %s", lines)
	}
}

func TestOffsetPersistsAcrossLoadSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.offset")
	if _, ok := loadOffset(path); ok {
		t.Fatal("expected no offset before it's ever been saved")
	}
	if err := saveOffset(path, 12345); err != nil {
		t.Fatal(err)
	}
	got, ok := loadOffset(path)
	if !ok || got != 12345 {
		t.Fatalf("loadOffset = %d, %v; want 12345, true", got, ok)
	}
}
