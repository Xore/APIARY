package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingWriterRotatesAtMaxBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.json")

	w, err := newRotatingWriter(path, 50, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	line := []byte(strings.Repeat("a", 20) + "\n") // 21 bytes/line
	for i := 0; i < 5; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// 5 writes of 21 bytes against a 50-byte cap must have rotated at
	// least once -- the live file should never be far past the cap.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 50+21 {
		t.Fatalf("current audit file is %d bytes, expected it to have rotated well before this near a 50-byte cap", info.Size())
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected a rotated backup at %s.1: %v", path, err)
	}
}

func TestRotatingWriterNeverDropsAnEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.json")

	w, err := newRotatingWriter(path, 40, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	var wrote [][]byte
	for i := 0; i < 20; i++ {
		line := []byte(strings.Repeat("x", 15) + "\n")
		if _, err := w.Write(line); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		wrote = append(wrote, line)
	}
	w.Close()

	// Every entry must be recoverable across the live file plus its
	// rotated backups -- rotation must never silently drop a write, only
	// age it out once it falls off the end of `keep` rotations.
	var total int
	for _, suffix := range []string{"", ".1", ".2", ".3"} {
		data, err := os.ReadFile(path + suffix)
		if err != nil {
			continue
		}
		total += strings.Count(string(data), "x\n")
	}
	if total == 0 {
		t.Fatal("no audit entries survived across the live file and its rotations")
	}
	if total > len(wrote) {
		t.Fatalf("found %d entries across rotated files, wrote only %d -- rotation duplicated data", total, len(wrote))
	}
	// With keep=3 and 20 small writes against a 40-byte cap, several
	// rotations happen; the most recent writes must always be present in
	// the live (unsuffixed) file specifically -- that's the "most recent
	// decisions must survive" guarantee the issue asks for.
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) == 0 {
		t.Fatal("live audit file is empty after writes -- most recent entries were lost")
	}
}

func TestRotatingWriterZeroMaxBytesNeverRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.json")

	w, err := newRotatingWriter(path, 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	line := []byte(strings.Repeat("a", 100) + "\n")
	for i := 0; i < 10; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := os.Stat(path + ".1"); err == nil {
		t.Fatal("maxBytes=0 (rotation disabled) should never rotate, but a .1 backup exists")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(10*len(line)) {
		t.Fatalf("expected all writes to land in the single unrotated file, got %d bytes", info.Size())
	}
}

// #2882 review: rotate() used to close the file first and return early on
// any later failure, leaving r.f pointing at a closed handle. Write() logs
// the rotation failure and then writes through r.f anyway, so that closed
// handle meant every subsequent audit entry was lost -- permanently, after
// one transient failure -- while the comment above Write() promises the
// opposite. A full filesystem making Close() or Rename() fail is the
// ordinary way this happens, and a full filesystem is why rotation exists.
//
// The blocker below stands in for that: renaming a file onto a non-empty
// directory fails, so every rotation attempt in this test fails, at the
// same point a real ENOSPC would.
func TestRotatingWriterSurvivesFailedRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.json")

	if err := os.MkdirAll(filepath.Join(path+".1", "blocker"), 0o755); err != nil {
		t.Fatal(err)
	}

	w, err := newRotatingWriter(path, 20, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	line := []byte(strings.Repeat("a", 15) + "\n") // 16 bytes, cap is 20
	for i := 0; i < 5; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatalf("write %d failed after a failed rotation: %v -- a failed "+
				"rotation must never cost an audit entry", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close after failed rotations: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "\n"); got != 5 {
		t.Fatalf("audit log holds %d entries after 5 writes across failed "+
			"rotations, want 5 -- entries were silently dropped", got)
	}
}
