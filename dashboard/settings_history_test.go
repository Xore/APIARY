package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeHistoryLines writes raw JSON lines to path, one entry per line, no
// trailing rotation logic — just the on-disk shape append() produces.
func writeHistoryLines(t *testing.T, path string, entries []configHistoryEntry) {
	t.Helper()
	var buf []byte
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Regression test for #1334: once the history file has rotated, read() must
// still return the live generation's entries as the newest, not the stale
// rotated (.1) generation.
func TestConfigHistoryReadReturnsLiveGenerationBeforeRotated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings-history.jsonl")

	older := []configHistoryEntry{
		{Revision: 1, Action: "update", Time: time.Unix(100, 0).UTC()},
		{Revision: 2, Action: "update", Time: time.Unix(200, 0).UTC()},
		{Revision: 3, Action: "update", Time: time.Unix(300, 0).UTC()},
	}
	newer := []configHistoryEntry{
		{Revision: 4, Action: "update", Time: time.Unix(400, 0).UTC()},
		{Revision: 5, Action: "update", Time: time.Unix(500, 0).UTC()},
		{Revision: 6, Action: "update", Time: time.Unix(600, 0).UTC()},
	}
	writeHistoryLines(t, path+".1", older)
	writeHistoryLines(t, path, newer)

	h := newConfigHistory(path)

	got := h.read(4)
	if len(got) != 4 {
		t.Fatalf("read(4): got %d entries, want 4: %+v", len(got), got)
	}
	want := []int64{6, 5, 4, 3}
	for i, rev := range want {
		if got[i].Revision != rev {
			t.Errorf("read(4)[%d].Revision = %d, want %d (full result: %+v)", i, got[i].Revision, rev, got)
		}
	}
}

// Regression test for #1334's rollback failure mode: once the rotated
// generation alone holds >= configHistoryReadLimit lines, find() must still
// be able to locate a revision that only exists in the live generation.
func TestConfigHistoryFindLocatesLiveRevisionPastRotatedLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings-history.jsonl")

	older := make([]configHistoryEntry, 0, configHistoryReadLimit)
	for i := int64(0); i < configHistoryReadLimit; i++ {
		older = append(older, configHistoryEntry{
			Revision: i,
			Action:   "update",
			Time:     time.Unix(i, 0).UTC(),
		})
	}
	newest := configHistoryEntry{
		Revision: configHistoryReadLimit + 1,
		Action:   "update",
		Time:     time.Unix(int64(configHistoryReadLimit+1), 0).UTC(),
	}
	writeHistoryLines(t, path+".1", older)
	writeHistoryLines(t, path, []configHistoryEntry{newest})

	h := newConfigHistory(path)

	entry, ok := h.find(newest.Revision)
	if !ok {
		t.Fatalf("find(%d) = not found, want the live-generation entry to be reachable", newest.Revision)
	}
	if entry.Revision != newest.Revision {
		t.Errorf("find(%d).Revision = %d, want %d", newest.Revision, entry.Revision, newest.Revision)
	}
}
