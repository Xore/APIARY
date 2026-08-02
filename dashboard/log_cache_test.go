package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFileLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func cowrieLine(sensor, when string) string {
	return `{"eventid":"cowrie.login.success","timestamp":"` + when + `","username":"root","password":"x","session":"` + sensor + `","src_ip":"203.0.113.5"}`
}

// TestClassifiedEventsForSkipsUnchangedFile (#353): an unchanged file (same
// size and mtime as last call) must return the exact previously-cached
// state -- proven by pointer identity, not just equal content, since that's
// the only way to be sure the expensive read+parse path was actually
// skipped rather than coincidentally producing the same result again.
func TestClassifiedEventsForSkipsUnchangedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	writeFileLines(t, path, cowrieLine("a", "2026-01-01T00:00:00Z"))

	s := &store{}
	events, state := s.classifiedEventsFor(path, "cowrie", nil, tailCap)
	if len(events) != 1 || state == nil {
		t.Fatalf("first call: events=%d state=%v", len(events), state)
	}

	events2, state2 := s.classifiedEventsFor(path, "cowrie", state, tailCap)
	if state2 != state {
		t.Fatal("unchanged file must return the exact same cached state (pointer identity), not recompute it")
	}
	if len(events2) != 1 {
		t.Fatalf("unchanged file event count changed: got %d, want 1", len(events2))
	}
}

// TestClassifiedEventsForAppendsOnGrowth (#353): appending new lines to a
// growing file must add exactly the new events while leaving the
// previously-cached ones in place -- the core incremental-read behavior.
func TestClassifiedEventsForAppendsOnGrowth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	writeFileLines(t, path, cowrieLine("a", "2026-01-01T00:00:00Z"))

	s := &store{}
	events, state := s.classifiedEventsFor(path, "cowrie", nil, tailCap)
	if len(events) != 1 {
		t.Fatalf("first call: got %d events, want 1", len(events))
	}

	// Append (not overwrite) -- a real log file only ever grows between
	// truncations/rotations.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(cowrieLine("b", "2026-01-01T00:01:00Z") + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	events2, state2 := s.classifiedEventsFor(path, "cowrie", state, tailCap)
	if len(events2) != 2 {
		t.Fatalf("after growth: got %d events, want 2 (1 cached + 1 new)", len(events2))
	}
	if events2[0].ev.session != "a" || events2[1].ev.session != "b" {
		t.Fatalf("growth did not preserve order/identity of cached + new events: %+v", events2)
	}
	if state2 == state {
		t.Fatal("growth must produce a new cache state, not reuse the stale one")
	}
}

// TestClassifiedEventsForFullRereadOnTruncation (#353): a file that shrank
// (copytruncate rotation) must be treated as entirely fresh content, not
// incorrectly merged with the stale cache from before the truncation.
func TestClassifiedEventsForFullRereadOnTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	writeFileLines(t, path, cowrieLine("a", "2026-01-01T00:00:00Z"), cowrieLine("b", "2026-01-01T00:01:00Z"))

	s := &store{}
	_, state := s.classifiedEventsFor(path, "cowrie", nil, tailCap)

	// Simulate copytruncate: the file is truncated then rewritten with a
	// single, different record.
	writeFileLines(t, path, cowrieLine("c", "2026-01-01T00:02:00Z"))

	events, _ := s.classifiedEventsFor(path, "cowrie", state, tailCap)
	if len(events) != 1 || events[0].ev.session != "c" {
		t.Fatalf("truncation was not treated as fresh content: %+v", events)
	}
}

// TestClassifiedEventsForFallsBackAboveTailCap (#353): once a file's size
// reaches the tail cap, incremental byte tracking can't know which old
// bytes have aged out of readTail's windowing as the file keeps growing --
// this must fall back to exactly readTail's own full-reread behavior (which
// always applies against the real, unparameterized tailCap constant) rather
// than trying to track incremental state at all. A tiny injected
// tailCapBytes exercises the branch decision without a multi-megabyte
// fixture; it does not (and should not) change what readTail itself windows
// against, since that stays pinned to the real 8 MiB constant in
// production.
func TestClassifiedEventsForFallsBackAboveTailCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	small := int64(len(cowrieLine("x", "2026-01-01T00:00:00Z")) + 1) // one line + its newline

	writeFileLines(t, path,
		cowrieLine("old", "2026-01-01T00:00:00Z"),
		cowrieLine("new", "2026-01-01T00:01:00Z"),
	)

	s := &store{}
	events, state := s.classifiedEventsFor(path, "cowrie", nil, small)
	if state.events != nil {
		t.Fatal("the tail-cap fallback path must not retain a cached event list (it never trusts incremental tracking once oversized)")
	}
	// The real tailCap (8 MiB) is far larger than this whole test file, so
	// readTail returns everything -- unlike the incremental path, this
	// fallback must never merge/append, only ever replace wholesale.
	if len(events) != 2 {
		t.Fatalf("tail-cap fallback did not delegate to a plain full readTail: got %d events, want 2", len(events))
	}
}

// TestClassifiedEventsForRetriesIncompleteTrailingLine (#353): a line that's
// still mid-write (no trailing newline yet) must not be consumed -- it has
// to be re-read, complete, on a later call, the same tolerance a full
// reread already has today (an unparseable line just gets retried next
// cycle, never silently dropped).
func TestClassifiedEventsForRetriesIncompleteTrailingLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	complete := cowrieLine("a", "2026-01-01T00:00:00Z")
	partial := `{"eventid":"cowrie.login.success","timestamp":"2026-01-01T00:01`

	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// complete line + newline, then a partial line with NO trailing newline.
	if err := os.WriteFile(path, []byte(complete+"\n"+partial), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{}
	events, state := s.classifiedEventsFor(path, "cowrie", nil, tailCap)
	if len(events) != 1 {
		t.Fatalf("first call: got %d events, want 1 (the partial trailing line must not be consumed)", len(events))
	}

	// The write "completes": the partial line gets its rest + newline
	// appended.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`:00Z","username":"root","password":"x","session":"b","src_ip":"203.0.113.5"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	events2, _ := s.classifiedEventsFor(path, "cowrie", state, tailCap)
	if len(events2) != 2 {
		t.Fatalf("after completion: got %d events, want 2 (previously-incomplete line must now be picked up)", len(events2))
	}
}

// TestRebuildIncrementalMatchesFullRebuild (#353) is the core equivalence
// proof: incremental caching across multiple rebuild() cycles as a file
// grows must produce exactly the same aggregate snapshot as a single
// rebuild() reading the fully-grown file fresh, with no cache involved at
// all.
func TestRebuildIncrementalMatchesFullRebuild(t *testing.T) {
	incrementalRoot := t.TempDir()
	path := filepath.Join(incrementalRoot, "cowrie", "cowrie.json")

	writeFileLines(t, path, cowrieLine("a", "2026-01-01T00:00:00Z"))
	incremental := &store{dir: incrementalRoot}
	incremental.rebuild()

	for i, session := range []string{"b", "c", "d"} {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		when := time.Date(2026, 1, 1, 0, i+1, 0, 0, time.UTC).Format(time.RFC3339)
		if _, err := f.WriteString(cowrieLine(session, when) + "\n"); err != nil {
			t.Fatal(err)
		}
		f.Close()
		incremental.rebuild()
	}

	// A second store, pointed at a fresh copy of the SAME final file
	// content, with no rebuild history / no cache at all.
	freshRoot := t.TempDir()
	freshPath := filepath.Join(freshRoot, "cowrie", "cowrie.json")
	finalBody, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(freshPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(freshPath, finalBody, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := &store{dir: freshRoot}
	fresh.rebuild()

	incSnap, freshSnap := incremental.get(), fresh.get()
	if incSnap.Total != freshSnap.Total {
		t.Fatalf("Total diverged: incremental=%d fresh=%d", incSnap.Total, freshSnap.Total)
	}
	if incSnap.UniqueIPs != freshSnap.UniqueIPs {
		t.Fatalf("UniqueIPs diverged: incremental=%d fresh=%d", incSnap.UniqueIPs, freshSnap.UniqueIPs)
	}
	if len(incremental.getEvents()) != len(fresh.getEvents()) {
		t.Fatalf("event count diverged: incremental=%d fresh=%d", len(incremental.getEvents()), len(fresh.getEvents()))
	}
}

// TestRebuildRejoinsCachedEventOnceViaMapCatchesUp (#353) is the
// correctness-critical case log_cache.go's own header comment documents: a
// sensor event logged before its matching portbridge connect record lands
// must still successfully join to the real attacker IP on a LATER rebuild
// cycle, even though the sensor's own log file didn't change between
// cycles (and its classification therefore came from the cache both
// times). Caching the classify() output but re-running the via-join fresh
// every cycle is what makes this possible; caching the joined result would
// have permanently frozen the miss.
func TestRebuildRejoinsCachedEventOnceViaMapCatchesUp(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	writeLog(t, root, "dionaea/incidents.json", map[string]any{
		"timestamp": now, "origin": "dionaea.connection.tcp.connect",
		"data": map[string]any{"connection": map[string]any{
			"protocol": "smb", "remote_ip": tunnelPeerIP, "remote_port": 41001.0, "local_port": 445.0,
		}},
	})

	s := &store{dir: root}
	s.rebuild()
	if s.get().Unattributed != 1 {
		t.Fatalf("cycle 1: Unattributed=%d, want 1 (no portbridge record exists yet)", s.get().Unattributed)
	}
	for _, event := range s.getEvents() {
		if event.SrcIP != "" {
			t.Fatalf("cycle 1: event was attributed before any portbridge record existed: %+v", event)
		}
	}

	// The portbridge record "lands" -- the dionaea file itself is untouched,
	// so its classification is served entirely from cache on this cycle.
	writeLog(t, root, "portbridge/portbridge.json", map[string]any{
		"time": now, "sensor": "portbridge", "event": "connect", "proto": "tcp",
		"port": 445.0, "src_ip": "203.0.113.9", "src_port": 41001.0, "via_port": 41001.0,
	})
	s.rebuild()

	if s.get().Unattributed != 0 {
		t.Fatalf("cycle 2: Unattributed=%d, want 0 (the cached event must still get a chance to join)", s.get().Unattributed)
	}
	found := false
	for _, event := range s.getEvents() {
		if event.SrcIP == "203.0.113.9" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cycle 2: cached event was never rejoined to the real IP once viaMap caught up: %+v", s.getEvents())
	}
}

// TestRebuildPrunesLogCacheForRemovedFiles (#353): a rotated-away or deleted
// file must not linger in the cache forever -- rebuild() rebuilds the cache
// map from only the files logFiles() finds each cycle, which is the prune.
func TestRebuildPrunesLogCacheForRemovedFiles(t *testing.T) {
	root := t.TempDir()
	keep := filepath.Join(root, "cowrie", "cowrie.json")
	gone := filepath.Join(root, "multipot", "multipot.json")
	writeFileLines(t, keep, cowrieLine("a", "2026-01-01T00:00:00Z"))
	writeFileLines(t, gone, `{"eventid":"connect","timestamp":"2026-01-01T00:00:00Z","src_ip":"203.0.113.5"}`)

	s := &store{dir: root}
	s.rebuild()
	if _, ok := s.logCache[gone]; !ok {
		t.Fatal("expected the multipot file to be cached after its first rebuild")
	}

	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	s.rebuild()
	if _, ok := s.logCache[gone]; ok {
		t.Fatal("a removed file's cache entry must be pruned, not retained indefinitely")
	}
	if _, ok := s.logCache[keep]; !ok {
		t.Fatal("pruning the removed file's entry must not disturb the still-present file's cache entry")
	}
}
