package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPayloadsDataDisabledWithoutESClient covers #483's "ES only, no local
// fallback" directive: even with real payload directories configured and
// files present on disk, /payloads must report Enabled=false (not fall back
// to a direct disk scan) when no Elasticsearch client is configured.
func TestPayloadsDataDisabledWithoutESClient(t *testing.T) {
	dir := t.TempDir()
	writeTestPayload(t, dir, strings.Repeat("a", 64), time.Now())

	s := &store{payloadDirs: []string{dir}}
	page := s.payloadsData(payloadsFilter{})
	if page.Enabled {
		t.Fatal("payloads must be Enabled=false without a configured ES client, even with real payload dirs present")
	}
}

// TestRefreshPayloadCacheAsyncNoopWithoutES proves the indexer/refresh loop
// does nothing at all (no disk walk, no cache population) when Elasticsearch
// isn't configured -- there is deliberately no local-scan fallback to run.
func TestRefreshPayloadCacheAsyncNoopWithoutES(t *testing.T) {
	dir := t.TempDir()
	writeTestPayload(t, dir, strings.Repeat("b", 64), time.Now())

	s := &store{payloadDirs: []string{dir}}
	s.refreshPayloadCacheAsync()
	if !s.payloadCacheAt.IsZero() {
		t.Fatal("refreshPayloadCacheAsync populated the cache without a configured ES client")
	}
}

func TestIndexPayloadInventoryWritesAndSkipsUnchangedOnRescan(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	hash := strings.Repeat("c", 64)
	files := []capturedFile{{Hash: hash, Size: 3, SizeH: "3 B", Mtime: "2026-08-01 00:00", MIME: "text/plain", Sources: []string{"cowrie"}, Copies: 1}}

	indexPayloadInventory(es, files)
	hit, found, err := es.docGet(payloadInventoryIndex, hash)
	if err != nil || !found {
		t.Fatalf("expected the file to be indexed: found=%v err=%v", found, err)
	}
	var stored capturedFile
	if err := json.Unmarshal(hit.Source, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Hash != hash || stored.Sources[0] != "cowrie" {
		t.Fatalf("unexpected stored document: %+v", stored)
	}
	firstSeqNo := hit.SeqNo

	// A rescan of the exact same, unchanged file must not rewrite the
	// document -- reindexing every file on every TTL tick regardless of
	// whether anything changed would make Elasticsearch traffic scale with
	// scan frequency instead of actual capture-directory churn.
	indexPayloadInventory(es, files)
	hit2, found2, err := es.docGet(payloadInventoryIndex, hash)
	if err != nil || !found2 {
		t.Fatalf("expected the file to still be indexed after rescan: found=%v err=%v", found2, err)
	}
	if hit2.SeqNo != firstSeqNo {
		t.Fatalf("unchanged file was rewritten on rescan: seq_no went from %d to %d", firstSeqNo, hit2.SeqNo)
	}

	// A real change (e.g. the same hash showing up under an additional
	// source directory) must still be written through.
	files[0].Sources = []string{"cowrie", "dionaea"}
	files[0].Copies = 2
	indexPayloadInventory(es, files)
	hit3, found3, err := es.docGet(payloadInventoryIndex, hash)
	if err != nil || !found3 {
		t.Fatalf("expected the changed file to still be indexed: found=%v err=%v", found3, err)
	}
	if hit3.SeqNo == firstSeqNo {
		t.Fatal("a real change to the document was not written (seq_no unchanged)")
	}
	var updated capturedFile
	if err := json.Unmarshal(hit3.Source, &updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Sources) != 2 || updated.Copies != 2 {
		t.Fatalf("update did not persist the new Sources/Copies: %+v", updated)
	}
}

func TestReadPayloadInventoryAggregatesSourcesAndTotals(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	files := []capturedFile{
		{Hash: strings.Repeat("d", 64), Size: 100, Mtime: "2026-08-01 00:00", Sources: []string{"cowrie"}},
		{Hash: strings.Repeat("e", 64), Size: 200, Mtime: "2026-08-02 00:00", Sources: []string{"cowrie", "dionaea"}},
	}
	indexPayloadInventory(es, files)

	page, err := readPayloadInventory(es)
	if err != nil {
		t.Fatal(err)
	}
	if page.UniqueTotal != 2 {
		t.Fatalf("UniqueTotal = %d, want 2", page.UniqueTotal)
	}
	if len(page.Files) != 2 {
		t.Fatalf("got %d files, want 2", len(page.Files))
	}
	// Newest Mtime first, matching scanPayloads' own ordering.
	if page.Files[0].Hash != strings.Repeat("e", 64) {
		t.Fatalf("Files not sorted newest-Mtime-first: %+v", page.Files)
	}
	bySource := map[string]int{}
	for _, s := range page.Sources {
		bySource[s.Name] = s.Count
	}
	if bySource["cowrie"] != 2 || bySource["dionaea"] != 1 {
		t.Fatalf("unexpected per-source counts: %+v", page.Sources)
	}
}

// TestRefreshPayloadCacheAsyncServesFromESWithoutScanningDisk covers #1202:
// payload-inventory-worker (#1201) now owns the disk walk and writes
// payloadInventoryIndex directly -- refreshPayloadCacheAsync's job is only
// to read what's already there and serve it, never to scan payloadDirs
// itself. Deliberately configures payloadDirs pointing at an *empty*
// directory (no file on disk at all) to prove the cache is populated purely
// from a pre-seeded Elasticsearch document, not from any local scan.
func TestRefreshPayloadCacheAsyncServesFromESWithoutScanningDisk(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	hash := strings.Repeat("f", 64)
	// Seeded directly via indexPayloadInventory, the same call
	// payload-inventory-worker makes -- simulating that worker's prior
	// write, not this dashboard instance's own disk scan.
	indexPayloadInventory(es, []capturedFile{{Hash: hash, Size: 13, SizeH: "13 B", Mtime: "2026-08-01 00:00", MIME: "text/plain", Sources: []string{"cowrie"}, Copies: 1}})

	s := &store{payloadDirs: []string{t.TempDir()}, es: es}
	s.refreshPayloadCacheAsync()

	// refreshPayloadCacheAsync does its work in a background goroutine;
	// poll briefly rather than sleeping a fixed duration.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.payloadMu.Lock()
		ready := !s.payloadCacheAt.IsZero()
		s.payloadMu.Unlock()
		if ready {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.payloadMu.Lock()
	cache := s.payloadCache
	s.payloadMu.Unlock()
	if len(cache.Files) != 1 || cache.Files[0].Hash != hash {
		t.Fatalf("expected the ES-seeded file to reach the cache via a plain read, with no matching file ever on disk: %+v", cache.Files)
	}
}
