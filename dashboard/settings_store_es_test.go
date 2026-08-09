package main

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

// testSettingsDoc is a minimal document type for exercising esSettingsStore
// without coupling these tests to dashboardConfig/usersDocument/
// reportsDocument's own evolving schemas.
type testSettingsDoc struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func validateTestSettingsDoc(doc testSettingsDoc) error {
	if doc.Count < 0 {
		return errors.New("count must not be negative")
	}
	return nil
}

// newTestESSettingsStore constructs a store against a fresh in-memory
// Elasticsearch stand-in (memESDocStore, defined in alerts_test.go), using
// the real production poll interval -- these tests only need Get/Update
// semantics, never an actual poll tick, so there's nothing to wait for.
func newTestESSettingsStore(t *testing.T) *esSettingsStore[testSettingsDoc] {
	t.Helper()
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	t.Cleanup(srv.Close)
	es := newESClient(srv.URL, "")
	return newESSettingsStore(es, "test-settings-v1", "singleton", testSettingsDoc{}, validateTestSettingsDoc)
}

func TestESSettingsStoreGetDefaultsOnEmptyStore(t *testing.T) {
	store := newTestESSettingsStore(t)
	doc, etag := store.Get()
	if doc.Name != "" || doc.Count != 0 {
		t.Fatalf("expected zero-value defaults on an empty store, got %+v", doc)
	}
	if etag == "" {
		t.Fatal("expected a non-empty ETag even for the default payload")
	}
	if store.Degraded() {
		t.Fatal("an empty (never-written) document is a normal state, not degraded")
	}
	if store.ReadOnly() {
		t.Fatal("a reachable Elasticsearch with no document yet must not be read-only")
	}
}

func TestESSettingsStoreUpdateAndGet(t *testing.T) {
	store := newTestESSettingsStore(t)
	etag, changed, err := store.Update("", func(doc *testSettingsDoc) error {
		doc.Name = "alice"
		doc.Count = 1
		return nil
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if etag == "" {
		t.Fatal("expected a non-empty ETag from a successful Update")
	}
	if len(changed) == 0 {
		t.Fatal("expected changedFields to report at least one changed field")
	}
	doc, getEtag := store.Get()
	if doc.Name != "alice" || doc.Count != 1 {
		t.Fatalf("Get after Update returned %+v, want Name=alice Count=1", doc)
	}
	if getEtag != etag {
		t.Fatalf("Get's ETag %q does not match Update's returned ETag %q", getEtag, etag)
	}
}

func TestESSettingsStoreStaleETagRejected(t *testing.T) {
	store := newTestESSettingsStore(t)
	if _, _, err := store.Update("", func(doc *testSettingsDoc) error { doc.Count = 1; return nil }); err != nil {
		t.Fatalf("seed Update failed: %v", err)
	}
	_, _, err := store.Update(`"r0-stale000000"`, func(doc *testSettingsDoc) error { doc.Count = 2; return nil })
	if !errors.Is(err, errStaleRevision) {
		t.Fatalf("Update with a stale If-Match: got err=%v, want errStaleRevision", err)
	}
	doc, _ := store.Get()
	if doc.Count != 1 {
		t.Fatalf("a rejected Update must not change the stored document, got Count=%d", doc.Count)
	}
}

func TestESSettingsStoreWeakETagAccepted(t *testing.T) {
	store := newTestESSettingsStore(t)
	etag, _, err := store.Update("", func(doc *testSettingsDoc) error { doc.Count = 1; return nil })
	if err != nil {
		t.Fatalf("seed Update failed: %v", err)
	}
	// A proxy in front of the real dashboard can downgrade a strong ETag to
	// weak on a compressed response (#177) -- the client then echoes the
	// weak form back as If-Match, which stripWeakPrefix must still accept.
	if _, _, err := store.Update("W/"+etag, func(doc *testSettingsDoc) error { doc.Count = 2; return nil }); err != nil {
		t.Fatalf("Update with a weak-prefixed but otherwise current If-Match: got err=%v, want success", err)
	}
	doc, _ := store.Get()
	if doc.Count != 2 {
		t.Fatalf("Get after a weak-ETag Update returned Count=%d, want 2", doc.Count)
	}
}

func TestESSettingsStoreValidationFailureLeavesStateUntouched(t *testing.T) {
	store := newTestESSettingsStore(t)
	if _, _, err := store.Update("", func(doc *testSettingsDoc) error { doc.Count = 5; return nil }); err != nil {
		t.Fatalf("seed Update failed: %v", err)
	}
	_, _, err := store.Update("", func(doc *testSettingsDoc) error { doc.Count = -1; return nil })
	if err == nil {
		t.Fatal("expected validateTestSettingsDoc to reject a negative Count")
	}
	doc, _ := store.Get()
	if doc.Count != 5 {
		t.Fatalf("a failed validation must not change the stored document, got Count=%d", doc.Count)
	}
}

func TestESSettingsStoreConcurrentUpdateRetries(t *testing.T) {
	store := newTestESSettingsStore(t)
	if _, _, err := store.Update("", func(doc *testSettingsDoc) error { doc.Count = 0; return nil }); err != nil {
		t.Fatalf("seed Update failed: %v", err)
	}
	const writers = 5
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func() {
			_, _, err := store.Update("", func(doc *testSettingsDoc) error {
				doc.Count++
				return nil
			})
			errs <- err
		}()
	}
	for i := 0; i < writers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Update %d failed (retry-on-conflict should have absorbed the race): %v", i, err)
		}
	}
	doc, _ := store.Get()
	if doc.Count != writers {
		t.Fatalf("after %d concurrent increments, Count=%d, want %d -- a losing compare-and-swap was not correctly retried", writers, doc.Count, writers)
	}
}

func TestESSettingsStoreNilESIsPermanentlyDegraded(t *testing.T) {
	store := newESSettingsStore[testSettingsDoc](nil, "test-settings-v1", "singleton", testSettingsDoc{}, validateTestSettingsDoc)
	if !store.Degraded() {
		t.Fatal("a store with no Elasticsearch client must report Degraded")
	}
	if !store.ReadOnly() {
		t.Fatal("a store with no Elasticsearch client must report ReadOnly")
	}
	if _, _, err := store.Update("", func(doc *testSettingsDoc) error { doc.Count = 1; return nil }); !errors.Is(err, errStoreReadOnly) {
		t.Fatalf("Update on a nil-ES store: got err=%v, want errStoreReadOnly", err)
	}
	doc, _ := store.Get()
	if doc.Name != "" || doc.Count != 0 {
		t.Fatalf("a nil-ES store must keep serving compiled defaults, got %+v", doc)
	}
}

// TestESSettingsStoreReadOnlySelfHealsAfterOutage uses
// newESSettingsStoreWithPollInterval (a short, test-only interval) instead
// of mutating any shared state -- each store's poll interval is a field set
// once at construction and read only by that store's own goroutine, so
// tests running concurrently (or leaving goroutines running past their own
// return, since pollLoop is never explicitly stopped) can't race each
// other the way an earlier version of this test did when it mutated a
// shared package var instead (caught live by go test -race).
func TestESSettingsStoreReadOnlySelfHealsAfterOutage(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	es := newESClient(srv.URL, "")
	store := newESSettingsStoreWithPollInterval(es, "test-settings-v1", "singleton", testSettingsDoc{}, validateTestSettingsDoc, 20*time.Millisecond)

	// Take the server down: the next poll tick should mark the store
	// read-only (a transient Elasticsearch outage), not permanently latch
	// it the way the old file-backed store's corrupt-file case did.
	srv.Close()
	waitFor(t, 2*time.Second, func() bool { return store.ReadOnly() })

	// A stopped httptest.Server's URL is now unroutable, so refresh() will
	// keep failing until we point the client at a live server again --
	// restart the same handler on a fresh listener and swap the client's
	// base URL the same way esClient's own tests do for outage scenarios.
	// store.es is otherwise write-once (set at construction, never mutated
	// again in production), but refresh()/Update() both read it under
	// s.mu, so this direct write is still race-free.
	srv2 := httptest.NewServer(memStore.handler())
	t.Cleanup(srv2.Close)
	store.mu.Lock()
	store.es = newESClient(srv2.URL, "")
	store.mu.Unlock()

	waitFor(t, 2*time.Second, func() bool { return !store.ReadOnly() })
	if store.Degraded() {
		t.Fatal("a store that already loaded real state before the outage must not become Degraded just from a transient outage")
	}
}

// TestESSettingsStoreCrossInstanceVisibility is the actual regression test
// for #787: two independent esSettingsStore instances (standing in for the
// dashboard's two replicas) against the same backing Elasticsearch. A write
// through one must become visible on the other within one poll tick,
// without either instance being restarted -- reproducing, and proving
// fixed, the exact bug where /agent-campaigns 404'd on every other request
// once a setting was toggled via the other replica.
func TestESSettingsStoreCrossInstanceVisibility(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	t.Cleanup(srv.Close)

	esA := newESClient(srv.URL, "")
	esB := newESClient(srv.URL, "")
	replicaA := newESSettingsStoreWithPollInterval(esA, "test-settings-v1", "singleton", testSettingsDoc{}, validateTestSettingsDoc, 20*time.Millisecond)
	replicaB := newESSettingsStoreWithPollInterval(esB, "test-settings-v1", "singleton", testSettingsDoc{}, validateTestSettingsDoc, 20*time.Millisecond)

	if _, _, err := replicaA.Update("", func(doc *testSettingsDoc) error {
		doc.Name = "toggled-via-replica-a"
		doc.Count = 42
		return nil
	}); err != nil {
		t.Fatalf("Update through replica A failed: %v", err)
	}

	// replicaA sees its own write immediately (no poll wait needed).
	docA, _ := replicaA.Get()
	if docA.Name != "toggled-via-replica-a" {
		t.Fatalf("replica A did not see its own write immediately: %+v", docA)
	}

	// replicaB must see it too, within one poll tick -- this is the bug
	// this whole migration exists to fix.
	waitFor(t, 2*time.Second, func() bool {
		doc, _ := replicaB.Get()
		return doc.Name == "toggled-via-replica-a" && doc.Count == 42
	})
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %s", timeout)
	}
}
