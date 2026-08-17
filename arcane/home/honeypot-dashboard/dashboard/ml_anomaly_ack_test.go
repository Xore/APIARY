package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMLAnomalyAckManagerNilWithoutES must return nil (acknowledgment
// disabled, not a local-file fallback) when Elasticsearch is not configured
// -- mirrors TestNewAlertManagerNilWithoutES in alerts_test.go, since every
// call site relies on this via `s.mlAnomalyAcks == nil ||` /
// `s.mlAnomalyAcks == nil` guards.
func TestNewMLAnomalyAckManagerNilWithoutES(t *testing.T) {
	if m := newMLAnomalyAckManager(nil); m != nil {
		t.Fatalf("expected nil mlAnomalyAckManager without an ES client, got %+v", m)
	}
}

func newTestMLAnomalyAckManager(t *testing.T) *mlAnomalyAckManager {
	t.Helper()
	store := newMemESDocStore()
	srv := httptest.NewServer(store.handler())
	t.Cleanup(srv.Close)
	es := newESClient(srv.URL, "")
	return newMLAnomalyAckManager(es)
}

// Acknowledging a key that has never been written before must create the
// record rather than fail: unlike alertManager.acknowledge (which requires
// observe() to have run first), ml-worker -- not this dashboard -- owns
// anomaly creation, so there is no equivalent write path to pre-seed one.
func TestMLAnomalyAcknowledgeCreatesOnFirstWrite(t *testing.T) {
	m := newTestMLAnomalyAckManager(t)
	if !m.acknowledge("anomaly-1", true, "alice") {
		t.Fatal("acknowledge on a never-seen key should succeed")
	}
	acked := m.acknowledged()
	r, ok := acked["anomaly-1"]
	if !ok {
		t.Fatalf("anomaly-1 not present in acknowledged(): %+v", acked)
	}
	if r.AckedBy != "alice" {
		t.Errorf("AckedBy = %q, want alice", r.AckedBy)
	}
	if r.AckedAt.IsZero() {
		t.Error("AckedAt was not set")
	}
}

// Reopening must clear the record out of acknowledged() (it is filtered to
// Acknowledged==true) even though the ES document itself still exists.
func TestMLAnomalyReopenClearsAcknowledgedState(t *testing.T) {
	m := newTestMLAnomalyAckManager(t)
	if !m.acknowledge("anomaly-1", true, "alice") {
		t.Fatal("acknowledge failed")
	}
	if !m.acknowledge("anomaly-1", false, "") {
		t.Fatal("reopen failed")
	}
	if acked := m.acknowledged(); len(acked) != 0 {
		t.Fatalf("acknowledged() after reopen = %+v, want empty", acked)
	}
	// The AckedBy/AckedAt bookkeeping is cleared on reopen too, not just the
	// flag -- a later re-acknowledge by a different operator must not show
	// the previous one's name.
	hit, found, err := m.es.docGet(mlAnomalyAckIndex, "anomaly-1")
	if err != nil || !found {
		t.Fatalf("docGet: found=%v err=%v", found, err)
	}
	if strings.Contains(string(hit.Source), "alice") {
		t.Fatalf("reopened record still references the prior acker: %s", hit.Source)
	}
}

// applyMLAnomalyAcks joins the snapshot against ack state without mutating
// the underlying cache -- a re-snapshot later must reflect the current ack
// state, not whatever was true the first time a snapshot was joined.
//
// applyMLAnomalyAcks reads mlAnomalyAckManager's own polled cache (#1157-
// sweep: acknowledged() itself is a full, unbounded ES scan and must not
// run on this read path per-request), so this test polls explicitly via
// refresh() first, the same way the background ticker in main.go would.
func TestApplyMLAnomalyAcksJoinsWithoutMutatingCache(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t)}
	s.mlAnomalyAcks.acknowledge("anomaly-1", true, "alice")
	s.mlAnomalyAcks.refresh()

	items := []mlAnomaly{{AnomalyID: "anomaly-1"}, {AnomalyID: "anomaly-2"}}
	s.applyMLAnomalyAcks(items)
	if !items[0].Acknowledged || items[0].AckedBy != "alice" {
		t.Errorf("anomaly-1 not joined: %+v", items[0])
	}
	if items[1].Acknowledged {
		t.Errorf("anomaly-2 should stay open: %+v", items[1])
	}
}

// Before refresh() has ever run (cache still nil, e.g. between process
// start and the first synchronous poll main.go does at startup),
// applyMLAnomalyAcks must leave every item un-acknowledged rather than
// panicking on a nil map read.
func TestApplyMLAnomalyAcksNoopBeforeFirstRefresh(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t)}
	s.mlAnomalyAcks.acknowledge("anomaly-1", true, "alice") // written to ES, never polled

	items := []mlAnomaly{{AnomalyID: "anomaly-1"}}
	s.applyMLAnomalyAcks(items)
	if items[0].Acknowledged {
		t.Errorf("un-polled ack state must not be visible yet: %+v", items[0])
	}
}

// refresh() must poll acknowledged() into the cache, and cached() must
// return exactly what the last refresh() saw -- the read path
// (applyMLAnomalyAcks) depends on both holding.
func TestMLAnomalyAckManagerRefreshPopulatesCache(t *testing.T) {
	m := newTestMLAnomalyAckManager(t)
	m.acknowledge("anomaly-1", true, "alice")
	if cached := m.cached(); len(cached) != 0 {
		t.Fatalf("cached() before any refresh() = %+v, want empty", cached)
	}
	m.refresh()
	cached := m.cached()
	r, ok := cached["anomaly-1"]
	if !ok || r.AckedBy != "alice" {
		t.Fatalf("cached() after refresh() = %+v, want anomaly-1 acked by alice", cached)
	}
}

// A reopen must clear the key out of the cache too, once polled -- the
// cache is a wholesale replacement on every refresh(), not an incremental
// merge, so stale acknowledged entries cannot survive a reopen.
func TestMLAnomalyAckManagerRefreshReflectsReopen(t *testing.T) {
	m := newTestMLAnomalyAckManager(t)
	m.acknowledge("anomaly-1", true, "alice")
	m.refresh()
	m.acknowledge("anomaly-1", false, "")
	m.refresh()
	if cached := m.cached(); len(cached) != 0 {
		t.Fatalf("cached() after reopen+refresh() = %+v, want empty", cached)
	}
}

// A nil mlAnomalyAcks (Elasticsearch not configured) must leave every item
// un-acknowledged rather than panicking or erroring -- the same posture
// mlAnomaliesData's own "Enabled" gate already takes elsewhere on this page.
func TestApplyMLAnomalyAcksNoopWithoutManager(t *testing.T) {
	s := &store{}
	items := []mlAnomaly{{AnomalyID: "anomaly-1"}}
	s.applyMLAnomalyAcks(items)
	if items[0].Acknowledged {
		t.Error("nil mlAnomalyAcks must not acknowledge anything")
	}
}

func TestServeMLAnomalyAckAcknowledgesAndRedirects(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t)}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/ml-anomalies/ack",
		strings.NewReader("key=anomaly-1&ack=true&return=/ml-anomalies"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveMLAnomalyAck(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/ml-anomalies" {
		t.Fatalf("Location = %q, want /ml-anomalies", loc)
	}
	acked := s.mlAnomalyAcks.acknowledged()
	if _, ok := acked["anomaly-1"]; !ok {
		t.Fatalf("anomaly-1 not acknowledged: %+v", acked)
	}
	// serveMLAnomalyAck must refresh the cache inline (#1157-sweep) -- the
	// operator's own action must be visible on the very next page load, not
	// stale for up to a minute until the next background poll.
	if cached := s.mlAnomalyAcks.cached(); !cached["anomaly-1"].Acknowledged {
		t.Fatalf("cache not refreshed inline after ack write: %+v", cached)
	}
}

// A return path outside the /ml-anomalies allowlist must fall back to the
// plain page, not redirect wherever the form happened to say -- the same
// open-redirect guard sandbox/ghidra/github-analysis submit already share.
func TestServeMLAnomalyAckRejectsUnlistedReturnPath(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t)}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/ml-anomalies/ack",
		strings.NewReader("key=anomaly-1&ack=true&return=https://evil.example/"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveMLAnomalyAck(w, r)

	if loc := w.Header().Get("Location"); loc != "/ml-anomalies" {
		t.Fatalf("Location = %q, want the safe fallback /ml-anomalies", loc)
	}
}

func TestServeMLAnomalyAckRequiresPOST(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t)}
	r := httptest.NewRequest(http.MethodGet, "https://honeypot.example/ml-anomalies/ack", nil)
	w := httptest.NewRecorder()
	s.serveMLAnomalyAck(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", w.Code)
	}
}

func TestServeMLAnomalyAckRequiresKey(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t)}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/ml-anomalies/ack",
		strings.NewReader("ack=true"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveMLAnomalyAck(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 for a missing key", w.Code)
	}
}

// Not configured (nil manager) must be refused explicitly, not silently
// treated as success -- the operator's click did not actually change
// anything, and the redirect-only success path would otherwise hide that.
func TestServeMLAnomalyAckRefusedWhenUnconfigured(t *testing.T) {
	s := &store{}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/ml-anomalies/ack",
		strings.NewReader("key=anomaly-1&ack=true"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveMLAnomalyAck(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", w.Code)
	}
}

func TestServeMLAnomalyAckRejectsCrossOrigin(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t)}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/ml-anomalies/ack",
		strings.NewReader("key=anomaly-1&ack=true"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.serveMLAnomalyAck(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", w.Code)
	}
}

// acknowledgeAllKeys (#1566) must flip every key it's given and skip blanks
// -- mirrors alertManager.acknowledgeAll's "changed" count, but keyed off a
// caller-supplied ID list rather than its own index scan (see the method's
// own doc comment for why: ml-worker, not this manager, owns anomaly
// identity).
func TestMLAnomalyAcknowledgeAllKeysAcknowledgesEveryKey(t *testing.T) {
	m := newTestMLAnomalyAckManager(t)
	changed := m.acknowledgeAllKeys([]string{"anomaly-1", "anomaly-2", "", "anomaly-3"}, "alice")
	if changed != 3 {
		t.Fatalf("acknowledgeAllKeys changed = %d, want 3", changed)
	}
	acked := m.acknowledged()
	for _, key := range []string{"anomaly-1", "anomaly-2", "anomaly-3"} {
		if !acked[key].Acknowledged {
			t.Errorf("%s not acknowledged: %+v", key, acked)
		}
	}
}

func newTestMLAnomaliesStore(t *testing.T, items ...mlAnomaly) *mlAnomalyStore {
	t.Helper()
	c := &mlAnomalyStore{}
	c.absorb(items)
	return c
}

// serveMLAnomalyAckAll's "acknowledge all" must act on every currently
// unacknowledged anomaly in the full polled snapshot -- not just whatever a
// filter bar happens to be narrowing the page to -- the same "every open
// one, plus anything the page doesn't show" semantics /alerts' own
// acknowledge-all uses (alerts_test.go's
// TestAcknowledgeAllCoversRecordsThePageNeverShows).
func TestServeMLAnomalyAckAllAcknowledgesEveryOpenAnomaly(t *testing.T) {
	acks := newTestMLAnomalyAckManager(t)
	anomalies := newTestMLAnomaliesStore(t,
		mlAnomaly{AnomalyID: "anomaly-1", Timestamp: "2026-08-01T12:00:00Z"},
		mlAnomaly{AnomalyID: "anomaly-2", Timestamp: "2026-08-01T12:01:00Z"},
	)
	// anomaly-2 is already acknowledged going in -- acknowledgeAllKeys must
	// not be asked to touch it again (acknowledged() below would still show
	// it acknowledged either way, but re-acking would be wasted ES writes).
	if !acks.acknowledge("anomaly-2", true, "bob") {
		t.Fatal("seed acknowledge failed")
	}
	acks.refresh()
	s := &store{mlAnomalyAcks: acks, mlAnomalies: anomalies}

	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/ml-anomalies/ack-all",
		strings.NewReader("return=/ml-anomalies"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveMLAnomalyAckAll(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/ml-anomalies" {
		t.Fatalf("Location = %q, want /ml-anomalies", loc)
	}
	acked := s.mlAnomalyAcks.acknowledged()
	if !acked["anomaly-1"].Acknowledged {
		t.Fatalf("anomaly-1 not acknowledged: %+v", acked)
	}
	if !acked["anomaly-2"].Acknowledged {
		t.Fatalf("anomaly-2 (already acked) should still show acknowledged: %+v", acked)
	}
}

func TestServeMLAnomalyAckAllRequiresPOST(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t), mlAnomalies: newTestMLAnomaliesStore(t)}
	r := httptest.NewRequest(http.MethodGet, "https://honeypot.example/ml-anomalies/ack-all", nil)
	w := httptest.NewRecorder()
	s.serveMLAnomalyAckAll(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", w.Code)
	}
}

func TestServeMLAnomalyAckAllRefusedWhenUnconfigured(t *testing.T) {
	s := &store{}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/ml-anomalies/ack-all", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveMLAnomalyAckAll(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", w.Code)
	}
}

func TestServeMLAnomalyAckAllRejectsCrossOrigin(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t), mlAnomalies: newTestMLAnomaliesStore(t)}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/ml-anomalies/ack-all", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.serveMLAnomalyAckAll(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", w.Code)
	}
}
