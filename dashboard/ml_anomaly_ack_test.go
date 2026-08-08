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
func TestApplyMLAnomalyAcksJoinsWithoutMutatingCache(t *testing.T) {
	s := &store{mlAnomalyAcks: newTestMLAnomalyAckManager(t)}
	s.mlAnomalyAcks.acknowledge("anomaly-1", true, "alice")

	items := []mlAnomaly{{AnomalyID: "anomaly-1"}, {AnomalyID: "anomaly-2"}}
	s.applyMLAnomalyAcks(items)
	if !items[0].Acknowledged || items[0].AckedBy != "alice" {
		t.Errorf("anomaly-1 not joined: %+v", items[0])
	}
	if items[1].Acknowledged {
		t.Errorf("anomaly-2 should stay open: %+v", items[1])
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
