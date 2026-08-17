package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ml_anomaly_ack.go closes #913: ml_anomalies.go had no acknowledge/dismiss
// action, unlike the structurally identical alerts queue (alerts.go) --
// same category of "thing an operator needs to triage", no way to mark one
// reviewed. Reuses alertManager's own ES-backed, optimistic-concurrency
// shape (docGet/docIndex/errESConflict retry loop) against a second,
// dedicated index rather than folding anomalies into alertIndex itself:
// alertRecord carries fields (Message, Link, cooldown-driven LastNotified)
// that don't apply to an ml anomaly, and /alerts' own list must not start
// showing ML anomalies mixed in with rule-based alerts.

// mlAnomalyAckIndex is the dashboard-owned Elasticsearch index storing ack
// state for ml-anomalies documents, keyed by the anomaly's own ES document
// ID (worker.py's write_anomaly() sets id=anomaly_doc_id(source_index,
// source_event_id) deterministically -- see refreshMLAnomalies, which reads
// that same _id off each search hit rather than recomputing it independently
// in Go). Same reasoning as alertIndex (#494): no local-file fallback, two
// dashboard instances must agree on ack state.
const mlAnomalyAckIndex = "dashboard-ml-anomaly-ack-v1"

type mlAnomalyAckRecord struct {
	Key          string
	Acknowledged bool
	AckedBy      string    `json:",omitempty"`
	AckedAt      time.Time `json:",omitempty"`
}

// mlAnomalyAckManager mirrors alertManager for writes (acknowledge is always
// a live, optimistic-concurrency Elasticsearch round-trip -- two dashboard
// instances, or two requests, can race to acknowledge the same anomaly, and
// a write must see the current state to resolve that race). Reads are
// different: acknowledged() itself is a full, unbounded (size=10000)
// index scan, so applyMLAnomalyAcks (the read path, called on every
// /ml-anomalies and /api/ml/anomalies request) reads a polled cache instead
// of hitting Elasticsearch per request -- see cache/refresh/cached below,
// same "poll on the 1-minute ticker, read the snapshot" shape as
// mlAnomalyStore/llmAnalysisStore/agentCampaignStore.
type mlAnomalyAckManager struct {
	es *esClient

	mu    sync.RWMutex
	cache map[string]mlAnomalyAckRecord
}

// newMLAnomalyAckManager returns nil when es is nil (Elasticsearch not
// configured) -- every call site already treats a nil manager as
// "acknowledgment disabled", the same posture newAlertManager's own callers
// take.
func newMLAnomalyAckManager(es *esClient) *mlAnomalyAckManager {
	if es == nil {
		return nil
	}
	return &mlAnomalyAckManager{es: es}
}

const mlAnomalyAckWriteRetries = 5

// acknowledge flips one anomaly's Acknowledged flag, retrying on a
// concurrent-write conflict the same way alertManager.acknowledge does.
// Unlike alertManager.acknowledge, a missing record is not a failure: an
// anomaly with no ack record yet is implicitly un-acknowledged, so
// acknowledging it for the first time creates the record rather than
// requiring observe() to have run first (ml-worker, not this dashboard,
// owns anomaly creation -- there is no equivalent write path to pre-seed one).
func (m *mlAnomalyAckManager) acknowledge(key string, ack bool, actor string) bool {
	for attempt := 0; attempt < mlAnomalyAckWriteRetries; attempt++ {
		hit, found, err := m.es.docGet(mlAnomalyAckIndex, key)
		if err != nil {
			return false
		}
		var r mlAnomalyAckRecord
		create := !found
		seqNo, primaryTerm := int64(0), int64(0)
		if found {
			if json.Unmarshal(hit.Source, &r) != nil {
				return false
			}
			seqNo, primaryTerm = hit.SeqNo, hit.PrimaryTerm
		} else {
			r = mlAnomalyAckRecord{Key: key}
		}
		if r.Acknowledged == ack {
			return true
		}
		r.Acknowledged = ack
		if ack {
			r.AckedBy, r.AckedAt = actor, time.Now()
		} else {
			r.AckedBy, r.AckedAt = "", time.Time{}
		}
		body, err := json.Marshal(r)
		if err != nil {
			return false
		}
		err = m.es.docIndex(mlAnomalyAckIndex, key, body, create, seqNo, primaryTerm)
		if err == nil {
			return true
		}
		if err != errESConflict {
			return false
		}
	}
	return false
}

// acknowledgeAllKeys (#1566) acknowledges every one of the given anomaly
// IDs, mirroring alertManager.acknowledgeAll's "flip everything currently
// open" bulk action for the structurally identical /alerts "acknowledge
// all" button. Unlike alertManager, this manager doesn't own anomaly
// identity itself -- ml-worker's mlAnomalyStore does, via a completely
// separate ES index -- so it can't scan its own index for "every open one"
// the way acknowledgeAll does; the caller (serveMLAnomalyAckAll) supplies
// the currently-unacknowledged IDs off the polled mlAnomalyStore snapshot
// instead. Reuses acknowledge()'s existing per-record optimistic-concurrency
// retry rather than a new bulk code path, so a write conflict on one
// anomaly can't abort the rest.
func (m *mlAnomalyAckManager) acknowledgeAllKeys(keys []string, actor string) int {
	changed := 0
	for _, key := range keys {
		if key != "" && m.acknowledge(key, true, actor) {
			changed++
		}
	}
	return changed
}

// acknowledged returns every acknowledged record, keyed by anomaly ID, for
// mlAnomaliesData/serveMLAnomaliesAPI to join against the polled cache.
// Unacknowledged records are never written (acknowledge only writes when
// flipping to true, or reopening one already true), so this index only ever
// holds anomalies an operator has actually touched -- no need to filter here.
func (m *mlAnomalyAckManager) acknowledged() map[string]mlAnomalyAckRecord {
	hits, err := m.es.docSearchAll(mlAnomalyAckIndex, 10000)
	if err != nil {
		return nil
	}
	out := make(map[string]mlAnomalyAckRecord, len(hits))
	for _, hit := range hits {
		var r mlAnomalyAckRecord
		if json.Unmarshal(hit.Source, &r) == nil && r.Acknowledged {
			out[r.Key] = r
		}
	}
	return out
}

// refresh polls acknowledged() (the live, unbounded ES scan) and replaces
// the cache wholesale -- called from main()'s synchronous startup block and
// its 1-minute ticker, alongside refreshMLAnomalies/refreshLLMAnalysis/
// refreshAgentCampaigns, plus once more after a successful acknowledge()
// write so the redirect back to /ml-anomalies doesn't show stale ack state
// for up to a minute.
func (m *mlAnomalyAckManager) refresh() {
	acked := m.acknowledged()
	m.mu.Lock()
	m.cache = acked
	m.mu.Unlock()
}

// cached returns the last-polled ack snapshot -- the read path
// (applyMLAnomalyAcks) uses this instead of acknowledged() itself, which is
// a full, unbounded (size=10000) Elasticsearch index scan and must not run
// on every /ml-anomalies or /api/ml/anomalies request.
func (m *mlAnomalyAckManager) cached() map[string]mlAnomalyAckRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cache
}

// applyMLAnomalyAcks joins the polled anomaly cache against ack state
// in-place. A nil manager (Elasticsearch not configured, same as every
// other ml-anomalies code path) leaves every item un-acknowledged rather
// than erroring -- consistent with mlAnomaliesData's own "Enabled" gate.
func (s *store) applyMLAnomalyAcks(items []mlAnomaly) {
	if s.mlAnomalyAcks == nil || len(items) == 0 {
		return
	}
	acked := s.mlAnomalyAcks.cached()
	if len(acked) == 0 {
		return
	}
	for i := range items {
		if items[i].AnomalyID == "" {
			continue
		}
		if r, ok := acked[items[i].AnomalyID]; ok {
			items[i].Acknowledged, items[i].AckedBy, items[i].AckedAt = true, r.AckedBy, r.AckedAt
		}
	}
}

// serveMLAnomalyAck handles the form POST from ml_anomalies.html's per-row
// acknowledge/reopen button -- a plain redirect-back form, not a JSON API,
// matching that page's own fully server-rendered shape (no client-side
// fetch/JS anywhere else on it, unlike alerts.html).
func (s *store) serveMLAnomalyAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	if !sameOriginRequest(r) {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	if s.mlAnomalyAcks == nil {
		http.Error(w, "ML anomaly acknowledgment is not configured on this host", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxActionFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(r.FormValue("key"))
	if key == "" {
		http.Error(w, "missing anomaly key", http.StatusBadRequest)
		return
	}
	ack := r.FormValue("ack") != "false"
	identity, _ := resolveIdentity(r)
	actor := identity.Username
	if actor == "" {
		actor = identity.Subject
	}
	if !s.mlAnomalyAcks.acknowledge(key, ack, actor) {
		http.Error(w, "acknowledgment update failed", http.StatusInternalServerError)
		return
	}
	// Refresh the cache inline: this is an explicit, low-frequency,
	// user-triggered POST (not a page-load read), so paying one extra live
	// ES round-trip here is fine, and it means the redirect below shows the
	// operator's own action immediately instead of stale state for up to a
	// minute (until the next background poll).
	s.mlAnomalyAcks.refresh()
	fallback := "/ml-anomalies"
	target := fallback
	if parsed, ok := safeReturnPath(r.FormValue("return"), []string{"/ml-anomalies"}); ok {
		target = parsed.String()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// serveMLAnomalyAckAll (#1566) is /ml-anomalies' bulk-acknowledge action --
// the same "acknowledge all (N)" bulk button /alerts already has, added
// here for the same reason: ~40 identical per-row acknowledge buttons with
// no way to clear the backlog at once. Like serveMLAnomalyAck, this is a
// plain form POST + redirect (ml_anomalies.html has no client-side fetch/JS
// elsewhere, unlike alerts.html's fetch-driven board), confirmed
// client-side by hp-modals.js's existing generic confirm-before-submit
// listener rather than a new one -- see ml_anomalies.html's form for the
// data-hp-confirm-* attributes that drive it.
func (s *store) serveMLAnomalyAckAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	if !sameOriginRequest(r) {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	if s.mlAnomalyAcks == nil || s.mlAnomalies == nil {
		http.Error(w, "ML anomaly acknowledgment is not configured on this host", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxActionFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	// The full polled snapshot, not just whatever the current filter bar
	// shows -- same "acknowledges every open one, plus any older ones this
	// page does not show" semantics /alerts' own acknowledge-all uses, so
	// the action does what its confirmation text promises regardless of
	// which severity/score/country filter happens to be active.
	items := s.mlAnomalies.snapshot()
	s.applyMLAnomalyAcks(items)
	keys := make([]string, 0, len(items))
	for _, item := range items {
		if item.AnomalyID != "" && !item.Acknowledged {
			keys = append(keys, item.AnomalyID)
		}
	}
	identity, _ := resolveIdentity(r)
	actor := identity.Username
	if actor == "" {
		actor = identity.Subject
	}
	s.mlAnomalyAcks.acknowledgeAllKeys(keys, actor)
	s.mlAnomalyAcks.refresh()
	fallback := "/ml-anomalies"
	target := fallback
	if parsed, ok := safeReturnPath(r.FormValue("return"), []string{"/ml-anomalies"}); ok {
		target = parsed.String()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
