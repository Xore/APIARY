package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

// alertsPageData is /alerts' own render type -- s.get() alone (used by most
// other simple pages) returns the shared snapshot, which every page using it
// must not gain unrelated fields on, so the new filterBar (#301) is layered
// on top here instead of added to snapshot itself. Filtering the alert board
// down to a state/key-or-message search happens client-side in alerts.html's
// own JS against the always-unfiltered GET /api/alerts response (a small,
// already-capped-at-200 list, and a shared endpoint other pages/widgets also
// call -- see alerts.html for why that must not itself start filtering).
// filterBar exists purely so the page gets the same pre-filled-form/reset-
// link widget every other filterable page has.
type alertsPageData struct {
	snapshot
	filterBar
}

type alertRecord struct {
	Key          string
	Message      string
	Link         string `json:",omitempty"` // optional drill-down URL to the events behind this alert
	FirstSeen    time.Time
	LastSeen     time.Time
	LastNotified time.Time
	Count        int
	Acknowledged bool
}

// alertIndex is the dashboard-owned Elasticsearch index storing operational
// alert state (campaign detection, stale sensor feeds, activity spikes, ES
// pipeline health, OT command detection, YARA hits, sandbox failures --
// nothing here is otherwise visible anywhere in the UI, unlike evebox's own
// separate Suricata signature leaderboard). #494: this replaces the
// previous local-file-backed store (ALERT_STATE_FILE) so two dashboard
// instances agree on ack/cooldown state -- deliberately no local-file
// fallback: if Elasticsearch is unavailable, alertManager is nil and every
// call site already treats that as "alerting disabled" (see the `s.alerts
// == nil ||` guard at every observe() call site), the same graceful-
// degrade-by-omission philosophy es_aggregate.go's own overview queries use.
const alertIndex = "dashboard-alert-state-v1"

// alertManager is a thin, stateless wrapper around alertIndex -- every
// method is a live Elasticsearch round-trip, no in-process cache to desync
// across instances. observe/acknowledge/acknowledgeAll use optimistic
// concurrency (docGet's seq_no/primary_term, docIndex's if_seq_no/
// if_primary_term) with a bounded retry loop against errESConflict, since
// two dashboard instances (or two requests) can race to update the same key.
type alertManager struct {
	es       *esClient
	cooldown time.Duration
}

// newAlertManager returns nil when es is nil (Elasticsearch not configured):
// every call site already short-circuits on a nil alertManager, so this is
// the "alerting disabled" state, not a local-file fallback.
func newAlertManager(es *esClient, cooldown time.Duration) *alertManager {
	if es == nil {
		return nil
	}
	return &alertManager{es: es, cooldown: cooldown}
}

const alertWriteRetries = 5

// observe upserts the record for key, applying the same first-seen/last-
// seen/count/cooldown bookkeeping the local-file version did, and reports
// whether a notification should fire. A conflict against a concurrent writer
// re-fetches and reapplies rather than failing the whole rebuild cycle over
// alerting bookkeeping.
func (m *alertManager) observe(key, message, link string, markOnly bool) bool {
	now := time.Now()
	for attempt := 0; attempt < alertWriteRetries; attempt++ {
		hit, found, err := m.es.docGet(alertIndex, key)
		if err != nil {
			return false
		}
		var r alertRecord
		create := !found
		seqNo, primaryTerm := int64(0), int64(0)
		if found {
			if err := json.Unmarshal(hit.Source, &r); err != nil {
				return false
			}
			seqNo, primaryTerm = hit.SeqNo, hit.PrimaryTerm
		} else {
			r = alertRecord{Key: key, FirstSeen: now}
		}
		r.Message, r.Link, r.LastSeen, r.Count = message, link, now, r.Count+1
		notify := !markOnly && !r.Acknowledged && (r.LastNotified.IsZero() || now.Sub(r.LastNotified) >= m.cooldown)
		if notify || (markOnly && r.LastNotified.IsZero()) {
			r.LastNotified = now
		}
		body, err := json.Marshal(r)
		if err != nil {
			return false
		}
		err = m.es.docIndex(alertIndex, key, body, create, seqNo, primaryTerm)
		if err == nil {
			return notify
		}
		if err != errESConflict {
			return false
		}
		// Lost a race (concurrent write, or a create that landed between our
		// docGet and docIndex, which Elasticsearch also reports as a 409) --
		// retry from a fresh read.
	}
	return false
}

// list returns every alert record, newest-observed first, capped at 200 --
// the same shape and cap the local-file version served.
func (m *alertManager) list() []alertRecord {
	hits, err := m.es.docSearchAll(alertIndex, 10000)
	if err != nil {
		return nil
	}
	out := make([]alertRecord, 0, len(hits))
	for _, hit := range hits {
		var r alertRecord
		if json.Unmarshal(hit.Source, &r) == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// acknowledge flips one record's Acknowledged flag, retrying on a
// concurrent-write conflict the same way observe does. Reports false when
// the key doesn't exist (nothing to acknowledge) or the write never landed.
func (m *alertManager) acknowledge(key string, ack bool) bool {
	for attempt := 0; attempt < alertWriteRetries; attempt++ {
		hit, found, err := m.es.docGet(alertIndex, key)
		if err != nil || !found {
			return false
		}
		var r alertRecord
		if json.Unmarshal(hit.Source, &r) != nil {
			return false
		}
		if r.Acknowledged == ack {
			return true
		}
		r.Acknowledged = ack
		body, err := json.Marshal(r)
		if err != nil {
			return false
		}
		if err := m.es.docIndex(alertIndex, key, body, false, hit.SeqNo, hit.PrimaryTerm); err == nil {
			return true
		} else if err != errESConflict {
			return false
		}
	}
	return false
}

// acknowledgeAll flips every record that is not already in the requested
// state and reports how many changed. list() only returns the newest 200, so
// this deliberately scans the full index: "acknowledge all" that quietly
// left older alerts open would be the more surprising behaviour. Each
// record is updated independently (no bulk API), retrying on a per-record
// write conflict the same way acknowledge does -- one record losing a race
// to a concurrent writer doesn't abort the rest.
func (m *alertManager) acknowledgeAll(ack bool) int {
	hits, err := m.es.docSearchAll(alertIndex, 10000)
	if err != nil {
		return 0
	}
	changed := 0
	for _, hit := range hits {
		var r alertRecord
		if json.Unmarshal(hit.Source, &r) != nil || r.Acknowledged == ack {
			continue
		}
		seqNo, primaryTerm := hit.SeqNo, hit.PrimaryTerm
		for attempt := 0; attempt < alertWriteRetries; attempt++ {
			r.Acknowledged = ack
			body, err := json.Marshal(r)
			if err != nil {
				break
			}
			err = m.es.docIndex(alertIndex, hit.ID, body, false, seqNo, primaryTerm)
			if err == nil {
				changed++
				break
			}
			if err != errESConflict {
				break
			}
			refreshed, found, err := m.es.docGet(alertIndex, hit.ID)
			if err != nil || !found {
				break
			}
			if json.Unmarshal(refreshed.Source, &r) != nil {
				break
			}
			if r.Acknowledged == ack {
				break
			}
			seqNo, primaryTerm = refreshed.SeqNo, refreshed.PrimaryTerm
		}
	}
	return changed
}

func (s *store) serveAlertsAPI(w http.ResponseWriter, r *http.Request) {
	if s.alerts == nil {
		http.Error(w, "alert state disabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPost {
		if !requireAdmin(w, r) {
			return
		}
		key := strings.TrimSpace(r.FormValue("key"))
		ack := r.FormValue("ack") != "false"
		// scope=all is spelled out rather than inferred from an empty key, so a
		// form that loses its key cannot silently acknowledge the whole board.
		if r.FormValue("scope") == "all" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"changed": s.alerts.acknowledgeAll(ack),
				"alerts":  s.alerts.list(),
			})
			return
		}
		if !s.alerts.acknowledge(key, ack) {
			http.NotFound(w, r)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.alerts.list())
}
