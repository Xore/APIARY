package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type alertRecord struct {
	Key          string
	Message      string
	FirstSeen    time.Time
	LastSeen     time.Time
	LastNotified time.Time
	Count        int
	Acknowledged bool
}

type alertManager struct {
	mu       sync.Mutex
	path     string
	cooldown time.Duration
	records  map[string]*alertRecord
}

func newAlertManager(path string, cooldown time.Duration) *alertManager {
	m := &alertManager{path: path, cooldown: cooldown, records: map[string]*alertRecord{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m.records)
	}
	return m
}

func (m *alertManager) observe(key, message string, markOnly bool) bool {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[key]
	if r == nil {
		r = &alertRecord{Key: key, Message: message, FirstSeen: now}
		m.records[key] = r
	}
	r.Message, r.LastSeen, r.Count = message, now, r.Count+1
	notify := !markOnly && !r.Acknowledged && (r.LastNotified.IsZero() || now.Sub(r.LastNotified) >= m.cooldown)
	if notify || markOnly && r.LastNotified.IsZero() {
		r.LastNotified = now
	}
	m.saveLocked()
	return notify
}

func (m *alertManager) list() []alertRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]alertRecord, 0, len(m.records))
	for _, r := range m.records {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func (m *alertManager) acknowledge(key string, ack bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[key]
	if r == nil {
		return false
	}
	r.Acknowledged = ack
	m.saveLocked()
	return true
}

// acknowledgeAll flips every record that is not already in the requested state
// and reports how many changed. list() only returns the newest 200, so this
// deliberately covers records the alerts page never rendered: "acknowledge
// all" that quietly left older alerts open would be the more surprising
// behaviour. The count is what lets the caller say what actually happened
// instead of assuming it matched the rows on screen.
func (m *alertManager) acknowledgeAll(ack bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := 0
	for _, r := range m.records {
		if r.Acknowledged == ack {
			continue
		}
		r.Acknowledged = ack
		changed++
	}
	if changed > 0 {
		m.saveLocked()
	}
	return changed
}

func (m *alertManager) saveLocked() {
	if m.path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(m.path), 0o750)
	b, _ := json.MarshalIndent(m.records, "", "  ")
	tmp := m.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, m.path)
	}
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
