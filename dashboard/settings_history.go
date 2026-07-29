package main

// settings_history.go — revision history for the administrator configuration
// store (roadmap §6, Milestone E). Every successful configuration mutation
// appends one JSON line holding the full payload snapshot, so a rollback can
// restore any retained revision exactly. The schema denylist (§12 Tier 3)
// guarantees the payload can never contain secrets, so snapshots are safe to
// retain.
//
// The file is bounded: when it grows past the size cap it rotates to a single
// .1 generation, and reads always return the newest entries first.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// configHistoryMaxBytes bounds one history generation. A snapshot of the
// typed configuration document is a few KiB; 2 MiB retains hundreds of
// revisions across both generations.
const configHistoryMaxBytes = 2 << 20

// configHistoryReadLimit caps a single history read. Rollback looks up one
// revision within this window; older revisions are still on disk in the
// rotated generation but are not offered for rollback in v1.
const configHistoryReadLimit = 200

type configHistoryEntry struct {
	Revision int64           `json:"revision"`
	Time     time.Time       `json:"time"`
	Actor    string          `json:"actor_subject"`
	Username string          `json:"actor_username"`
	Action   string          `json:"action"` // update | rollback
	Fields   []string        `json:"fields,omitempty"`
	Payload  json.RawMessage `json:"payload"`
}

type configHistory struct {
	mu   sync.Mutex
	path string
}

func newConfigHistory(path string) *configHistory {
	if path == "" {
		return nil
	}
	return &configHistory{path: path}
}

// append records one revision snapshot. History failures never block the
// mutation that produced the entry — the configuration store itself is the
// source of truth; history is a convenience layer for review and rollback.
func (h *configHistory) append(entry configHistoryEntry) {
	if h == nil || h.path == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if entry.Time.IsZero() {
		entry.Time = time.Now().UTC()
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(h.path), 0o750); err != nil {
		return
	}
	if stat, err := os.Stat(h.path); err == nil && stat.Size() > configHistoryMaxBytes {
		_ = os.Remove(h.path + ".1")
		_ = os.Rename(h.path, h.path+".1")
	}
	file, err := os.OpenFile(h.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = file.Write(append(line, '\n'))
	_ = file.Close()
}

// read returns the newest entries first across both generations, bounded to
// limit. Corrupt lines are skipped, never fatal.
func (h *configHistory) read(limit int) []configHistoryEntry {
	if h == nil || h.path == "" || limit <= 0 {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var raw []byte
	for _, path := range []string{h.path, h.path + ".1"} {
		data, err := os.ReadFile(path)
		if err == nil {
			raw = append(raw, data...)
		}
	}
	lines := bytes.Split(raw, []byte{'\n'})
	entries := make([]configHistoryEntry, 0, min(len(lines), limit))
	for i := len(lines) - 1; i >= 0 && len(entries) < limit; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		var entry configHistoryEntry
		if json.Unmarshal(line, &entry) == nil && entry.Action != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

// find returns the retained snapshot for one revision, or false when the
// revision has rotated out of the retained window.
func (h *configHistory) find(revision int64) (configHistoryEntry, bool) {
	for _, entry := range h.read(configHistoryReadLimit) {
		if entry.Revision == revision {
			return entry, true
		}
	}
	return configHistoryEntry{}, false
}
