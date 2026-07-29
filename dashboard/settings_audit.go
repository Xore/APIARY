package main

// settings_audit.go — append-only audit log for settings mutations
// (roadmap §6). Records actor, action, dotted field names, revision, and
// result; values are never written to the log. The log is JSONL with a
// single rotated generation, matching the intelligence archive pattern.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const auditMaxBytes = 8 << 20 // rotate the active log at 8 MiB, keep one generation

type auditEvent struct {
	Time      time.Time `json:"time"`
	Actor     string    `json:"actor_subject"`
	Username  string    `json:"actor_username"`
	RequestID string    `json:"request_id,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	Action    string    `json:"action"`
	Fields    []string  `json:"fields,omitempty"`
	Revision  int64     `json:"revision"`
	Result    string    `json:"result"` // success | conflict | invalid | error
}

type auditLogger struct {
	mu   sync.Mutex
	path string
}

func newAuditLogger(path string) *auditLogger {
	if path == "" {
		return nil
	}
	return &auditLogger{path: path}
}

// log appends one event. Audit failures never block the mutation that
// produced the event — the write is best-effort, like every other log in the
// stack, and a full disk surfaces through the store's own error handling.
func (a *auditLogger) log(event auditEvent) {
	if a == nil || a.path == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o750); err != nil {
		return
	}
	if stat, err := os.Stat(a.path); err == nil && stat.Size() > auditMaxBytes {
		_ = os.Remove(a.path + ".1")
		_ = os.Rename(a.path, a.path+".1")
	}
	line, err := json.Marshal(event)
	if err != nil {
		return
	}
	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = file.Write(append(line, '\n'))
	_ = file.Close()
}

// read returns the newest events first, bounded to limit. Used by the
// configuration history API and by tests.
func (a *auditLogger) read(limit int) []auditEvent {
	if a == nil || a.path == "" || limit <= 0 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, err := os.ReadFile(a.path)
	if err != nil {
		return nil
	}
	lines := bytes.Split(raw, []byte{'\n'})
	events := make([]auditEvent, 0, min(len(lines), limit))
	for i := len(lines) - 1; i >= 0 && len(events) < limit; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		var event auditEvent
		if json.Unmarshal(line, &event) == nil {
			events = append(events, event)
		}
	}
	return events
}
