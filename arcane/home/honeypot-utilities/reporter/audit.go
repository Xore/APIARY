package main

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// auditEntry is one line of the reporter's structured audit log -- every
// decision it makes about an IP (would-report, reported, skipped, error),
// not just the reports that actually went out. WORK-LEDGER.md rule 7 asks
// for this to be provable, not just claimed: an operator reviewing dry-run
// output before authorizing live reporting needs to see what was *skipped*
// and why, not only what would have been sent.
type auditEntry struct {
	Action     string    `json:"action"` // would_report | reported | report_error | skipped
	Service    string    `json:"service,omitempty"`
	IP         string    `json:"ip"`
	Reason     string    `json:"reason,omitempty"` // for "skipped": why (whitelist, cooldown, uncategorized)
	Categories []int     `json:"categories,omitempty"`
	Sensor     string    `json:"sensor,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Error      string    `json:"error,omitempty"`
	At         time.Time `json:"event_time"`
	Logged     time.Time `json:"logged_at"`
}

// auditLog writes one JSON line per entry. Safe for concurrent use -- the
// tailer processes multiple log files, and both dryRunSender and
// liveSender write through the same log.
type auditLog struct {
	mu sync.Mutex
	w  io.Writer
}

func newAuditLog(w io.Writer) *auditLog { return &auditLog{w: w} }

func (a *auditLog) log(e auditEntry) {
	e.Logged = time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.w.Write(append(line, '\n'))
}
