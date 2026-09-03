package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
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

// rotatingWriter bounds audit.json's on-disk size (#2882: 5.99 GB, unbounded,
// on a 128M-limited container -- 25 days of accumulation at a ~240 MB/day
// lifetime average, ~62 MB/day currently, not the ~2.9 GB/day the issue body
// asserts by dividing the whole file by ~2 days). It rotates
// in-process, the same way audit.go already owns the file handle it writes
// through -- no second process or script touches this file.
//
// This is a straight rename-and-reopen, not log-maintenance.sh's
// copytruncate: copytruncate exists there specifically to keep Filebeat's
// inode/offset tracking intact for logs Filebeat tails, and nothing tails
// audit.json (it's the reporter's own dry-run-review artifact, not a
// sensor log ingested into Elasticsearch) -- so there's no reason to
// prefer the more fragile copy+truncate window over a clean rename.
//
// The most recent decisions are never lost: rotation only ever moves the
// current file to audit.json.1 (cascading older numbered files up to
// `keep`) and starts a fresh one, so every entry survives until it ages
// out through `keep` rotations, same shape as log-maintenance.sh's
// ROTATIONS knob.
type rotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
}

func newRotatingWriter(path string, maxBytes int64, keep int) (*rotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rotatingWriter{path: path, maxBytes: maxBytes, keep: keep, f: f, size: info.Size()}, nil
}

func (r *rotatingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxBytes > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			// Keep writing to the current file rather than dropping the
			// entry -- a rotation that failed (e.g. a permissions issue)
			// should never cost an audit decision.
			log.Printf("reporter: audit log rotation failed, continuing without rotating: %v", err)
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// rotate moves the current audit file aside and reopens a fresh one.
//
// Every failure path must still leave r.f pointing at an *open* handle and
// r.size agreeing with the file behind it. Write() deliberately falls back
// to writing through r.f when rotation fails, so that one transient error
// costs no audit entry; if rotate() could return with r.f closed, that
// fallback write would fail with os.ErrClosed, r.size would stay over the
// cap, and every subsequent write would re-enter rotate(), fail on the
// already-closed handle and return early again -- silencing the audit log
// permanently after a single transient failure, rather than for one entry.
// The trigger is realistic exactly when it matters: Close() flushing on a
// full filesystem is the ordinary way this fails, and a full filesystem is
// why this rotation exists. Hence: close, cascade, and then reopen
// unconditionally, reporting all three outcomes together.
func (r *rotatingWriter) rotate() error {
	closeErr := r.f.Close()
	cascadeErr := r.cascade()
	// Unconditional: on success this opens the new empty file, on failure
	// the original one. Either way r.f is writable when we return.
	reopenErr := r.reopen()
	return errors.Join(closeErr, cascadeErr, reopenErr)
}

// cascade shifts audit.json.N -> audit.json.N+1 for the kept generations and
// moves the live file to audit.json.1 (or removes it outright when keep<=0).
func (r *rotatingWriter) cascade() error {
	if r.keep <= 0 {
		if err := os.Remove(r.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	for i := r.keep - 1; i >= 1; i-- {
		old := fmt.Sprintf("%s.%d", r.path, i)
		next := fmt.Sprintf("%s.%d", r.path, i+1)
		if _, err := os.Stat(old); err != nil {
			continue
		}
		if err := os.Rename(old, next); err != nil {
			return err
		}
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// reopen points r.f back at r.path and re-derives r.size from the file on
// disk. Re-deriving rather than zeroing matters on the failure path: if the
// cascade did not happen, the live file is still over the cap, and claiming
// size 0 would silently disable rotation for the next maxBytes of writes.
func (r *rotatingWriter) reopen() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		// Nothing further can be done here -- r.f stays closed and the
		// error reaches Write()'s caller. This is the irreducible case
		// (the path itself cannot be opened), not the recoverable one the
		// comment above is about.
		return err
	}
	r.f = f
	r.size = 0
	if info, err := f.Stat(); err == nil {
		r.size = info.Size()
	}
	return nil
}

func (r *rotatingWriter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
