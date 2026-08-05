package main

import (
	"sync"
	"time"
)

// pendingQueue holds lines whose src_ip==tunnelPeerIP but whose matching
// portbridge via_port entry hasn't landed yet. portbridge logs a
// connection's via_port at dial time, which happens before the honeypot
// itself ever sees the resulting connection -- so a miss is almost always
// either a genuinely-unattributable connection (no PROXY alternative and no
// portbridge record at all, e.g. traffic that reached the sensor some other
// way) or a brief race between the two log writers, not a permanent
// condition. Holding a line briefly and retrying preserves the same
// "retry every cycle" property dashboard/log_cache.go's own doc comment
// describes for the exact same race -- see that file for the fuller
// reasoning this mirrors.
type pendingQueue struct {
	mu    sync.Mutex
	items []pendingLine
}

type pendingLine struct {
	line     []byte
	deadline time.Time
}

func (q *pendingQueue) add(line []byte, timeout time.Duration, now time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, pendingLine{line: line, deadline: now.Add(timeout)})
}

// drain retries every pending line against vm, returning (in original
// order) every line that either resolved or timed out -- ready to write
// now, enriched or not. Lines still within their window and still
// unresolved stay queued for the next call.
func (q *pendingQueue) drain(vm, tftpVM viaMap, now time.Time, persona string) [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()

	var ready [][]byte
	remaining := q.items[:0]
	for _, p := range q.items {
		out, resolved := enrichLine(p.line, vm, tftpVM, persona)
		if resolved || now.After(p.deadline) {
			ready = append(ready, out)
			continue
		}
		remaining = append(remaining, p)
	}
	q.items = remaining
	return ready
}
