package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"
)

// #353: rebuild() used to re-read and re-classify every log file's entire
// tail (up to tailCap bytes) on every 15s cycle, even for a sensor that
// logged nothing new since the last cycle. classifiedEventsFor caches the
// expensive, per-line-deterministic half of that work -- reading bytes off
// disk, json.Unmarshal, classify(), normalizeProtocol(), and
// captureScriptPayload() -- keyed by file size+mtime, so an unchanged file
// costs one os.Stat instead of a full re-read and re-parse.
//
// What is deliberately NOT cached, and still runs fresh over the full
// (cached + freshly parsed) event set on every single call to rebuild():
// the portbridge via-map join, the p0f fallback fingerprint, cross-line
// dedup, GeoIP lookup, and every now-relative aggregate (last24h/
// previous24h/the activity heatmap, all bucketed against the current
// instant). Two correctness reasons this split exists, not just
// performance:
//
//  1. viaMap only spans portbridge's current + previous log rotation
//     (buildViaMap's own doc comment). A cowrie event line logged slightly
//     before its matching portbridge connect record lands would miss the
//     join on the cycle it was first read -- today's always-full-reread
//     naturally retries that join on every later cycle too, since the whole
//     line gets reclassified from scratch each time. Caching the raw
//     classify() output but re-running the join fresh every cycle preserves
//     that retry property for a now-cached line; caching the *joined*
//     result would silently freeze a transient miss into a permanent one.
//  2. last24h/previous24h/the heatmap bucket every event's age against
//     time.Now() at rebuild time, not a value fixed when the line was first
//     read -- an event's own age bucket keeps shifting every cycle
//     regardless of whether its source file changed.
type cachedEvent struct {
	ev event
	// srcPort is eventSrcPort(e) from the line's raw JSON, computed once at
	// classify time since the raw map itself isn't retained -- the via-join
	// needs it on every cycle (see above), not just the cycle a line was
	// first parsed.
	srcPort int
}

type logFileState struct {
	size    int64
	modTime time.Time
	events  []cachedEvent
}

// classifiedEventsFor returns fn's classified events, reusing prev's cached
// work wherever the file's own content guarantees it's still correct to do
// so, and reports the state to cache for the next call. prev may be nil (a
// file seen for the first time, or the map handed to it after last cycle's
// stale-entry prune -- see rebuild()).
//
// tailCapBytes matches tailCap in production; passed as a parameter rather
// than the package constant so tests can exercise the "file is large enough
// that windowing matters" path without writing multi-megabyte fixtures.
func (s *store) classifiedEventsFor(fn, dirSensor string, prev *logFileState, tailCapBytes int64) ([]cachedEvent, *logFileState) {
	st, err := os.Stat(fn)
	if err != nil {
		return nil, nil
	}

	// Once a file is at or past the tail cap, readTail's windowing (only the
	// last tailCapBytes are ever considered) has to keep applying every
	// cycle -- incremental byte tracking doesn't know which OLD bytes have
	// aged out of that window as the file keeps growing. Falling back to
	// exactly today's full-reread behavior for such a file is simplest and
	// safest: it costs what it costs today, no regression, and the
	// incremental win still applies to every smaller, quieter file.
	if st.Size() >= tailCapBytes {
		events := s.classifyLines(readTail(fn), dirSensor)
		return events, &logFileState{size: st.Size(), modTime: st.ModTime()}
	}

	if prev != nil && prev.size == st.Size() && prev.modTime.Equal(st.ModTime()) {
		return prev.events, prev
	}

	// Truncation (copytruncate rotation) or shrinkage some other way: the
	// previously cached byte range no longer corresponds to this file's
	// content at all. First sighting (prev == nil) falls in here too.
	if prev == nil || st.Size() < prev.size {
		body, err := os.ReadFile(fn)
		if err != nil {
			return nil, nil
		}
		consumed, events := s.classifyCompleteLines(body, dirSensor)
		return events, &logFileState{size: consumed, modTime: st.ModTime(), events: events}
	}

	// Pure growth: read only the new suffix.
	f, err := os.Open(fn)
	if err != nil {
		return prev.events, prev
	}
	defer f.Close()
	if _, err := f.Seek(prev.size, io.SeekStart); err != nil {
		return prev.events, prev
	}
	suffix, err := io.ReadAll(f)
	if err != nil {
		return prev.events, prev
	}
	consumed, newEvents := s.classifyCompleteLines(suffix, dirSensor)
	if consumed == 0 {
		// Nothing beyond an in-progress, still-incomplete final line. Leave
		// prev.size where it was so the next cycle re-reads (and this time
		// hopefully completes) that same trailing line, exactly like a full
		// reread would naturally retry it.
		return prev.events, prev
	}
	merged := append(append([]cachedEvent{}, prev.events...), newEvents...)
	return merged, &logFileState{size: prev.size + consumed, modTime: st.ModTime(), events: merged}
}

// classifyCompleteLines classifies every complete (newline-terminated) line
// in data and reports how many leading bytes those complete lines actually
// consumed. Any trailing partial line (the sensor's write was still in
// flight when this was read) is left unconsumed so a future call re-reads
// it whole, the same tolerance readTail's callers already have today: an
// unparseable line is silently retried next cycle, never lost.
func (s *store) classifyCompleteLines(data []byte, dirSensor string) (consumed int64, events []cachedEvent) {
	last := bytes.LastIndexByte(data, '\n')
	if last < 0 {
		return 0, nil
	}
	complete := data[:last+1]
	return int64(len(complete)), s.classifyLines(complete, dirSensor)
}

// classifyLines is readTail's own line-splitting convention, factored out
// so both the tailCapBytes fallback and the incremental path parse
// identically.
func (s *store) classifyLines(data []byte, dirSensor string) []cachedEvent {
	var events []cachedEvent
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		ev := classify(e, dirSensor)
		if ev.skip {
			continue
		}
		ev.proto = normalizeProtocol(ev.proto)
		s.captureScriptPayload(&ev)
		events = append(events, cachedEvent{ev: ev, srcPort: eventSrcPort(e)})
	}
	return events
}
