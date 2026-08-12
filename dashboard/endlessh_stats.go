package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// endlessh_stats.go (#1294): endlessh's disconnect events carry held_ms
// (how long the tarpit kept a connection stuck before it gave up) --
// aggregate.go's rebuild() already sums it and buckets it into
// endlesshHeldBuckets during the same in-memory pass everything else on
// honeypot-v2-* (a flattened-mapped index) already needs, since a live ES
// stats/sum aggregation on that field fails outright (confirmed live:
// "Field [honeypot._keyed] of type [flattened] is not supported for
// aggregation [stats]"). This file only shapes what rebuild() already
// computed for the overview page's stat tile and /api/endlessh-held-histogram.

// heldMsBuckets is the fixed, ordered set of held_ms ranges every duration
// is sorted into -- ordered explicitly (not map iteration order, which Go
// randomizes per process) so /api/endlessh-held-histogram's bars render in
// the same short-to-long sequence on every request, matching #40's own
// "two dashboard instances must render identically" fix for /commands.
var heldMsBuckets = []struct {
	label string
	upper int // exclusive upper bound in ms; 0 means "no upper bound"
}{
	{"<1s", 1000},
	{"1-5s", 5000},
	{"5-15s", 15000},
	{"15-60s", 60000},
	{"1-5min", 300000},
	{"5min+", 0},
}

// endlesshHeldHumanDuration renders totalMs as a compact "Nh Nm" (or "Nm",
// or "<1m" for anything under a minute -- rounding down to 0m would read
// as "nothing happened" for what is, cumulatively, real held time) figure
// for the overview stat tile. Deliberately coarser than time.Duration's own
// String() (which would print seconds too, more precision than a
// cumulative "time wasted" headline number needs).
func endlesshHeldHumanDuration(totalMs int64) string {
	d := time.Duration(totalMs) * time.Millisecond
	hours := int64(d.Hours())
	minutes := int64(d.Minutes()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	if totalMs > 0 {
		return "<1m"
	}
	return "0m"
}

// heldMsBucket returns the label of the bucket ms falls into.
func heldMsBucket(ms int) string {
	for _, b := range heldMsBuckets {
		if b.upper == 0 || ms < b.upper {
			return b.label
		}
	}
	return heldMsBuckets[len(heldMsBuckets)-1].label
}

// serveEndlesshHeldHistogram answers /api/endlessh-held-histogram, reading
// the already-computed snapshot field -- no new aggregation pass, same
// pattern serveOSDistribution (os_distribution.go, #1277) already
// established for a snapshot-backed chart.
func (s *store) serveEndlesshHeldHistogram(w http.ResponseWriter, r *http.Request) {
	snap := s.get()
	categories := make([]string, 0, len(heldMsBuckets))
	values := make([]int, 0, len(heldMsBuckets))
	for _, b := range heldMsBuckets {
		categories = append(categories, b.label)
		values = append(values, snap.EndlesshHeldBuckets[b.label])
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(struct {
		Categories []string `json:"categories"`
		Values     []int    `json:"values"`
	}{categories, values})
}
