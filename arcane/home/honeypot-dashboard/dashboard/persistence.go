package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type intelligenceSnapshot struct {
	Version   int           `json:"version"`
	Generated time.Time     `json:"generated"`
	Campaigns []campaignRow `json:"campaigns"`
	Clusters  []clusterRow  `json:"clusters"`
}

// intelligenceArchiveIndex holds one document per periodic snapshot (#638):
// this used to be a locally rotated .jsonl file the dashboard served
// straight off disk via http.ServeFile -- moved to Elasticsearch so every
// dashboard instance serves the same history and this artifact no longer
// needs the now-superseded #470/#483 raw-bytes exception to the dashboard's
// "no direct file reads" rule (#37/#39).
const intelligenceArchiveIndex = "dashboard-intelligence-archive-v1"

// intelligenceArchiveMaxDocs bounds how much history serveArchive returns in
// one response. The old local file capped itself at 32MB plus one rotated
// generation; this expresses the same "don't return unbounded history"
// intent as a document count instead, since each stored document here is one
// small JSON snapshot, not a growing append-only file.
const intelligenceArchiveMaxDocs = 5000

type intelligenceStore struct {
	mu   sync.Mutex
	path string
	last time.Time
	es   *esClient
}

func (p *intelligenceStore) due() bool {
	if p == nil || p.path == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last.IsZero() || time.Since(p.last) >= 5*time.Minute
}

// save writes the current snapshot to p.path (an operator-inspectable local
// file, never served over HTTP -- out of #638's scope, which is about the
// dashboard's own read paths) and appends the same snapshot to the
// Elasticsearch archive serveArchive reads from.
func (p *intelligenceStore) save(data intelligenceSnapshot) {
	if p == nil || p.path == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.last.IsZero() && time.Since(p.last) < 5*time.Minute {
		return
	}
	p.last = time.Now()
	_ = os.MkdirAll(filepath.Dir(p.path), 0o750)
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	tmp := p.path + ".tmp"
	if os.WriteFile(tmp, append(b, '\n'), 0o600) != nil || os.Rename(tmp, p.path) != nil {
		return
	}
	if p.es == nil {
		return
	}
	compact, err := json.Marshal(data)
	if err != nil {
		return
	}
	// A fresh random id per entry, same as reports_es.go's generated-report
	// history: this is an append-only historical record, not state to
	// update in place, so op_type=create with no prior seq_no/primary_term
	// is the right shape -- a collision is not a real scenario to design
	// retry logic around.
	_ = p.es.docIndex(intelligenceArchiveIndex, newReportID("intel_"), compact, true, 0, 0)
}

// serveArchive streams every retained snapshot as newline-delimited JSON,
// oldest first -- the same shape the old rotated .jsonl file had, so
// existing consumers of this endpoint see no format change, only a
// different (and now instance-independent) source.
func (p *intelligenceStore) serveArchive(w http.ResponseWriter, r *http.Request) {
	if p == nil || p.path == "" || p.es == nil {
		http.Error(w, "intelligence persistence disabled", http.StatusServiceUnavailable)
		return
	}
	hits, err := p.es.docSearchAll(intelligenceArchiveIndex, intelligenceArchiveMaxDocs)
	if err != nil {
		http.Error(w, "intelligence archive unavailable", http.StatusBadGateway)
		return
	}
	type entry struct {
		source    json.RawMessage
		generated time.Time
	}
	entries := make([]entry, 0, len(hits))
	for _, hit := range hits {
		var meta struct {
			Generated time.Time `json:"generated"`
		}
		if json.Unmarshal(hit.Source, &meta) != nil {
			continue
		}
		entries = append(entries, entry{source: hit.Source, generated: meta.Generated})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].generated.Before(entries[j].generated) })

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="intelligence-history.jsonl"`)
	for _, e := range entries {
		w.Write(e.source)
		w.Write([]byte("\n"))
	}
}
