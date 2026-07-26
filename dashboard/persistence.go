package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type intelligenceSnapshot struct {
	Version   int           `json:"version"`
	Generated time.Time     `json:"generated"`
	Campaigns []campaignRow `json:"campaigns"`
	Clusters  []clusterRow  `json:"clusters"`
}

type intelligenceStore struct {
	mu   sync.Mutex
	path string
	last time.Time
}

func (p *intelligenceStore) due() bool {
	if p == nil || p.path == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last.IsZero() || time.Since(p.last) >= 5*time.Minute
}

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
	archive := p.path + "l"
	if stat, err := os.Stat(archive); err == nil && stat.Size() > 32<<20 {
		_ = os.Remove(archive + ".1")
		_ = os.Rename(archive, archive+".1")
	}
	if file, err := os.OpenFile(archive, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		compact, _ := json.Marshal(data)
		_, _ = file.Write(append(compact, '\n'))
		_ = file.Close()
	}
}

func (p *intelligenceStore) serveArchive(w http.ResponseWriter, r *http.Request) {
	if p == nil || p.path == "" {
		http.Error(w, "intelligence persistence disabled", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="intelligence-history.jsonl"`)
	http.ServeFile(w, r, p.path+"l")
}
