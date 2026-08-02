package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// revdeckStandaloneResult mirrors {sha256}_revdeck.json, written by
// ghidra-worker.py's drain_revdeck() (#78). Distinct from the ghidraResult's
// own RevDeck field: that one is an enrichment embedded inside a full Ghidra
// analysis; this is a standalone submission whose entire purpose is the
// RevDeck field below, so a null RevDeck here always means ExitStatus is
// "error" with Error explaining why -- there is no other field to fall back
// on reading.
type revdeckStandaloneResult struct {
	Version     int            `json:"version"`
	SHA256      string         `json:"sha256"`
	RequestedAt string         `json:"requested_at"`
	StartedAt   string         `json:"started_at"`
	CompletedAt string         `json:"completed_at"`
	ExitStatus  string         `json:"exit_status"`
	Error       string         `json:"error,omitempty"`
	RevDeck     *ghidraRevDeck `json:"revdeck"`
}

type revdeckPageData struct {
	pageMeta
	Generated time.Time
	Detail    *revdeckStandaloneResult
}

func revdeckRequestDir() string { return getenv("REVDECK_REQUEST_DIR", "") }
func revdeckResultsDir() string { return getenv("REVDECK_RESULTS_DIR", "") }

func loadRevdeckResults() []revdeckStandaloneResult {
	dir := revdeckResultsDir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var rows []revdeckStandaloneResult
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_revdeck.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var row revdeckStandaloneResult
		if err := json.Unmarshal(raw, &row); err != nil {
			// Malformed result skipped rather than failing the page, same
			// reasoning as loadGhidraResults(): the worker writes atomically,
			// so this means hand-editing or disk damage.
			continue
		}
		// Trust the filename over the document for identity, same as
		// loadGhidraResults().
		row.SHA256 = strings.TrimSuffix(entry.Name(), "_revdeck.json")
		if !hashName.MatchString(row.SHA256) {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CompletedAt != rows[j].CompletedAt {
			return rows[i].CompletedAt > rows[j].CompletedAt
		}
		return rows[i].SHA256 > rows[j].SHA256
	})
	return rows
}

func newestRevdeckResult(hash string, results []revdeckStandaloneResult, after time.Time) (revdeckStandaloneResult, bool) {
	for _, result := range results {
		if result.SHA256 == hash && workbenchResultAfter(result.CompletedAt, after) {
			return result, true
		}
	}
	return revdeckStandaloneResult{}, false
}

func revdeckData(sha256 string) (revdeckPageData, error) {
	data := revdeckPageData{Generated: time.Now()}
	if sha256 == "" {
		return data, errors.New("revdeck result not found")
	}
	for _, row := range loadRevdeckResults() {
		if row.SHA256 == sha256 {
			result := row
			data.Detail = &result
			return data, nil
		}
	}
	return data, errors.New("revdeck result not found")
}

func serveRevdeckAPI(w http.ResponseWriter, r *http.Request) {
	sha := strings.TrimPrefix(r.URL.Path, "/api/revdeck/")
	if sha == "" || !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	data, err := revdeckData(sha)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data.Detail)
}
