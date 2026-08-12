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
	Version            int                `json:"version"`
	SHA256             string             `json:"sha256"`
	RequestedAt        string             `json:"requested_at"`
	StartedAt          string             `json:"started_at"`
	CompletedAt        string             `json:"completed_at"`
	ExitStatus         string             `json:"exit_status"`
	Error              string             `json:"error,omitempty"`
	RevDeck            *ghidraRevDeck     `json:"revdeck"`
	RevDeckChatThreads *ghidraChatThreads `json:"revdeck_chat_threads"`
	RevDeckRecovery    *ghidraRecovery    `json:"revdeck_recovery"`
}

type revdeckPageData struct {
	pageMeta
	Generated time.Time
	Detail    *revdeckStandaloneResult
}

func revdeckRequestDir() string { return getenv("REVDECK_REQUEST_DIR", "") }
func revdeckResultsDir() string { return getenv("REVDECK_RESULTS_DIR", "") }

// loadRevdeckResults reads the revdeck-analysis-v1 ES mirror (#404)
// exclusively (#1103) -- see loadGhidraResults' doc comment in ghidra.go for
// the reasoning.
//
// reconcileWorkbenchRun deliberately calls loadRevdeckResultsLocal directly
// instead of this: it polls for job completion to flip run state, and the
// ES mirror's import interval (5 minutes by default) would delay or miss
// that transition -- same reasoning workbench_orchestrator.go's own comment
// gives for why it calls loadGhidraResultsLocal/loadSandboxResultsLocal
// there too.
func loadRevdeckResults() []revdeckStandaloneResult {
	if esResultsClient == nil {
		return nil
	}
	rows, _ := loadRevdeckResultsES(esResultsClient)
	return rows
}

func loadRevdeckResultsES(es *esClient) ([]revdeckStandaloneResult, bool) {
	raws, err := es.searchNamespace("revdeck-analysis-v1", "revdeck")
	if err != nil {
		return nil, false
	}
	rows := make([]revdeckStandaloneResult, 0, len(raws))
	for _, raw := range raws {
		var row revdeckStandaloneResult
		if json.Unmarshal(raw, &row) != nil || !hashName.MatchString(row.SHA256) {
			continue
		}
		rows = append(rows, row)
	}
	sortRevdeckResults(rows)
	return rows, true
}

func sortRevdeckResults(rows []revdeckStandaloneResult) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CompletedAt != rows[j].CompletedAt {
			return rows[i].CompletedAt > rows[j].CompletedAt
		}
		return rows[i].SHA256 > rows[j].SHA256
	})
}

func loadRevdeckResultsLocal() []revdeckStandaloneResult {
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
	sortRevdeckResults(rows)
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

// #1142: scoped server-side via searchNamespaceByHash instead of
// loadRevdeckResults' whole-index fetch filtered down to one match in Go
// -- this page has no listing view at all (unlike ghidra/github-analysis),
// so there was never a reason to load more than the one result being
// asked for. See loadGhidraResultByHash's own comment.
//
// Skeleton-sweep audit (#1157 follow-up): checked against the site-wide
// instant-render sweep and needs no change. searchNamespaceByHash issues one
// bounded size=5 term-query round trip -- not an unbounded whole-index
// fetch like #1156 flagged elsewhere -- and there is no per-file computation
// (hashing/entropy/YARA) like the /payload-analysis finding this sweep
// otherwise centers on. No skeleton is warranted; there's no genuinely slow
// work here to hide behind one.
func revdeckData(sha256 string) (revdeckPageData, error) {
	data := revdeckPageData{Generated: time.Now()}
	if sha256 == "" {
		return data, errors.New("revdeck result not found")
	}
	if esResultsClient == nil {
		return data, errors.New("revdeck result not found")
	}
	raws, err := esResultsClient.searchNamespaceByHash("revdeck-analysis-v1", "revdeck", sha256, 5)
	if err != nil {
		return data, errors.New("revdeck result not found")
	}
	// Verified here, not trusted from the query alone -- see
	// loadGhidraResultByHash's own comment on why.
	for _, raw := range raws {
		var row revdeckStandaloneResult
		if json.Unmarshal(raw, &row) != nil || !strings.EqualFold(row.SHA256, sha256) {
			continue
		}
		data.Detail = &row
		return data, nil
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
