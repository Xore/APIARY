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

// The shapes here mirror what analysis/ghidra/worker/ghidra-worker.py writes.
// That worker is the only producer; the dashboard never writes a result and
// never calls the Ghidra REST service.

type ghidraFunction struct {
	Address   string `json:"address"`
	Name      string `json:"name"`
	Signature string `json:"signature"`
}

type ghidraCrypto struct {
	Address   string `json:"address"`
	Constant  string `json:"constant"`
	Algorithm string `json:"algorithm"`
}

type ghidraTriage struct {
	Workflow    string   `json:"workflow"`
	FamilyGuess string   `json:"family_guess"`
	RiskLevel   string   `json:"risk_level"`
	Behaviors   []string `json:"behaviors"`
	Model       string   `json:"model"`
}

type ghidraResult struct {
	Version     int    `json:"version"`
	SHA256      string `json:"sha256"`
	RequestedAt string `json:"requested_at"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	ExitStatus  string `json:"exit_status"`
	// Error is set only when ExitStatus is "error". The worker records a
	// result for failures too, so a job that went wrong is visible with its
	// reason rather than silently missing from the list.
	Error string `json:"error,omitempty"`

	Functions []ghidraFunction `json:"functions"`
	Strings   []string         `json:"strings"`
	Imports   []string         `json:"imports"`
	FindCrypt []ghidraCrypto   `json:"findcrypt"`

	CallGraphSVG string        `json:"call_graph_svg"`
	AITriage     *ghidraTriage `json:"ai_triage"`
	ReportPDF    string        `json:"report_pdf"`

	// Set by the dashboard, not the worker: a download route, present only
	// when the file actually exists and is a plausible size.
	ExportURL string `json:"export_url,omitempty"`
}

// ghidraQueueStatus matches the status.json the worker writes. Flat, unlike
// sandboxQueueStatus's nested Counts, because the producer is a small script
// and one shape written in one place is worth more than symmetry with a
// struct nothing shares with it.
type ghidraQueueStatus struct {
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
	Queued    int    `json:"queued"`
	Running   int    `json:"running"`
	Failed    int    `json:"failed"`
	Done      int    `json:"done"`
	// Stale reports that status.json has not been rewritten recently. The
	// worker touches it on every drain, so a cold timestamp means the path
	// unit or the service is not firing — which otherwise looks exactly like
	// an empty queue.
	Stale bool `json:"stale"`
	// Configured is false when GHIDRA_RESULTS_DIR is unset, i.e. the host-side
	// worker was never deployed. The page uses it to explain the absence
	// rather than showing a permanently empty queue.
	Configured bool `json:"configured"`
}

type ghidraPageData struct {
	Generated time.Time
	Rows      []ghidraResult
	Detail    *ghidraResult
	Status    ghidraQueueStatus
	Query     string
	Analysis  string
}

func ghidraResultsDir() string { return getenv("GHIDRA_RESULTS_DIR", "") }

// ghidraStatusStaleAfter is how long status.json may go untouched before the
// queue is reported stale. The worker rewrites it on every drain and on every
// no-op run, so anything much older than a path-unit trigger means nothing is
// consuming the spool.
const ghidraStatusStaleAfter = 30 * time.Minute

func loadGhidraResults() []ghidraResult {
	dir := ghidraResultsDir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var rows []ghidraResult
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_ghidra.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var row ghidraResult
		if err := json.Unmarshal(raw, &row); err != nil {
			// A malformed result is skipped rather than failing the page. The
			// worker writes atomically, so this means hand-editing or disk
			// damage, and one bad file should not hide the other results.
			continue
		}
		// Trust the filename over the document for identity: the filename is
		// what the worker derived from the validated request, and it is what
		// every route below looks up by.
		row.SHA256 = strings.TrimSuffix(entry.Name(), "_ghidra.json")
		if !hashName.MatchString(row.SHA256) {
			continue
		}
		attachGhidraDownload(&row)
		rows = append(rows, row)
	}
	// Newest first. CompletedAt is an RFC3339 string from the worker, which
	// sorts correctly as text for a fixed offset; fall back to the hash so the
	// order is stable rather than map-random when timestamps tie or are empty.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CompletedAt != rows[j].CompletedAt {
			return rows[i].CompletedAt > rows[j].CompletedAt
		}
		return rows[i].SHA256 < rows[j].SHA256
	})
	return rows
}

func loadGhidraStatus() ghidraQueueStatus {
	dir := ghidraResultsDir()
	status := ghidraQueueStatus{Configured: dir != ""}
	if dir == "" {
		return status
	}
	path := filepath.Join(dir, "status.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		// No status.json yet is the normal state before the worker's first
		// run. Report it as stale so the page says "not running" rather than
		// "nothing queued", which are very different things to an operator.
		status.Stale = true
		return status
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		status.Configured = true
		status.Stale = true
		return status
	}
	status.Configured = true
	if info, err := os.Stat(path); err == nil {
		status.Stale = time.Since(info.ModTime()) > ghidraStatusStaleAfter
	}
	return status
}

// attachGhidraDownload exposes a download route only for a report that exists.
// The worker leaves ReportPDF empty until IMPLEMENTATION_PLAN.md phase 5 is
// built, so today this normally does nothing — which is the point: no link is
// offered for a file that is not there.
func attachGhidraDownload(row *ghidraResult) {
	if row == nil || row.ReportPDF == "" {
		return
	}
	// The worker controls this value, but it lands in a filesystem path, so
	// treat it as untrusted anyway: only a bare filename, never a traversal.
	if row.ReportPDF != filepath.Base(row.ReportPDF) || strings.Contains(row.ReportPDF, "..") {
		row.ReportPDF = ""
		return
	}
	info, err := os.Stat(filepath.Join(ghidraResultsDir(), row.ReportPDF))
	if err != nil || info.IsDir() || info.Size() == 0 {
		return
	}
	row.ExportURL = "/export/ghidra/" + row.SHA256
}

func ghidraData(sha256, query string) (ghidraPageData, error) {
	data := ghidraPageData{
		Generated: time.Now(),
		Rows:      loadGhidraResults(),
		Status:    loadGhidraStatus(),
		Query:     strings.TrimSpace(query),
	}
	if data.Query != "" {
		needle := strings.ToLower(data.Query)
		filtered := data.Rows[:0]
		for _, row := range data.Rows {
			// Imports and the AI family guess are the two fields an analyst
			// actually hunts by; strings are deliberately excluded because a
			// binary's string table would match nearly every query.
			haystack := strings.ToLower(strings.Join(append([]string{
				row.SHA256, row.ExitStatus, triageFamily(row),
			}, row.Imports...), " "))
			if strings.Contains(haystack, needle) {
				filtered = append(filtered, row)
			}
		}
		data.Rows = filtered
	}
	if sha256 == "" {
		return data, nil
	}
	for i := range data.Rows {
		if data.Rows[i].SHA256 == sha256 {
			data.Detail = &data.Rows[i]
			return data, nil
		}
	}
	return data, errors.New("ghidra result not found")
}

func triageFamily(row ghidraResult) string {
	if row.AITriage == nil {
		return ""
	}
	return row.AITriage.FamilyGuess
}

func serveGhidraAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/ghidra/status" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loadGhidraStatus())
		return
	}
	sha := ""
	if r.URL.Path != "/api/ghidra" {
		sha = strings.TrimPrefix(r.URL.Path, "/api/ghidra/")
	}
	if sha != "" && !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	data, err := ghidraData(sha, r.URL.Query().Get("q"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if data.Detail != nil {
		json.NewEncoder(w).Encode(data.Detail)
		return
	}
	json.NewEncoder(w).Encode(data.Rows)
}

// serveGhidraExport streams the PDF report for one result.
//
// The plan also describes falling back to a zip of raw artifacts. That is not
// built here because the artifacts it would bundle — the call-graph SVG and
// the Ghidra project export — are produced by IMPLEMENTATION_PLAN.md phases
// 3-5, which do not exist yet. A zip containing one JSON file would be a
// worse download than the JSON the API already serves.
func serveGhidraExport(w http.ResponseWriter, r *http.Request) {
	sha := strings.TrimPrefix(r.URL.Path, "/export/ghidra/")
	if !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	dir := ghidraResultsDir()
	if dir == "" {
		http.NotFound(w, r)
		return
	}
	raw, err := os.ReadFile(filepath.Join(dir, sha+"_ghidra.json"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var row ghidraResult
	if err := json.Unmarshal(raw, &row); err != nil {
		http.NotFound(w, r)
		return
	}
	row.SHA256 = sha
	attachGhidraDownload(&row)
	if row.ReportPDF == "" || row.ExportURL == "" {
		http.Error(w, "no report has been generated for this analysis yet", http.StatusNotFound)
		return
	}
	// ReportPDF is re-validated as a bare filename by attachGhidraDownload
	// above, so this join cannot escape the results directory.
	path := filepath.Join(dir, row.ReportPDF)
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sha+`_ghidra.pdf"`)
	http.ServeContent(w, r, row.ReportPDF, info.ModTime(), f)
}
