package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
	Size      int    `json:"size"`
}

type ghidraCrypto struct {
	Address   string `json:"address"`
	Constant  string `json:"constant"`
	Algorithm string `json:"algorithm"`
}

type ghidraFuzzyHashes struct {
	SSDeep      string `json:"ssdeep"`
	SSDeepError string `json:"ssdeep_error"`
	TLSH        string `json:"tlsh"`
	TLSHError   string `json:"tlsh_error"`
}

type ghidraSection struct {
	Name    string   `json:"name"`
	Size    int      `json:"size"`
	Entropy *float64 `json:"entropy"`
}

// ghidraLief mirrors what analysis/ghidra/statictools/server.py's
// lief_parse() returns, forwarded verbatim by the worker (#85, #138).
// Libraries and Stripped are format-specific (ELF/PE/Mach-O) and are absent
// -- zero value, not an error -- on a format that does not have the concept.
type ghidraLief struct {
	Format            string          `json:"format"`
	Architecture      string          `json:"architecture"`
	Entrypoint        string          `json:"entrypoint"`
	IsPIE             bool            `json:"is_pie"`
	SectionCount      int             `json:"section_count"`
	SectionsTruncated bool            `json:"sections_truncated"`
	Sections          []ghidraSection `json:"sections"`
	Libraries         []string        `json:"libraries"`
	// Stripped, IsDLL and CompileTimestamp are ELF/PE-specific and absent on
	// a format that has no such concept (e.g. Mach-O). Pointers so the
	// template can tell "absent" from "false"/"zero" rather than rendering a
	// claim the sidecar never made.
	Stripped         *bool  `json:"stripped"`
	IsDLL            *bool  `json:"is_dll"`
	CompileTimestamp *int64 `json:"compile_timestamp"`
}

type ghidraTriage struct {
	Workflow    string   `json:"workflow"`
	FamilyGuess string   `json:"family_guess"`
	RiskLevel   string   `json:"risk_level"`
	Behaviors   []string `json:"behaviors"`
	Model       string   `json:"model"`
	// EvidenceShown says how much of the binary the model actually saw —
	// "150/312 imports, 200/11482 strings (longest first...)". A real sample
	// overflows any context window, so the assessment is formed from a subset,
	// and the size of that subset is the single most useful thing for deciding
	// how much weight it deserves. Empty on results written before #103.
	EvidenceShown string `json:"evidence_shown"`
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

	CallGraphSVG string             `json:"call_graph_svg"`
	AITriage     *ghidraTriage      `json:"ai_triage"`
	FuzzyHashes  *ghidraFuzzyHashes `json:"fuzzy_hashes"`
	Lief         *ghidraLief        `json:"lief"`
	ReportPDF    string             `json:"report_pdf"`

	// Set by the dashboard, not the worker: download routes, present only when
	// the file actually exists.
	ExportURL    string `json:"export_url,omitempty"`
	CallGraphURL string `json:"call_graph_url,omitempty"`
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
	pageMeta
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
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) > ghidraStatusStaleAfter {
		// A cold status.json alone does not mean the worker is dead: it is a
		// systemd *path* unit (honeypot-ghidra-worker.path), triggered only
		// when a request lands in the spool, and it only rewrites status.json
		// from inside that run. Zero submissions for 30+ minutes -- routine
		// for a quiet honeypot -- leaves status.json stale with the worker
		// completely healthy (#204). Only call it stale when the *live* spool
		// (not the counts status.json itself last recorded, which predate
		// whatever made it go stale) actually has something queued or
		// running that isn't being drained; an old timestamp over an empty
		// spool is just "nothing to do". Live counts also replace the
		// stale/misleading ones from status.json so ghidraAlerts' message
		// reports what is really sitting in the spool right now.
		if queued, running, ok := ghidraLiveSpoolCounts(); ok {
			status.Stale = queued+running > 0
			if status.Stale {
				status.Queued, status.Running = queued, running
			}
		} else {
			// No request spool configured/readable to re-check against, but
			// GHIDRA_RESULTS_DIR is set: an unusual split configuration, or a
			// permissions problem. Fall back to the original, more
			// conservative "cold file means stale" behavior rather than
			// guessing that everything is fine.
			status.Stale = true
		}
	}
	return status
}

// ghidraLiveSpoolCounts re-checks the request spool directly rather than
// trusting status.json's Queued/Running fields, which are exactly the values
// that went stale -- a request that arrived after the worker's last drain
// would not be reflected in them at all. ok is false when the spool isn't
// configured or isn't readable, distinct from a genuinely empty spool.
func ghidraLiveSpoolCounts() (queued, running int, ok bool) {
	dir := ghidraRequestDir()
	if dir == "" {
		return 0, 0, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch name := entry.Name(); {
		case strings.HasSuffix(name, ".request.running"):
			running++
		case strings.HasSuffix(name, ".request"):
			queued++
		}
	}
	return queued, running, true
}

// attachGhidraDownload exposes a download route only for a report that exists.
// The worker leaves ReportPDF empty until IMPLEMENTATION_PLAN.md phase 5 is
// built, so today this normally does nothing — which is the point: no link is
// offered for a file that is not there.
func attachGhidraDownload(row *ghidraResult) {
	if row == nil {
		return
	}
	attachGhidraCallGraph(row)
	if row.ReportPDF == "" {
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

// attachGhidraCallGraph exposes the rendered call graph, if one exists. The
// worker writes {sha}_callgraph.svg only when graphviz is installed on the
// host, so on a host without it this correctly offers nothing rather than a
// broken image.
func attachGhidraCallGraph(row *ghidraResult) {
	if row.CallGraphSVG == "" {
		return
	}
	// Worker-controlled, but it becomes a filesystem path: bare filename only.
	if row.CallGraphSVG != filepath.Base(row.CallGraphSVG) ||
		strings.Contains(row.CallGraphSVG, "..") ||
		!strings.HasSuffix(row.CallGraphSVG, ".svg") {
		row.CallGraphSVG = ""
		return
	}
	info, err := os.Stat(filepath.Join(ghidraResultsDir(), row.CallGraphSVG))
	if err != nil || info.IsDir() || info.Size() == 0 {
		return
	}
	row.CallGraphURL = "/export/ghidra/" + row.SHA256 + "/callgraph.svg"
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
	if rest, ok := strings.CutSuffix(sha, "/callgraph.svg"); ok {
		serveGhidraCallGraph(w, r, rest)
		return
	}
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

// ghidraAlerts appends Ghidra queue and finding alerts, riding the same
// s.alerts sink as the sandbox and Suricata checks. No new transport.
//
// The plan sketched this against fields that do not exist here — HandoffOld,
// WorkerState, AITriage.Interesting, and a numeric GHIDRA_ALERT_RISK_SCORE.
// The worker reports a flat queue and a *string* risk level, so the checks
// below are written against what is actually produced rather than against the
// struct the sketch imagined.
func ghidraAlerts(s *store, messages *[]string, markOnly bool) {
	status := loadGhidraStatus()
	if !status.Configured {
		// The worker was never deployed on this host. Alerting about a
		// subsystem the operator has not opted into is pure noise.
		return
	}

	emit := func(key, message string) {
		if s.alerts == nil || s.alerts.observe(key, message, markOnly) {
			if !markOnly {
				*messages = append(*messages, message)
			}
		}
	}

	// One alert for "not draining", carrying the queue depth, rather than
	// separate stalled-handoff and unhealthy-worker alerts: both describe the
	// same fault and would page twice for one cause.
	if status.Stale {
		emit("ghidra:worker", fmt.Sprintf(
			"ghidra worker not draining: queue file is stale, %d queued, %d running (check honeypot-ghidra-worker.path)",
			status.Queued, status.Running))
	}
	if status.Failed > 0 {
		emit("ghidra:failed", fmt.Sprintf("ghidra queue has %d failed request(s)", status.Failed))
	}

	// Alert-worthy findings. Two things are deliberately NOT here:
	//
	// Crypto constants alone. A stock AES table appears in a great deal of
	// benign software, and the page already says their presence does not show
	// malicious use. Paging on it would train the reader to ignore the alert.
	// GHIDRA_ALERT_ON_CRYPTO=true opts in for an operator who wants it.
	//
	// A numeric risk threshold. There is no score to threshold — the worker
	// records a string level from the AI triage, so the levels that alert are
	// named instead.
	alertLevels := map[string]bool{}
	for _, level := range strings.Split(getenv("GHIDRA_ALERT_RISK_LEVELS", "high,critical"), ",") {
		if level = strings.ToLower(strings.TrimSpace(level)); level != "" {
			alertLevels[level] = true
		}
	}
	alertOnCrypto := strings.EqualFold(getenv("GHIDRA_ALERT_ON_CRYPTO", "false"), "true")

	for _, result := range loadGhidraResults() {
		if result.ExitStatus == "error" {
			emit("ghidra:error:"+result.SHA256, fmt.Sprintf(
				"ghidra analysis failed: sha256=%s reason=%s", result.SHA256, result.Error))
			continue
		}
		risky := result.AITriage != nil &&
			alertLevels[strings.ToLower(strings.TrimSpace(result.AITriage.RiskLevel))]
		crypto := alertOnCrypto && len(result.FindCrypt) > 0
		if !risky && !crypto {
			continue
		}
		// The AI level is an unverified model guess — the detail page says so,
		// and an alert that hides that would be worse than one that does not
		// fire. Say it in the message, where the reader actually sees it.
		detail := "crypto constants only"
		if risky {
			detail = fmt.Sprintf("AI-guessed risk=%s (UNVERIFIED, %s)",
				result.AITriage.RiskLevel, result.AITriage.Model)
		}
		emit("ghidra:flagged:"+result.SHA256, fmt.Sprintf(
			"ghidra flagged sample: sha256=%s crypto_hits=%d imports=%d %s",
			result.SHA256, len(result.FindCrypt), len(result.Imports), detail))
	}
}

// serveGhidraCallGraph streams the rendered call graph.
//
// The node labels are function names recovered from the sample, so this SVG is
// attacker-influenced content. An <img> tag cannot execute script in an SVG,
// but a browser navigating directly to this URL renders it as a document,
// where it can. Hence the headers: a default-src 'none' CSP leaves nothing for
// embedded script or remote references to reach, and nosniff keeps the
// declared type authoritative. The page embeds it with <img> regardless.
func serveGhidraCallGraph(w http.ResponseWriter, r *http.Request, sha string) {
	if !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	dir := ghidraResultsDir()
	if dir == "" {
		http.NotFound(w, r)
		return
	}
	// Built from the validated hash, never from a client-supplied filename.
	path := filepath.Join(dir, sha+"_callgraph.svg")
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, "callgraph.svg", info.ModTime(), f)
}
