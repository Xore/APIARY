package main

// githubAnalysisResult mirrors the JSON that analysis/github/process-
// github-requests.sh and analysis/github/collect-results.py write to
// GITHUB_ANALYSIS_RESULTS_DIR/{sha256}.json. The dashboard never writes one
// of these files, never calls git or the GitHub API, and never holds a
// GH_PAT -- see docs/github-analysis-integration-roadmap.md.
//
// Not every field is populated for every exit_status:
//   - dry_run: version, sha256, requested_at, completed_at, exit_status only.
//   - denylist_blocked: the above plus Reason.
//   - quota_exceeded: the above plus DailyCap.
//   - error: the above plus Error.
//   - timeout: the above plus StartedAt and Commit (no run/verdict data).
//   - failed: the above plus StartedAt, Commit, RunID, RunURL (the Actions
//     run concluded but did not succeed).
//   - ok: every field below is populated.
//
// StartedAt, Commit, RunID and RunURL are absent (empty/zero, never a JSON
// null) on the four bash-written statuses -- process-github-requests.sh
// resolves a request before an Actions run exists to record.
import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type githubAnalysisScanner struct {
	Source     string `json:"source"`
	OK         bool   `json:"ok"`
	Positives  int    `json:"positives,omitempty"`
	Total      int    `json:"total,omitempty"`
	Suspicious bool   `json:"suspicious,omitempty"`
	Permalink  string `json:"permalink,omitempty"`
	Error      string `json:"error,omitempty"`
}

type githubAnalysisVerdict struct {
	Malicious  int    `json:"malicious"`
	Suspicious int    `json:"suspicious"`
	Total      int    `json:"total"`
	Level      string `json:"level"`
}

type githubAnalysisResult struct {
	Version     int    `json:"version"`
	SHA256      string `json:"sha256"`
	RequestedAt string `json:"requested_at"`
	StartedAt   string `json:"started_at,omitempty"`
	CompletedAt string `json:"completed_at"`
	ExitStatus  string `json:"exit_status"`

	// Populated only by the gate that rejected the request -- see the
	// exit_status table above. A zero value on the other two means "not
	// applicable to this status", not "no reason given".
	Reason   string `json:"reason,omitempty"`    // denylist_blocked
	DailyCap int    `json:"daily_cap,omitempty"` // quota_exceeded
	Error    string `json:"error,omitempty"`     // error

	Commit string `json:"commit,omitempty"`
	// ReportCommit is the commit reports/scanner/reports/pdf actually exist
	// at, not Commit (the original push) -- analyze.yml commits the scanner
	// JSON, YARA rules and PDF in its own later commit, so a
	// raw.githubusercontent.com URL built from Commit 404s (#255). Absent on
	// results collect-results.py wrote before that field existed; fall back
	// to Commit rather than showing no report at all in githubAnalysisPDFURL.
	ReportCommit string `json:"report_commit,omitempty"`
	RunID        int64  `json:"run_id,omitempty"`
	RunURL       string `json:"run_url,omitempty"`

	SamplePath    string                  `json:"sample_path,omitempty"`
	Family        string                  `json:"family,omitempty"`
	Verdict       *githubAnalysisVerdict  `json:"verdict,omitempty"`
	Scanners      []githubAnalysisScanner `json:"scanners,omitempty"`
	YARAAutoRules []string                `json:"yara_auto_rules,omitempty"`
	ReportPDF     string                  `json:"report_pdf,omitempty"`

	// Set by the dashboard, not the producer scripts.
	ExportURL   string `json:"export_url,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
	// ViewURL (#309) is set only when a real upstream PDF exists
	// (githubAnalysisPDFURL succeeds) -- unlike ExportURL, which is always
	// offered since it falls back to the JSON record. The detail page's
	// Report card uses ViewURL's presence to decide whether to render the
	// inline modal/iframe viewer at all, rather than opening one for a
	// result that can only ever answer with JSON.
	ViewURL string `json:"view_url,omitempty"`
}

// githubAnalysisQueueStatus matches the status.json collect-results.py
// writes on every drain. Flat, like ghidraQueueStatus, because the producer
// is a small script and one shape written in one place beats symmetry with a
// struct nothing else shares.
type githubAnalysisQueueStatus struct {
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
	Queued    int    `json:"queued"`
	Running   int    `json:"running"`
	Done      int    `json:"done"`
	Failed    int    `json:"failed"`
	Timeout   int    `json:"timeout"`
	// Stale reports that status.json has not been rewritten recently. The
	// collector runs on a one-minute timer (honeypot-github-collect.timer),
	// so a cold timestamp means the timer or the service is not firing --
	// which otherwise looks exactly like an empty queue.
	Stale bool `json:"stale"`
	// Configured is false when GITHUB_ANALYSIS_RESULTS_DIR is unset, i.e.
	// analysis/github/install-github-publisher.sh was never run on this
	// host. The page uses it to explain the absence rather than showing a
	// permanently empty queue.
	Configured bool `json:"configured"`
	// Handoff/HandoffOld mirror sandboxQueueStatus's fields of the same name
	// (dashboard/sandbox.go): the count of *.request markers still sitting in
	// GITHUB_ANALYSIS_REQUEST_DIR, and whether the oldest of them predates
	// githubAnalysisHandoffStaleAfter. honeypot-github-publish.path drains this
	// spool the moment it becomes non-empty (no polling interval to wait out),
	// so a marker that is still there after the threshold means the .path unit
	// or process-github-requests.sh itself has stopped, not that a run is
	// merely in progress.
	Handoff    int  `json:"handoff"`
	HandoffOld bool `json:"handoff_stale"`
}

type githubAnalysisPageData struct {
	pageMeta
	Generated time.Time
	Rows      []githubAnalysisResult
	Detail    *githubAnalysisResult
	Status    githubAnalysisQueueStatus
	Query     string
	Analysis  string
}

func githubAnalysisResultsDir() string { return getenv("GITHUB_ANALYSIS_RESULTS_DIR", "") }

// githubAnalysisStatusStaleAfter mirrors ghidraStatusStaleAfter's reasoning,
// scaled to this pipeline's much faster one-minute poll: half an hour
// untouched means nothing is draining GITHUB_ANALYSIS_PENDING_DIR.
const githubAnalysisStatusStaleAfter = 30 * time.Minute

// githubAnalysisHandoffStaleAfter mirrors sandbox's inline 5-minute handoff
// threshold (dashboard/sandbox.go loadSandboxStatus): the publish .path unit
// reacts to a non-empty spool immediately, so five minutes already well
// exceeds normal pickup latency.
const githubAnalysisHandoffStaleAfter = 5 * time.Minute

// loadGitHubAnalysisResults prefers #383's github-analysis-v1 ES mirror
// (#384) exclusively (#1103) -- see loadGhidraResults' doc comment in
// ghidra.go for the reasoning. Unlike Ghidra/sandbox, every caller of this
// function is a browse/search/filter surface (#384's audit found no write-
// adjacent reconciliation caller for GitHub-analysis results), so there is
// no "Local"-only variant here to preserve for a stricter freshness need.
func loadGitHubAnalysisResults() []githubAnalysisResult {
	if esResultsClient == nil {
		return nil
	}
	rows, _ := loadGitHubAnalysisResultsES(esResultsClient)
	return rows
}

func loadGitHubAnalysisResultsES(es *esClient) ([]githubAnalysisResult, bool) {
	raws, err := es.searchNamespace("github-analysis-v1", "github_analysis", 10000)
	if err != nil {
		return nil, false
	}
	rows := make([]githubAnalysisResult, 0, len(raws))
	for _, raw := range raws {
		var row githubAnalysisResult
		if json.Unmarshal(raw, &row) != nil || !hashName.MatchString(row.SHA256) {
			continue
		}
		row.SHA256 = strings.ToLower(row.SHA256)
		row.ExportURL = "/export/github-analysis/" + row.SHA256
		if _, ok := githubAnalysisPDFURL(row); ok {
			row.ViewURL = row.ExportURL + "/pdf"
		}
		rows = append(rows, row)
	}
	sortGitHubAnalysisResults(rows)
	return rows, true
}

func sortGitHubAnalysisResults(rows []githubAnalysisResult) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CompletedAt != rows[j].CompletedAt {
			return rows[i].CompletedAt > rows[j].CompletedAt
		}
		return rows[i].SHA256 < rows[j].SHA256
	})
}

// githubAnalysisHashesForFamily resolves a family label to every SHA-256 the
// upstream scanner pipeline (analysis/github/collect-results.py's
// family_for()) attributed to it. Comparison is case- and whitespace-
// insensitive, so "Mirai" and "mirai " behave as the same family instead of
// silently fragmenting into two dead-end filters -- but always exact
// equality against a value the pipeline itself already wrote, never a
// substring or pattern test against event data: the /events?family= filter
// can only ever select hashes the scanner pipeline actually named, never
// broaden into arbitrary query syntax over event fields. See #149.
func githubAnalysisHashesForFamily(family string) map[string]bool {
	family = strings.ToLower(strings.TrimSpace(family))
	if family == "" {
		return nil
	}
	hashes := map[string]bool{}
	for _, result := range loadGitHubAnalysisResults() {
		if strings.ToLower(strings.TrimSpace(result.Family)) == family {
			hashes[result.SHA256] = true
		}
	}
	return hashes
}

// loadGitHubAnalysisStatus reports Handoff/HandoffOld on every return path,
// including the unconfigured and never-run ones -- GITHUB_ANALYSIS_REQUEST_DIR
// is its own independent setting, scanned regardless of how far the results
// side of the pipeline got, the same way loadSandboxStatus scans its request
// dirs unconditionally.
func loadGitHubAnalysisStatus() (status githubAnalysisQueueStatus) {
	dir := githubAnalysisResultsDir()
	status.Configured = dir != ""
	defer func() { status.Handoff, status.HandoffOld = githubAnalysisHandoffCounts() }()
	if dir == "" {
		return status
	}
	path := filepath.Join(dir, "status.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		// No status.json yet is the normal state before the collector's
		// first run. Report it as stale so the page says "not running"
		// rather than "nothing queued", which are very different things to
		// an operator.
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
		status.Stale = time.Since(info.ModTime()) > githubAnalysisStatusStaleAfter
	}
	return status
}

// githubAnalysisHandoffCounts scans GITHUB_ANALYSIS_REQUEST_DIR for *.request
// markers the host publisher has not yet picked up, mirroring
// loadSandboxStatus's identical scan of its own request spool(s). An unset or
// unreadable directory yields (0, false) -- indistinguishable from a healthy,
// empty spool, which is correct: an operator who never ran
// install-github-publisher.sh should see "not configured", not "unhealthy".
func githubAnalysisHandoffCounts() (count int, old bool) {
	dir := githubAnalysisRequestDir()
	if dir == "" {
		return 0, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, false
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".request") ||
			!hashName.MatchString(strings.TrimSuffix(entry.Name(), ".request")) {
			continue
		}
		count++
		if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) > githubAnalysisHandoffStaleAfter {
			old = true
		}
	}
	return count, old
}

// githubAnalysisRequester scans the audit log for the newest accepted
// submission of this hash and returns who queued it. Best-effort: the
// dashboard runs with DASHBOARD_REQUIRE_ADMIN unset in single-operator
// deployments, where identity resolution fails open to an empty string, so
// an empty result here is normal and not treated as an error by callers.
func (s *store) githubAnalysisRequester(sha256 string) string {
	if s == nil || s.settings == nil {
		return ""
	}
	for _, event := range s.settings.audit.read(500) {
		if event.Action != "github_analysis.submit" || event.Result != "queued" {
			continue
		}
		if len(event.Fields) == 0 || !strings.EqualFold(event.Fields[0], sha256) {
			continue
		}
		if event.Username != "" {
			return event.Username
		}
		return event.Actor
	}
	return ""
}

func (s *store) githubAnalysisData(sha256, query string) (githubAnalysisPageData, error) {
	data := githubAnalysisPageData{
		Generated: time.Now(),
		Rows:      loadGitHubAnalysisResults(),
		Status:    loadGitHubAnalysisStatus(),
		Query:     strings.TrimSpace(query),
	}
	if data.Query != "" {
		needle := strings.ToLower(data.Query)
		filtered := data.Rows[:0]
		for _, row := range data.Rows {
			haystack := strings.ToLower(strings.Join([]string{
				row.SHA256, row.ExitStatus, row.Family,
			}, " "))
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
			data.Detail.RequestedBy = s.githubAnalysisRequester(sha256)
			return data, nil
		}
	}
	return data, errors.New("github analysis result not found")
}

func (s *store) serveGitHubAnalysisAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/github-analysis/status" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loadGitHubAnalysisStatus())
		return
	}
	sha := ""
	if r.URL.Path != "/api/github-analysis" {
		sha = strings.TrimPrefix(r.URL.Path, "/api/github-analysis/")
	}
	if sha != "" && !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	data, err := s.githubAnalysisData(strings.ToLower(sha), r.URL.Query().Get("q"))
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

// serveGitHubAnalysisExport redirects to the upstream PDF report when one
// exists, falling back to the JSON result record otherwise.
//
// This is the one place github_analysis.go deliberately diverges from
// ghidra.go's serveGhidraExport: docker-compose.yml mounts
// GITHUB_ANALYSIS_RESULTS_DIR into the dashboard container but not
// GITHUB_CLONE, so there is no local file to stream a PDF from -- the report
// lives only in the public Xore/honeypot repository collect-results.py
// pushed it to. serveGhidraExport 404s when no PDF exists; that would be
// wrong here, since a JSON record with a real verdict is always available
// and more useful than a 404.
func (s *store) serveGitHubAnalysisExport(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/export/github-analysis/")
	// #309: the detail page's Report card views the PDF inline in an
	// app-managed modal/iframe rather than redirecting straight to
	// raw.githubusercontent.com (which the dashboard's own CSP frame-src
	// would silently block anyway, render.go) or forcing a download. Kept
	// as a suffix on this same handler/route, not a separately-registered
	// pattern, matching this file's existing manual-path-parsing
	// convention rather than introducing a second style.
	if sha, ok := strings.CutSuffix(path, "/pdf"); ok {
		s.serveGitHubAnalysisPDFProxy(w, r, strings.ToLower(sha))
		return
	}
	sha := strings.ToLower(path)
	if !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	dir := githubAnalysisResultsDir()
	if dir == "" {
		http.NotFound(w, r)
		return
	}
	raw, err := os.ReadFile(filepath.Join(dir, sha+".json"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var row githubAnalysisResult
	if err := json.Unmarshal(raw, &row); err != nil {
		http.NotFound(w, r)
		return
	}
	if pdfURL, ok := githubAnalysisPDFURL(row); ok {
		http.Redirect(w, r, pdfURL, http.StatusFound)
		return
	}
	row.SHA256 = sha
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sha+`_github-analysis.json"`)
	json.NewEncoder(w).Encode(row)
}

// githubAnalysisPDFClient fetches the upstream report; a short, fixed
// timeout so a slow or hanging raw.githubusercontent.com can never stall a
// dashboard request indefinitely -- there is no retry/backoff concern here
// the way there is for ml-worker's own ES polling, since this is a
// synchronous, one-shot page-view fetch, not a background loop.
var githubAnalysisPDFClient = &http.Client{Timeout: 15 * time.Second}

// serveGitHubAnalysisPDFProxy streams the upstream raw.githubusercontent.com
// PDF bytes through the dashboard itself, same-origin (#309). Framing
// raw.githubusercontent.com directly would be silently blocked by the
// dashboard's own CSP -- frame-src only permits 'self' and the auth origin
// (render.go's secHeaders/setAuthFrameOrigin) -- so the bytes have to be
// fetched server-side and re-served from this origin instead, the same
// posture the pre-existing JSON fallback in serveGitHubAnalysisExport
// already takes (serve the content itself rather than redirect to it).
//
// Content-Disposition defaults to inline (the Report card's modal/iframe);
// ?download=1 switches to attachment, mirroring reports_api.go's
// serveGeneratedPDF -- same one-endpoint-two-dispositions shape, so a
// "download instead" action doesn't need a second route.
func (s *store) serveGitHubAnalysisPDFProxy(w http.ResponseWriter, r *http.Request, sha string) {
	if !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	dir := githubAnalysisResultsDir()
	if dir == "" {
		http.NotFound(w, r)
		return
	}
	raw, err := os.ReadFile(filepath.Join(dir, sha+".json"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var row githubAnalysisResult
	if err := json.Unmarshal(raw, &row); err != nil {
		http.NotFound(w, r)
		return
	}
	pdfURL, ok := githubAnalysisPDFURL(row)
	if !ok {
		http.Error(w, "no report has been generated for this analysis yet", http.StatusNotFound)
		return
	}
	resp, err := githubAnalysisPDFClient.Get(pdfURL)
	if err != nil {
		http.Error(w, "upstream report is not reachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "upstream report is not available", http.StatusBadGateway)
		return
	}
	disposition := "inline"
	if r.URL.Query().Get("download") == "1" {
		disposition = "attachment"
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", disposition+`; filename="`+sha+`_github-analysis.pdf"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	io.Copy(w, resp.Body)
}

// githubAnalysisCommit matches a full, lowercase git commit SHA -- the only
// shape publish-sample.sh ever records.
var githubAnalysisCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// githubAnalysisPDFURL builds the raw.githubusercontent.com URL for a
// result's report, validating both inputs first: the commit is producer-
// controlled but becomes a URL path segment, and ReportPDF is producer-
// controlled but becomes a second path segment -- treat both as untrusted,
// the same posture attachGhidraDownload takes toward a worker-written
// filename before turning it into a filesystem path.
//
// Uses ReportCommit, not Commit: analyze.yml commits the PDF in its own
// commit, after the original push Commit records, so a URL built from
// Commit 404s (#255) -- the file did not exist there yet. Falls back to
// Commit only for results collect-results.py wrote before ReportCommit
// existed, which is still better than refusing to link at all.
func githubAnalysisPDFURL(row githubAnalysisResult) (string, bool) {
	commit := row.ReportCommit
	if commit == "" {
		commit = row.Commit
	}
	if row.ReportPDF == "" || commit == "" {
		return "", false
	}
	if !githubAnalysisCommit.MatchString(commit) {
		return "", false
	}
	if strings.Contains(row.ReportPDF, "..") || strings.HasPrefix(row.ReportPDF, "/") {
		return "", false
	}
	u := url.URL{
		Scheme: "https",
		Host:   "raw.githubusercontent.com",
		Path:   "/Xore/honeypot/" + commit + "/" + row.ReportPDF,
	}
	return u.String(), true
}

// githubAnalysisAlerts appends GitHub-analysis queue and verdict alerts,
// riding the same s.alerts sink as the sandbox and Ghidra checks
// (dashboard/store.go, dashboard/ghidra.go's ghidraAlerts) -- no new
// transport. See #148 and docs/github-analysis-integration-roadmap.md Phase 5.
func githubAnalysisAlerts(s *store, messages *[]string, markOnly bool) {
	status := loadGitHubAnalysisStatus()
	if !status.Configured {
		// install-github-publisher.sh was never run on this host. Alerting
		// about a subsystem the operator has not opted into is pure noise --
		// same reasoning as ghidraAlerts's own Configured check.
		return
	}

	emit := func(key, message, link string) {
		if s.alerts == nil || s.alerts.observe(key, message, link, markOnly) {
			if !markOnly {
				*messages = append(*messages, message)
			}
		}
	}

	// One alert for a stalled handoff and a separate one for a stale/errored
	// worker, mirroring sandbox's split (sandbox:handoff vs sandbox:worker):
	// a pile of unpicked-up requests and a collector that stopped refreshing
	// status.json are different faults with different fixes (restart the
	// .path/.service unit vs. restart the collect timer), so folding them into
	// one alert would hide which one to act on.
	if status.HandoffOld {
		emit("github-analysis:handoff", fmt.Sprintf(
			"github-analysis handoff stalled: %d request(s) waiting for the host publisher", status.Handoff), "")
	}
	if status.Stale {
		emit("github-analysis:worker", fmt.Sprintf(
			"github-analysis worker unhealthy: status.json stale, queued=%d running=%d", status.Queued, status.Running), "")
	}
	if status.Failed > 0 {
		emit("github-analysis:failed", fmt.Sprintf("github-analysis queue has %d failed request(s)", status.Failed), "")
	}

	// No upper clamp, unlike SANDBOX_ALERT_RISK_SCORE/100: this counts engines
	// out of however many the upstream scanner pipeline runs, not a percentage.
	threshold, _ := strconv.Atoi(getenv("GITHUB_ANALYSIS_ALERT_POSITIVES", "10"))
	if threshold < 1 {
		threshold = 10
	}
	for _, result := range loadGitHubAnalysisResults() {
		if result.Verdict == nil || result.Verdict.Malicious < threshold {
			continue
		}
		emit("github-analysis:verdict:"+result.SHA256, fmt.Sprintf(
			"github-analysis high-verdict sample: sha256=%s malicious=%d/%d family=%s",
			result.SHA256, result.Verdict.Malicious, result.Verdict.Total, result.Family),
			"/github-analysis/"+result.SHA256)
	}
}
