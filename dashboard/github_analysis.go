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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

func loadGitHubAnalysisResults() []githubAnalysisResult {
	dir := githubAnalysisResultsDir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var rows []githubAnalysisResult
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var row githubAnalysisResult
		if err := json.Unmarshal(raw, &row); err != nil {
			// A malformed result is skipped rather than failing the page. Both
			// producer scripts write atomically (tmp file + rename), so this
			// means hand-editing or disk damage, and one bad file should not
			// hide the others.
			continue
		}
		// Trust the filename over the document for identity: both producer
		// scripts derive it from the sample's validated content SHA-256, and
		// it is what every route below looks up by. This also rejects
		// status.json, whose trimmed name ("status") never matches hashName.
		row.SHA256 = strings.TrimSuffix(entry.Name(), ".json")
		if !hashName.MatchString(row.SHA256) {
			continue
		}
		row.SHA256 = strings.ToLower(row.SHA256)
		// Always offered, unlike Ghidra's PDF link: the export route falls
		// back to serving the JSON record when no PDF exists, so there is
		// always something useful behind this link.
		row.ExportURL = "/export/github-analysis/" + row.SHA256
		rows = append(rows, row)
	}
	// Newest first. CompletedAt is an RFC3339 string from the producer
	// scripts, which sorts correctly as text for a fixed offset; fall back to
	// the hash so the order is stable rather than map-random when timestamps
	// tie or are empty.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CompletedAt != rows[j].CompletedAt {
			return rows[i].CompletedAt > rows[j].CompletedAt
		}
		return rows[i].SHA256 < rows[j].SHA256
	})
	return rows
}

func loadGitHubAnalysisStatus() githubAnalysisQueueStatus {
	dir := githubAnalysisResultsDir()
	status := githubAnalysisQueueStatus{Configured: dir != ""}
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
	sha := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/export/github-analysis/"))
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
