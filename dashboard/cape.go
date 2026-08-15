package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// cape.go — Workbench registry wiring and the /cape/{sha256} result page
// (#319).
//
// #319's own text was explicit that the result page depends on "a real
// result shape" from #318 -- and until #318 actually verified cape-worker.py
// against a live win11-cape detonation, there was no real {sha256}_cape.json
// to design against without guessing, the same "don't guess an endpoint
// contract" discipline ghidra-worker.py's own header already warns about.
// #318 is done now (two live round trips against production win11-cape,
// tasks 8 and 9) -- capeResult below matches what cape-worker.py's
// analyse_one() actually writes, and capeReportSummary matches the real
// CAPE report shape observed live against task 9's report, not CAPEv2's
// documentation.
func capeRequestDir() string { return getenv("CAPE_REQUEST_DIR", "") }
func capeResultsDir() string { return getenv("CAPE_RESULTS_DIR", "") }

// capeSignature mirrors the flattened shape cape-worker.py's analyse_one()
// already reduces CAPE's own (much larger, version-dependent) signature
// objects to.
type capeSignature struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    any    `json:"severity"`
}

// capeResult mirrors {sha256}_cape.json, written by cape-worker.py's
// write_result(). Report is kept as raw JSON rather than a fully-typed CAPE
// report struct: the substructures actually worth surfacing (see
// capeReportSummary below) are parsed out of it on demand by capeData(),
// but the full report can be tens of thousands of API-call entries per
// process (11,056 for a single trivial process in the #318 verification
// run) -- far too large and too CAPE-version-dependent to model
// exhaustively up front, the same reasoning analyse_one()'s own "report"
// field comment gives for keeping it as-is rather than re-shaping it in
// the worker.
type capeResult struct {
	Version     int             `json:"version"`
	SHA256      string          `json:"sha256"`
	RequestedAt string          `json:"requested_at"`
	StartedAt   string          `json:"started_at"`
	CompletedAt string          `json:"completed_at"`
	ExitStatus  string          `json:"exit_status"`
	Error       string          `json:"error,omitempty"`
	TaskID      *int            `json:"task_id"`
	CapeStatus  string          `json:"cape_status"`
	Route       string          `json:"route"`
	Score       *float64        `json:"score"`
	Category    string          `json:"category"`
	Signatures  []capeSignature `json:"signatures"`
	Report      json.RawMessage `json:"report,omitempty"`
}

// ScoreDisplay renders Score for the template. Not {{printf "%.0f"
// .Detail.Score}} in the template itself -- confirmed live that
// text/template's printf (unlike its own default {{.}} print action) does
// not dereference a *float64, and prints the pointer's address instead of
// the value it points to.
func (r *capeResult) ScoreDisplay() string {
	if r == nil || r.Score == nil {
		return "0"
	}
	return strconv.FormatFloat(*r.Score, 'f', 0, 64)
}

// ScoreIsRisky is deliberately not "{{if .Detail.Score}}" in the template:
// a Go template's {{if}} on a non-nil pointer only checks nil-ness, not the
// value it points to -- a confirmed-benign malscore of 0.0 (a real result,
// task 9 in the #318 verification run) is a non-nil *float64 and would
// have read as truthy, highlighting a clean result the same red as an
// actually risky one.
func (r *capeResult) ScoreIsRisky() bool {
	return r != nil && r.Score != nil && *r.Score > 0
}

// capeProcessSummary is one entry from the real report's behavior.processes
// array, reduced to what's renderable at a glance -- NOT the per-process
// "calls" array itself (11,056 entries for one process in the #318
// verification run; see capeReportSummary's own comment on why the
// debugger trace stays a count here, not an inline list).
type capeProcessSummary struct {
	ProcessID   int
	ProcessName string
	ParentID    int
	ModulePath  string
	FirstSeen   string
	CallCount   int
}

// capeReportSummary is what capeData() extracts from capeResult.Report for
// the detail page -- the specific sections #319's own issue text asked for
// (debugger trace, dynamic YARA/config extraction, dumped payloads,
// behavioral/network analysis), confirmed against a real report (#318,
// task 9) rather than CAPEv2's documentation:
//
//   - Machine/Package/Route/Timeout/Duration: info.{machine,package,route,
//     timeout,duration} -- which guest ran this and how long it took.
//   - MalScore/MalStatus: top-level malscore/malstatus.
//   - Summary/SummaryKeys: behavior.summary, a map of category
//     (files/keys/mutexes/...) to the (potentially very large -- 4,761
//     registry keys touched in the #318 verification run) list of values
//     CAPE observed. Rendered as counts with an evidence-panel per
//     category, the same pattern sandbox.html's own Suspicious Windows API
//     imports table already uses for a map[string][]string.
//   - Processes: behavior.processes, reduced to identity + a call COUNT
//     (see capeProcessSummary) -- the debugger trace itself (each
//     process's full "calls" array) is not rendered inline at all; it is
//     available via /api/cape/{sha256}'s raw report for anyone who needs
//     it, the same "too large for this page, use the API" posture
//     ghidra.html already takes toward its own largest evidence sections.
//   - Payloads/Configs: CAPE.payloads / CAPE.configs -- CAPE's own dumped
//     payloads and extracted malware configuration, empty for anything
//     that never triggered either.
//   - DebugLog/DebugErrors: debug.log / debug.errors -- the analyzer's own
//     operational log, not a per-instruction breakpoint trace (CAPE does
//     not expose one over apiv2; the closest live equivalent is the
//     per-process API call trace already described above).
type capeReportSummary struct {
	Machine     string
	Package     string
	Route       string
	Timeout     bool
	Duration    int
	MalScore    float64
	MalStatus   string
	Summary     map[string][]string
	SummaryKeys []string // sorted, so the template range has a stable order
	Processes   []capeProcessSummary
	TotalCalls  int // sum of every Processes[].CallCount, computed once here
	// rather than in the template -- html/template has no arithmetic
	// built-in to sum a range itself.
	Payloads    []map[string]any
	Configs     []map[string]any
	DebugLog    string
	DebugErrors []string
}

func parseCapeReportSummary(raw json.RawMessage) *capeReportSummary {
	if len(raw) == 0 {
		return nil
	}
	var report struct {
		Info struct {
			Machine struct {
				Label string `json:"label"`
			} `json:"machine"`
			Package  string `json:"package"`
			Route    string `json:"route"`
			Timeout  bool   `json:"timeout"`
			Duration int    `json:"duration"`
		} `json:"info"`
		MalScore  float64 `json:"malscore"`
		MalStatus *string `json:"malstatus"`
		Behavior  struct {
			Summary   map[string][]string `json:"summary"`
			Processes []struct {
				ProcessID   int             `json:"process_id"`
				ProcessName string          `json:"process_name"`
				ParentID    int             `json:"parent_id"`
				ModulePath  string          `json:"module_path"`
				FirstSeen   string          `json:"first_seen"`
				Calls       json.RawMessage `json:"calls"`
			} `json:"processes"`
		} `json:"behavior"`
		CAPE struct {
			Payloads []map[string]any `json:"payloads"`
			Configs  []map[string]any `json:"configs"`
		} `json:"CAPE"`
		Debug struct {
			Log    string   `json:"log"`
			Errors []string `json:"errors"`
		} `json:"debug"`
	}
	if json.Unmarshal(raw, &report) != nil {
		return nil
	}
	s := &capeReportSummary{
		Machine:     report.Info.Machine.Label,
		Package:     report.Info.Package,
		Route:       report.Info.Route,
		Timeout:     report.Info.Timeout,
		Duration:    report.Info.Duration,
		MalScore:    report.MalScore,
		Summary:     report.Behavior.Summary,
		Payloads:    report.CAPE.Payloads,
		Configs:     report.CAPE.Configs,
		DebugLog:    report.Debug.Log,
		DebugErrors: report.Debug.Errors,
	}
	if report.MalStatus != nil {
		s.MalStatus = *report.MalStatus
	}
	for name := range s.Summary {
		s.SummaryKeys = append(s.SummaryKeys, name)
	}
	sort.Strings(s.SummaryKeys)
	for _, p := range report.Behavior.Processes {
		s.Processes = append(s.Processes, capeProcessSummary{
			ProcessID:   p.ProcessID,
			ProcessName: p.ProcessName,
			ParentID:    p.ParentID,
			ModulePath:  p.ModulePath,
			FirstSeen:   p.FirstSeen,
			CallCount:   countJSONArrayElements(p.Calls),
		})
	}
	for _, p := range s.Processes {
		s.TotalCalls += p.CallCount
	}
	return s
}

// countJSONArrayElements counts top-level elements of a JSON array without
// fully decoding each one into a Go value -- at CAPE's real scale (11,000+
// calls for one process, each carrying a full argument list) that decode
// cost is the expensive part, and this page only ever needs the count, not
// the calls themselves (see capeReportSummary's own comment on why).
func countJSONArrayElements(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	tok, err := dec.Token()
	if err != nil {
		return 0
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return 0
	}
	n := 0
	for dec.More() {
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			break
		}
		n++
	}
	return n
}

type capePageData struct {
	pageMeta
	Generated     time.Time
	Detail        *capeResult
	Summary       *capeReportSummary
	DetailLoading bool
}

// loadCapeResults reads the cape-analysis-v1 ES mirror exclusively (#1103)
// -- see loadGhidraResults' doc comment in ghidra.go for the reasoning.
func loadCapeResults() []capeResult {
	if esResultsClient == nil {
		return nil
	}
	rows, _ := loadCapeResultsES(esResultsClient)
	return rows
}

func loadCapeResultsES(es *esClient) ([]capeResult, bool) {
	raws, err := es.searchNamespace("cape-analysis-v1", "cape")
	if err != nil {
		return nil, false
	}
	rows := make([]capeResult, 0, len(raws))
	for _, raw := range raws {
		var row capeResult
		if json.Unmarshal(raw, &row) != nil || !hashName.MatchString(row.SHA256) {
			continue
		}
		rows = append(rows, row)
	}
	sortCapeResults(rows)
	return rows, true
}

func sortCapeResults(rows []capeResult) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CompletedAt != rows[j].CompletedAt {
			return rows[i].CompletedAt > rows[j].CompletedAt
		}
		return rows[i].SHA256 < rows[j].SHA256
	})
}

func capeData(sha256 string) (capePageData, error) {
	data := capePageData{Generated: time.Now()}
	if sha256 == "" {
		return data, errors.New("cape result not found")
	}
	if esResultsClient != nil {
		raws, err := esResultsClient.searchNamespaceByHash("cape-analysis-v1", "cape", sha256, 5)
		if err == nil {
			for _, raw := range raws {
				var result capeResult
				if json.Unmarshal(raw, &result) == nil && strings.EqualFold(result.SHA256, sha256) {
					data.Detail = &result
					data.Summary = parseCapeReportSummary(result.Report)
					return data, nil
				}
			}
		}
	}
	return data, errors.New("cape result not found")
}

func capeDetailShell(sha256 string) capePageData {
	return capePageData{Generated: time.Now(), Detail: &capeResult{SHA256: sha256}, DetailLoading: true}
}

func serveCapeAPI(w http.ResponseWriter, r *http.Request) {
	sha := strings.TrimPrefix(r.URL.Path, "/api/cape/")
	if sha == "" || !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	data, err := capeData(sha)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data.Detail)
}

// capeQueueStatus matches the status.json cape-worker.py's write_status()
// writes (#319 follow-up) -- deliberately the exact same field names and
// glob conventions as ghidraQueueStatus/loadGhidraStatus(), so the
// staleness and live-recheck logic below is a close copy of that one
// rather than a new design. #319's own issue text asked for this
// explicitly: "a stalled or unhealthy CAPE worker surfaces the same way a
// stalled Ghidra queue already does."
type capeQueueStatus struct {
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
	Queued    int    `json:"queued"`
	Running   int    `json:"running"`
	Failed    int    `json:"failed"`
	Done      int    `json:"done"`
	// Stale reports that status.json has not been rewritten recently. See
	// ghidraQueueStatus's own Stale comment -- same reasoning, same
	// systemd path-unit trigger model (honeypot-cape-worker.path).
	Stale bool `json:"stale"`
	// Configured is false when CAPE_RESULTS_DIR is unset, i.e. the CAPE
	// worker was never deployed on this host.
	Configured bool `json:"configured"`
}

// capeStatusStaleAfter mirrors ghidraStatusStaleAfter. CAPE detonations run
// far longer than a Ghidra headless pass (minutes, not seconds -- #320's own
// KVM lock exists because of that), so the same 30-minute threshold is
// already generous rather than tight for this worker too.
const capeStatusStaleAfter = 30 * time.Minute

func loadCapeStatus() capeQueueStatus {
	dir := capeResultsDir()
	status := capeQueueStatus{Configured: dir != ""}
	if dir == "" {
		return status
	}
	path := filepath.Join(dir, "status.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		// No status.json yet is the normal state before the worker's first
		// run -- see loadGhidraStatus's own comment for why this reports
		// stale rather than an empty queue.
		status.Stale = true
		return status
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		status.Configured = true
		status.Stale = true
		return status
	}
	status.Configured = true
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) > capeStatusStaleAfter {
		// Re-check the live spool before calling it stale, exact same
		// reasoning as loadGhidraStatus: a systemd *path* unit only rewrites
		// status.json when it fires, so a quiet honeypot with nothing
		// submitted for 30+ minutes is a perfectly healthy worker, not a
		// dead one -- only an old timestamp *over a non-empty spool* is a
		// real stall.
		if queued, running, ok := capeLiveSpoolCounts(); ok {
			status.Stale = queued+running > 0
			if status.Stale {
				status.Queued, status.Running = queued, running
			}
		} else {
			status.Stale = true
		}
	}
	return status
}

// capeLiveSpoolCounts mirrors ghidraLiveSpoolCounts -- re-checks
// CAPE_REQUEST_DIR directly rather than trusting a status.json that may
// itself be the stale thing in question.
func capeLiveSpoolCounts() (queued, running int, ok bool) {
	dir := capeRequestDir()
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

// capeAlerts appends CAPE queue alerts, riding the same s.alerts sink as
// ghidraAlerts/githubAnalysisAlerts (#319 follow-up). Deliberately scoped to
// worker health only -- not a malscore-threshold finding alert, unlike
// ghidraAlerts' risk-level findings section: #319's own issue text asked
// specifically for the stalled/unhealthy-worker surfacing, and a
// score-threshold alert would need its own env var and its own design
// discussion the issue never raised. capeData()'s ScoreIsRisky already
// highlights a risky score on the result page itself for anyone looking at
// one result; this is about the worker being alive at all.
func capeAlerts(s *store, messages *[]string, markOnly bool) {
	status := loadCapeStatus()
	if !status.Configured {
		// The worker was never deployed on this host -- same "no noise for
		// an unopted-in subsystem" reasoning as ghidraAlerts.
		return
	}

	emit := func(key, message string) {
		if s.alerts == nil || s.alerts.observe(key, message, "", markOnly) {
			if !markOnly {
				*messages = append(*messages, message)
			}
		}
	}

	if status.Stale {
		emit("cape:worker", fmt.Sprintf(
			"cape worker not draining: queue file is stale, %d queued, %d running (check honeypot-cape-worker.path)",
			status.Queued, status.Running))
	}
	if status.Failed > 0 {
		emit("cape:failed", fmt.Sprintf("cape queue has %d failed request(s)", status.Failed))
	}
}
