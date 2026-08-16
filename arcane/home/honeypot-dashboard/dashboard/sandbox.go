package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

type sandboxCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type sandboxTechnique struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Evidence string `json:"evidence"`
}

type sandboxNetwork struct {
	Packets        int            `json:"packets"`
	Bytes          int64          `json:"bytes"`
	Protocols      map[string]int `json:"protocols"`
	Events         []string       `json:"events"`
	Attempts       []string       `json:"attempts"`
	GuestPackets   int            `json:"guest_packets"`
	GuestPCAPBytes int64          `json:"guest_pcap_bytes"`
	GuestProtocols map[string]int `json:"guest_protocols"`
	GuestEvents    []string       `json:"guest_events"`
	DNSQueries     []string       `json:"dns_queries"`
	DNSEvents      []string       `json:"dns_events"`
	// RemoteIPs (#482) was extracted by the Windows sandbox pipeline's
	// extract_iocs.py all along but silently discarded before export -- see
	// sandboxIOCs's doc comment for the rest of that gap.
	RemoteIPs []string `json:"remote_ips"`
}

// sandboxIOCs (#482) carries the Windows sandbox pipeline's static
// (binary-embedded, via extract_iocs.py's printable-string scan) and
// static-only ("dormant": present in the sample but never observed at
// runtime -- either an untriggered code path or a backup C2/exfil address
// this run's observation window never exercised) IOCs, alongside dynamic
// download IOCs that were previously computed and then discarded before
// ever reaching the exported result. Windows-only for now: the Linux
// runner's export-result.py has no equivalent static extraction pass yet.
type sandboxIOCs struct {
	DownloadURLs           []string `json:"download_urls"`
	DownloadCradleCount    int      `json:"download_cradle_count"`
	StaticRemoteIPs        []string `json:"static_remote_ips"`
	StaticDNSDomains       []string `json:"static_dns_domains"`
	StaticDownloadURLs     []string `json:"static_download_urls"`
	StaticUNCPaths         []string `json:"static_unc_paths"`
	StaticOnlyRemoteIPs    []string `json:"static_only_remote_ips"`
	StaticOnlyDNSDomains   []string `json:"static_only_dns_domains"`
	StaticOnlyDownloadURLs []string `json:"static_only_download_urls"`
}

type sandboxClassification struct {
	Code         string `json:"code"`
	Label        string `json:"label"`
	Platform     string `json:"platform"`
	Category     string `json:"category"`
	AnalysisPath string `json:"analysis_path"`
	Dynamic      bool   `json:"dynamic"`
}

type sandboxHashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

type sandboxArtifacts struct {
	Kernel              string   `json:"kernel"`
	ExifTool            string   `json:"exiftool"`
	PEObjdump           string   `json:"pe_objdump"`
	ProcessesBefore     []string `json:"processes_before"`
	ProcessesAfter      []string `json:"processes_after"`
	HostTCPDumpLog      string   `json:"host_tcpdump_log"`
	GuestTCPDumpLog     string   `json:"guest_tcpdump_log"`
	ClassificationError string   `json:"classification_error"`
	PEForensicsError    string   `json:"pe_forensics_error"`
	ConsoleLog          string   `json:"console_log"`
	QEMULog             string   `json:"qemu_log"`
	DomainState         string   `json:"domain_state"`
	QEMUStatus          string   `json:"qemu_status"`
	HostPhase           string   `json:"host_phase"`
}

type sandboxPESection struct {
	Name            string  `json:"name"`
	VirtualAddress  int64   `json:"virtual_address"`
	VirtualSize     int64   `json:"virtual_size"`
	RawSize         int64   `json:"raw_size"`
	Entropy         float64 `json:"entropy"`
	Characteristics string  `json:"characteristics"`
}

type sandboxPEImport struct {
	DLL     string   `json:"dll"`
	Symbols []string `json:"symbols"`
}

type sandboxWindows struct {
	Detected          bool                `json:"detected"`
	ExecutionMode     string              `json:"execution_mode"`
	Machine           string              `json:"machine"`
	PEType            string              `json:"pe_type"`
	CompileTimestamp  string              `json:"compile_timestamp"`
	EntryPoint        int64               `json:"entry_point"`
	ImageBase         int64               `json:"image_base"`
	Subsystem         int                 `json:"subsystem"`
	DLL               bool                `json:"dll"`
	ImpHash           string              `json:"imphash"`
	SignaturePresent  bool                `json:"signature_present"`
	Authenticode      string              `json:"authenticode"`
	Sections          []sandboxPESection  `json:"sections"`
	Imports           []sandboxPEImport   `json:"imports"`
	Exports           []string            `json:"exports"`
	SuspiciousImports map[string][]string `json:"suspicious_imports"`
	ASCIIStrings      []string            `json:"ascii_strings"`
	UTF16Strings      []string            `json:"utf16_strings"`
	Warnings          []string            `json:"warnings"`
	Truncated         bool                `json:"truncated"`
}

type sandboxDifference struct {
	Added   []string
	Removed []string
}

type sandboxResult struct {
	Version     int    `json:"version"`
	Job         string `json:"job"`
	SHA256      string `json:"sha256"`
	CaptureName string `json:"capture_name"`
	Source      string `json:"source"`
	RequestedAt string `json:"requested_at"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	// CompletedAgo (#514) is computed, never read from the result JSON --
	// the queue list already gives an operator scanning for stale/stuck
	// jobs this same relative-age context via Status.Handoff/HandoffOld;
	// the completed-jobs grid had only the absolute timestamp, requiring
	// the operator to do that math themselves.
	CompletedAgo  string  `json:"-"`
	Duration      float64 `json:"duration_seconds"`
	ExitStatus    string  `json:"exit_status"`
	RunStatus     string  `json:"run_status"`
	GuestStarted  bool    `json:"guest_started"`
	FailureReason string  `json:"failure_reason"`
	TimeoutReason string  `json:"timeout_reason"`
	RiskScore     int     `json:"risk_score"`
	RiskLevel     string  `json:"risk_level"`
	Network       string  `json:"network"`
	// Route identifies which detonation backend actually ran this job --
	// "windows", "linux", or "windows-ghosts" (#327). Older result files
	// predate this field; normalizeSandboxResult backfills it from
	// Platform for those, defaulting to the isolated route rather than the
	// WAN-permitted one, since every backend before #327 was air-gapped.
	// The result template's isolation description branches on this, not on
	// Platform alone -- Platform is "Windows" for both the isolated
	// win11-sandbox route and the WAN-permitted win11-ghosts route, and
	// asserting "no forwarding, strict libvirt NIC filter" for a GHOSTS run
	// would be actively wrong, not just imprecise.
	Route           string                `json:"route"`
	FileType        string                `json:"file_type"`
	Platform        string                `json:"platform"`
	AnalysisPath    string                `json:"analysis_path"`
	ExecutionMode   string                `json:"execution_mode"`
	Classification  sandboxClassification `json:"classification"`
	Hashes          sandboxHashes         `json:"hashes"`
	Stdout          string                `json:"stdout"`
	Stderr          string                `json:"stderr"`
	RunnerLog       string                `json:"runner_log"`
	ChangedFiles    []string              `json:"changed_files"`
	SocketsBefore   []string              `json:"sockets_before"`
	SocketsAfter    []string              `json:"sockets_after"`
	TopSyscalls     []sandboxCount        `json:"top_syscalls"`
	NetworkSummary  sandboxNetwork        `json:"network_summary"`
	IOCs            sandboxIOCs           `json:"iocs"`
	Windows         sandboxWindows        `json:"windows_forensics"`
	Artifacts       sandboxArtifacts      `json:"artifacts"`
	Techniques      []sandboxTechnique    `json:"techniques"`
	Truncated       bool                  `json:"truncated"`
	HostPCAPURL     string                `json:"-"`
	HostPCAPSize    int64                 `json:"-"`
	GuestPCAPURL    string                `json:"-"`
	GuestPCAPSize   int64                 `json:"-"`
	DiagnosticsURL  string                `json:"-"`
	DiagnosticsSize int64                 `json:"-"`
	ProcessDiff     sandboxDifference     `json:"-"`
	SocketDiff      sandboxDifference     `json:"-"`
	Incomplete      bool                  `json:"-"`
	// CaptureAvailable reports whether the original capture is still in a
	// payload directory. Re-analysis needs the sample itself, so the detail
	// page only offers the button when the submit endpoint could satisfy it.
	CaptureAvailable bool `json:"-"`
}

type sandboxQueueCounts struct {
	Queued    int `json:"queued"`
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

type sandboxQueueJob struct {
	SHA256      string `json:"sha256"`
	Source      string `json:"source"`
	CaptureName string `json:"capture_name"`
	RequestedAt string `json:"requested_at"`
	State       string `json:"state"`
}

type sandboxQueueStatus struct {
	UpdatedAt   string             `json:"updated_at"`
	WorkerState string             `json:"worker_state"`
	Counts      sandboxQueueCounts `json:"counts"`
	Handoff     int                `json:"handoff"`
	HandoffOld  bool               `json:"handoff_stale"`
	Jobs        []sandboxQueueJob  `json:"jobs"`
}

// goldenImageStatus is #86's staleness report for win11-analysis.qcow2 --
// written on a host-side timer (golden-image-status.sh) into
// WINDOWS_SANDBOX_RESULTS_DIR, the same directory already bind-mounted
// read-only into the dashboard for per-job results, so no new mount/env var
// is needed to read it back out here.
type goldenImageStatus struct {
	BuiltAt          string `json:"built_at"`
	AgeDays          int    `json:"age_days"`
	ChecksumWritten  bool   `json:"checksum_written"`
	ChecksumVerified bool   `json:"checksum_verified"`
	StaleMonthly     bool   `json:"stale_monthly"`
	StaleISOEval     bool   `json:"stale_iso_eval"`
	CheckedAt        string `json:"checked_at"`
	Error            string `json:"error"`
}

type sandboxPageData struct {
	pageMeta
	Generated   time.Time
	Rows        []sandboxResult
	Detail      *sandboxResult
	Status      sandboxQueueStatus
	GoldenImage *goldenImageStatus
	Query       string
	StaticYARA  []string
	// WindowsLiveSHA256 and VNCViewerEnabled (#805) drive the "watch this
	// detonation live" banner: WindowsLiveSHA256 is set only while a
	// windows-sandbox job is actually mid-run (see windowsSandboxLiveJob),
	// VNCViewerEnabled only when the host operator has actually configured
	// the read-only VNC bridge (empty SANDBOX_VNC_BRIDGE_WS means the
	// bridge was never turned on, same off-by-default convention as
	// REVDECK_API_BASE/STATICTOOLS_API_BASE).
	WindowsLiveSHA256 string
	VNCViewerEnabled  bool
	// Analysis carries the ?analysis= marker set by the submit redirect so the
	// detail page can confirm a queued re-analysis in place.
	Analysis string
	// Loading is true only while the listing cache (s.sandboxCache) has never
	// been populated -- the same #1157 payloadsPage.Loading/#1156-follow-up
	// githubAnalysisPageData.Loading/ghidraPageData.Loading convention,
	// distinguishing "still warming up" from "genuinely no results yet" so
	// the list branch can show a skeleton instead of misreporting an empty
	// result. Always false on a detail-view render (Detail != nil), which
	// never reads the cache.
	Loading bool
	// DetailLoading marks the initial /sandbox/{job} shell. The shell only
	// carries the validated job from the URL; the full result is fetched by
	// /sandbox/{job}/fragment after the page is already visible.
	DetailLoading bool
}

var sandboxJobName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)

func sandboxResultsDir() string { return getenv("SANDBOX_RESULTS_DIR", "/sandbox-results") }

// sandboxResultsDirs lists every backend's result directory. The Windows guest
// is a separate host worker with its own spool, so it gets its own mount rather
// than sharing the Linux one; an unset variable means that worker is not
// deployed here, which is the normal state on a Linux-only host.
func sandboxResultsDirs() []string {
	dirs := []string{sandboxResultsDir()}
	if windows := getenv("WINDOWS_SANDBOX_RESULTS_DIR", ""); windows != "" && !slices.Contains(dirs, windows) {
		dirs = append(dirs, windows)
	}
	if ghosts := getenv("GHOSTS_SANDBOX_RESULTS_DIR", ""); ghosts != "" && !slices.Contains(dirs, ghosts) {
		dirs = append(dirs, ghosts)
	}
	return dirs
}

func sandboxRequestDirs() []string {
	dirs := []string{}
	for _, dir := range []string{sandboxRequestDir(targetLinux), sandboxRequestDir(targetWindows), sandboxRequestDir(targetGhosts)} {
		if dir != "" && !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// loadSandboxResults reads #383's sandbox-analysis-v1 ES mirror (#384)
// exclusively (#1103) -- see loadGhidraResults' doc comment in ghidra.go for
// the reasoning. workbench_orchestrator.go's reconcileWorkbenchRun calls
// loadSandboxResultsLocal directly instead, for the same reconciliation-
// freshness reason as the Ghidra side.
func loadSandboxResults() []sandboxResult {
	if esResultsClient == nil {
		return nil
	}
	rows, _ := loadSandboxResultsES(esResultsClient)
	return rows
}

func loadSandboxResultsES(es *esClient) ([]sandboxResult, bool) {
	raws, err := es.searchNamespace("sandbox-analysis-v1", "sandbox")
	if err != nil {
		return nil, false
	}
	return decodeSandboxRows(raws), true
}

// loadSandboxResultsESCapped is loadSandboxResultsES bounded to the newest
// `limit` rows via searchNamespaceLimit's single bounded request, instead of
// searchNamespace's whole-namespace pagination -- for
// refreshSandboxCacheAsync, which only ever needs to fill a listing view's
// own top-N (see that function's own comment, #1156-follow-up).
func loadSandboxResultsESCapped(es *esClient, limit int) ([]sandboxResult, bool) {
	raws, err := es.searchNamespaceLimit("sandbox-analysis-v1", "sandbox", limit)
	if err != nil {
		return nil, false
	}
	return decodeSandboxRows(raws), true
}

// decodeSandboxRows is the raw-hit-to-row conversion shared by
// loadSandboxResultsES and loadSandboxResultsESCapped: validate the hash,
// dedupe by job, and normalize -- identical regardless of which request
// shape fetched the raw hits.
func decodeSandboxRows(raws []json.RawMessage) []sandboxResult {
	seen := map[string]bool{}
	rows := make([]sandboxResult, 0, len(raws))
	for _, raw := range raws {
		var row sandboxResult
		if json.Unmarshal(raw, &row) != nil || !hashName.MatchString(row.SHA256) || row.Job == "" || seen[row.Job] {
			continue
		}
		seen[row.Job] = true
		normalizeSandboxResult(&row)
		rows = append(rows, row)
	}
	sortSandboxResults(&rows)
	return rows
}

// loadSandboxResultsByHash answers "every sandbox run for this hash" --
// matchingSandboxRuns' own need (a sample can be re-detonated, so unlike
// ghidra/github-analysis/revdeck this genuinely can return more than one
// result) -- scoped server-side via searchNamespaceByHash instead of
// loadSandboxResults' whole-index fetch filtered down in Go. See
// loadGhidraResultByHash's own comment (#1142).
func loadSandboxResultsByHash(es *esClient, sha256 string) []sandboxResult {
	if es == nil {
		return nil
	}
	raws, err := es.searchNamespaceByHash("sandbox-analysis-v1", "sandbox", sha256, 50)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	rows := make([]sandboxResult, 0, len(raws))
	for _, raw := range raws {
		var row sandboxResult
		// Verified here, not trusted from the query alone -- see
		// loadGhidraResultByHash's own comment on why.
		if json.Unmarshal(raw, &row) != nil || !strings.EqualFold(row.SHA256, sha256) || row.Job == "" || seen[row.Job] {
			continue
		}
		seen[row.Job] = true
		normalizeSandboxResult(&row)
		rows = append(rows, row)
	}
	sortSandboxResults(&rows)
	return rows
}

// loadSandboxResultByJob resolves the one result a sandbox detail page needs
// with a realtime document GET. es-results-importer keys sandbox documents as
// "sandbox:{job}", so scanning or searching the whole namespace here is both
// slower and less precise than addressing that stable ID directly. The body is
// still checked against the requested job rather than trusting the ID alone.
func loadSandboxResultByJob(es *esClient, job string) (sandboxResult, bool) {
	if es == nil || !sandboxJobName.MatchString(job) {
		return sandboxResult{}, false
	}
	hit, found, err := es.docGet("sandbox-analysis-v1", "sandbox:"+job)
	if err != nil || !found {
		return sandboxResult{}, false
	}
	var source struct {
		Sandbox json.RawMessage `json:"sandbox"`
	}
	if json.Unmarshal(hit.Source, &source) != nil {
		return sandboxResult{}, false
	}
	var row sandboxResult
	if json.Unmarshal(source.Sandbox, &row) != nil || row.Job != job || !hashName.MatchString(row.SHA256) {
		return sandboxResult{}, false
	}
	normalizeSandboxResult(&row)
	return row, true
}

func sortSandboxResults(rows *[]sandboxResult) {
	sort.Slice(*rows, func(i, j int) bool { return (*rows)[i].CompletedAt > (*rows)[j].CompletedAt })
	if len(*rows) > 250 {
		*rows = (*rows)[:250]
	}
}

func loadSandboxResultsLocal() []sandboxResult {
	var rows []sandboxResult
	seen := map[string]bool{}
	for _, dir := range sandboxResultsDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() ||
				(!strings.HasPrefix(entry.Name(), "linux-") && !strings.HasPrefix(entry.Name(), "windows-")) ||
				!strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			info, err := entry.Info()
			if err != nil || info.Size() > 1024*1024 {
				continue
			}
			body, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var row sandboxResult
			if json.Unmarshal(body, &row) != nil || !hashName.MatchString(row.SHA256) || row.Job == "" {
				continue
			}
			// Job identifies a run across the whole surface: it is the key for
			// the detail route and the export filenames. Two backends offering
			// the same one would make those routes ambiguous, so the first
			// directory listed wins and the duplicate is dropped.
			if seen[row.Job] {
				continue
			}
			seen[row.Job] = true
			normalizeSandboxResult(&row)
			rows = append(rows, row)
		}
	}
	sortSandboxResults(&rows)
	return rows
}

func normalizeSandboxResult(row *sandboxResult) {
	if row == nil {
		return
	}
	if row.Route == "" {
		// Every backend before #327 was air-gapped; default there rather
		// than to the WAN-permitted route for a result file that predates
		// this field entirely.
		if row.Platform == "Windows" {
			row.Route = "windows"
		} else {
			row.Route = "linux"
		}
	}
	if completed, err := time.Parse(time.RFC3339, row.CompletedAt); err == nil {
		row.CompletedAgo = ago(completed)
	}
	row.Incomplete = row.RunStatus == "failed" || row.TimeoutReason != "" ||
		row.ExitStatus == "unknown" || row.ExitStatus == "guest-no-result" || row.ExitStatus == "host-timeout"
	if row.RunStatus == "" {
		if row.Incomplete {
			row.RunStatus = "failed"
		} else {
			row.RunStatus = "completed"
		}
	}
	if row.FailureReason == "" && row.TimeoutReason == "host deadline" {
		row.FailureReason = "The virtual machine did not reach the guest analysis service before the host deadline."
	}
	if row.Incomplete {
		if row.ExitStatus == "unknown" && row.TimeoutReason == "host deadline" {
			row.ExitStatus = "host-timeout"
		}
		row.RiskScore = 0
		row.RiskLevel = "unrated"
	}
	row.ProcessDiff = sandboxLineDifference(
		row.Artifacts.ProcessesBefore,
		row.Artifacts.ProcessesAfter,
		normalizeSandboxProcess,
	)
	row.SocketDiff = sandboxLineDifference(row.SocketsBefore, row.SocketsAfter, normalizeSandboxLine)
}

func normalizeSandboxLine(line string) string {
	return strings.Join(strings.Fields(line), " ")
}

func normalizeSandboxProcess(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 11 || (fields[0] == "USER" && fields[1] == "PID") {
		return ""
	}
	command := strings.Join(fields[10:], " ")
	if strings.HasPrefix(command, "[") && strings.HasSuffix(command, "]") {
		return ""
	}
	return fields[0] + " " + command
}

func sandboxLineDifference(before, after []string, normalize func(string) string) sandboxDifference {
	beforeSet := make(map[string]struct{}, len(before))
	afterSet := make(map[string]struct{}, len(after))
	for _, line := range before {
		if value := normalize(line); value != "" {
			beforeSet[value] = struct{}{}
		}
	}
	for _, line := range after {
		if value := normalize(line); value != "" {
			afterSet[value] = struct{}{}
		}
	}
	var diff sandboxDifference
	for value := range afterSet {
		if _, found := beforeSet[value]; !found {
			diff.Added = append(diff.Added, value)
		}
	}
	for value := range beforeSet {
		if _, found := afterSet[value]; !found {
			diff.Removed = append(diff.Removed, value)
		}
	}
	sort.Strings(diff.Added)
	sort.Strings(diff.Removed)
	return diff
}

// sandboxWorkerStateRank orders worker states from healthy to broken so a
// merge across backends surfaces the worst one. A degraded Windows worker must
// not be hidden behind a healthy Linux worker just because the Linux status
// file was read first.
var sandboxWorkerStateRank = map[string]int{"idle": 1, "running": 2, "stale": 3}

// loadSandboxStatus merges the queue status of every configured backend into
// the single view the sandbox page renders.
//
// Only readable status files take part in the merge. A Windows worker that is
// configured but has not run yet has no status.json, and treating that as
// "unavailable" would report a healthy stack as broken. The signal for a
// backend that is genuinely dead is its spool filling up, which HandoffOld
// already reports.
func loadSandboxStatus() sandboxQueueStatus {
	var merged sandboxQueueStatus
	found := false
	for _, dir := range sandboxResultsDirs() {
		status, ok := readSandboxQueueFile(dir)
		if !ok {
			if !found && merged.WorkerState == "" {
				merged.WorkerState = status.WorkerState
			}
			continue
		}
		if !found {
			merged, found = status, true
		} else {
			merged.Counts.Queued += status.Counts.Queued
			merged.Counts.Running += status.Counts.Running
			merged.Counts.Completed += status.Counts.Completed
			merged.Counts.Failed += status.Counts.Failed
			merged.Jobs = append(merged.Jobs, status.Jobs...)
			if status.UpdatedAt > merged.UpdatedAt {
				merged.UpdatedAt = status.UpdatedAt
			}
			if sandboxWorkerStateRank[status.WorkerState] > sandboxWorkerStateRank[merged.WorkerState] {
				merged.WorkerState = status.WorkerState
			}
		}
	}
	for _, dir := range sandboxRequestDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".request") || !hashName.MatchString(strings.TrimSuffix(entry.Name(), ".request")) {
				continue
			}
			merged.Handoff++
			if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) > 5*time.Minute {
				merged.HandoffOld = true
			}
		}
	}
	return merged
}

// readSandboxQueueFile reads one backend's status.json. ok is false when the
// file is missing or unusable, in which case WorkerState carries the reason.
func readSandboxQueueFile(dir string) (sandboxQueueStatus, bool) {
	path := filepath.Join(dir, "status.json")
	body, err := os.ReadFile(path)
	if err != nil || len(body) > 256*1024 {
		return sandboxQueueStatus{WorkerState: "unavailable"}, false
	}
	var raw struct {
		UpdatedAt   string `json:"updated_at"`
		WorkerState string `json:"worker_state"`
		Counts      struct {
			Queued, Running, Completed, Failed int
		} `json:"counts"`
		Jobs []struct {
			SHA256      string `json:"sha256"`
			Source      string `json:"source"`
			CaptureName string `json:"capture_name"`
			RequestedAt string `json:"requested_at"`
			State       string `json:"state"`
		} `json:"jobs"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return sandboxQueueStatus{WorkerState: "invalid"}, false
	}
	status := sandboxQueueStatus{UpdatedAt: raw.UpdatedAt, WorkerState: raw.WorkerState,
		Counts: sandboxQueueCounts{raw.Counts.Queued, raw.Counts.Running, raw.Counts.Completed, raw.Counts.Failed}}
	for _, item := range raw.Jobs {
		if !hashName.MatchString(item.SHA256) {
			continue
		}
		status.Jobs = append(status.Jobs, sandboxQueueJob{item.SHA256, item.Source, item.CaptureName, item.RequestedAt, item.State})
	}
	if updated, err := time.Parse(time.RFC3339Nano, status.UpdatedAt); err == nil && status.WorkerState == "running" && time.Since(updated) > 10*time.Minute {
		status.WorkerState = "stale"
	}
	return status, true
}

// loadGoldenImageStatus reads golden-image-status.sh's output. Missing or
// unreadable is not an error: the timer may not have run yet on a fresh
// install, and this is an informational staleness badge, not a health gate.
func loadGoldenImageStatus() *goldenImageStatus {
	windows := getenv("WINDOWS_SANDBOX_RESULTS_DIR", "")
	if windows == "" {
		return nil
	}
	body, err := os.ReadFile(filepath.Join(windows, "golden-image-status.json"))
	if err != nil || len(body) > 16*1024 {
		return nil
	}
	var status goldenImageStatus
	if json.Unmarshal(body, &status) != nil {
		return nil
	}
	return &status
}

// sandboxListCap bounds refreshSandboxCacheAsync's own fetch to the newest N
// rows -- matches sortSandboxResults' own pre-existing 250-row display
// truncation (this page already discarded anything past row 250 after
// fetching it; a listing has no use for anything past what it will ever
// display). Mirrors githubAnalysisListCap/ghidraListCap's reasoning
// (#1156-follow-up).
const sandboxListCap = 250

// sandboxCacheTTL mirrors githubAnalysisCacheTTL/ghidraCacheTTL's reasoning:
// long enough that a burst of page loads shares one Elasticsearch round
// trip, short enough that a freshly completed detonation shows up without a
// meaningful wait.
const sandboxCacheTTL = 2 * time.Minute

func (s *store) sandboxData(job, query string) (sandboxPageData, error) {
	if job != "" {
		row, ok := loadSandboxResultByJob(esResultsClient, job)
		if !ok {
			return sandboxPageData{}, errors.New("sandbox result not found")
		}
		attachSandboxDownloads(&row)
		return sandboxPageData{Generated: time.Now(), Detail: &row}, nil
	}
	data := sandboxPageData{
		Generated: time.Now(), Status: loadSandboxStatus(),
		GoldenImage: loadGoldenImageStatus(), Query: strings.TrimSpace(query),
		WindowsLiveSHA256: windowsSandboxLiveJob(), VNCViewerEnabled: getenv("SANDBOX_VNC_BRIDGE_WS", "") != "",
	}
	if job == "" {
		// #1156-follow-up: this used to call loadSandboxResults() (a
		// whole-namespace ES fetch, up to searchNamespaceMaxPages*
		// searchNamespacePageSize documents, paginated) synchronously on
		// every load of this listing, only to immediately discard
		// everything past sortSandboxResults' own 250-row display cap.
		// refreshSandboxCacheAsync keeps that off the request path entirely
		// (#1157's payloadCache shape) and bounds the fetch itself to
		// sandboxListCap, so the query stops after the rows the page will
		// ever display instead of paginating the whole index first.
		s.refreshSandboxCacheAsync()
		s.sandboxMu.Lock()
		data.Rows = append([]sandboxResult(nil), s.sandboxCache...)
		data.Loading = s.sandboxCacheAt.IsZero() && s.sandboxRefreshing
		s.sandboxMu.Unlock()
	}
	if data.Query != "" {
		needle := strings.ToLower(data.Query)
		filtered := data.Rows[:0]
		for _, row := range data.Rows {
			haystack := strings.ToLower(strings.Join([]string{row.Job, row.SHA256, row.Source, row.CaptureName, row.FileType, row.RiskLevel}, " "))
			if strings.Contains(haystack, needle) {
				filtered = append(filtered, row)
			}
		}
		data.Rows = filtered
	}
	return data, nil
}

// sandboxDetailShell is the synchronous half of /sandbox/{job}. It performs
// no Elasticsearch or artifact reads; hp-sandbox-detail.js replaces the
// skeleton with the server-rendered fragment on its own follow-up request.
func sandboxDetailShell(job string) sandboxPageData {
	return sandboxPageData{
		Generated: time.Now(), Detail: &sandboxResult{Job: job}, DetailLoading: true,
	}
}

// refreshSandboxCacheAsync keeps the listing view's own Elasticsearch round
// trip off the HTTP request path, the same shape as
// refreshGithubAnalysisCacheAsync/refreshGhidraCacheAsync (github_analysis.go/
// ghidra.go, #1156-follow-up) -- see refreshGithubAnalysisCacheAsync's own
// comment for the general reasoning. A no-op entirely when esResultsClient
// isn't configured, mirroring loadSandboxResults' own gate, and a no-op
// while a refresh is already running or the last successful one is still
// within sandboxCacheTTL. Bounded to sandboxListCap via
// loadSandboxResultsESCapped rather than the whole-namespace
// loadSandboxResults() -- see that function's own comment.
func (s *store) refreshSandboxCacheAsync() {
	if esResultsClient == nil {
		return
	}
	s.sandboxMu.Lock()
	if s.sandboxRefreshing || (!s.sandboxCacheAt.IsZero() && time.Since(s.sandboxCacheAt) < sandboxCacheTTL) {
		s.sandboxMu.Unlock()
		return
	}
	s.sandboxRefreshing = true
	s.sandboxMu.Unlock()
	go func() {
		fresh, ok := loadSandboxResultsESCapped(esResultsClient, sandboxListCap)
		s.sandboxMu.Lock()
		defer s.sandboxMu.Unlock()
		s.sandboxRefreshing = false
		if !ok {
			// Elasticsearch unreachable this cycle -- keep serving whatever
			// the last successful read produced (the same graceful-degrade-
			// by-omission refreshPayloadCacheAsync's own ES-error path
			// uses) rather than blanking an already-warm cache.
			return
		}
		s.sandboxCache = fresh
		s.sandboxCacheAt = time.Now()
	}()
}

// sandboxCacheSnapshot returns a copy of the current sandbox listing cache,
// triggering a background refresh first (a no-op if one is already in
// flight or the last successful fetch is still within sandboxCacheTTL).
// search.go's searchRedirect/searchSandbox read through this instead of
// calling loadSandboxResults() (a whole-namespace, paginated ES fetch)
// directly, so a /search or per-keystroke /api/quick-search request never
// repeats that scan -- it reuses the same bounded cache the /sandbox
// listing itself keeps warm (#1157-follow-up).
func (s *store) sandboxCacheSnapshot() []sandboxResult {
	s.refreshSandboxCacheAsync()
	s.sandboxMu.Lock()
	defer s.sandboxMu.Unlock()
	return append([]sandboxResult(nil), s.sandboxCache...)
}

// attachSandboxDownloads exposes a download link only for an artifact that
// actually exists in sandbox-export-artifacts-v1 (#638/#764) -- never from
// disk. minSize is a light sanity floor (an empty/near-empty artifact
// almost certainly means a broken capture, not a legitimate tiny one --
// same values the old disk-backed check used), kept even though the
// upper bound the old check also had is gone: chunking removes the
// reason for one (a legitimately large PCAP is exactly what this design
// exists to support, not something to filter out).
func attachSandboxDownloads(result *sandboxResult) {
	if result == nil {
		return
	}
	for _, item := range []struct {
		kind    string
		minSize int64
		url     *string
		size    *int64
	}{
		{"host_pcap", 24, &result.HostPCAPURL, &result.HostPCAPSize},
		{"guest_pcap", 24, &result.GuestPCAPURL, &result.GuestPCAPSize},
		{"diagnostics", 22, &result.DiagnosticsURL, &result.DiagnosticsSize},
	} {
		manifest, ok := sandboxArtifactManifest(esResultsClient, result.Job, item.kind)
		if !ok || manifest.SizeBytes < item.minSize {
			continue
		}
		*item.url = "/export/sandbox/" + manifest.Filename
		*item.size = manifest.SizeBytes
	}
}

func (s *store) serveSandboxAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/sandbox/status" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loadSandboxStatus())
		return
	}
	job := ""
	if r.URL.Path != "/api/sandbox" {
		job = strings.TrimPrefix(r.URL.Path, "/api/sandbox/")
	}
	data, err := s.sandboxData(job, r.URL.Query().Get("q"))
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

func (s *store) serveSandboxExport(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/export/sandbox/")
	artifactKind := ""
	job := strings.TrimSuffix(name, ".json")
	if strings.HasSuffix(name, ".host.pcap") {
		job = strings.TrimSuffix(name, ".host.pcap")
		artifactKind = "host_pcap"
	} else if strings.HasSuffix(name, ".guest.pcap") {
		job = strings.TrimSuffix(name, ".guest.pcap")
		artifactKind = "guest_pcap"
	} else if strings.HasSuffix(name, ".diagnostics.zip") {
		job = strings.TrimSuffix(name, ".diagnostics.zip")
		artifactKind = "diagnostics"
	}
	data, err := s.sandboxData(job, "")
	if err != nil || data.Detail == nil {
		http.NotFound(w, r)
		return
	}
	if artifactKind != "" {
		if !requireAdmin(w, r) {
			return
		}
		expectedURL := data.Detail.HostPCAPURL
		if artifactKind == "guest_pcap" {
			expectedURL = data.Detail.GuestPCAPURL
		} else if artifactKind == "diagnostics" {
			expectedURL = data.Detail.DiagnosticsURL
		}
		if expectedURL == "" || expectedURL != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		// #638/#764: from sandbox-export-artifacts-v1, never disk.
		// errSandboxArtifactStorageUnavailable is the one failure mode
		// that happens before any header/byte is written (the manifest
		// fetch itself, at the top of serveSandboxArtifact) -- still a
		// clean 404. Any other error means a later chunk failed after
		// the response was already committed; serveSandboxArtifact's own
		// doc comment covers why that can only truncate the download,
		// not report a clean error, at that point.
		if err := serveSandboxArtifact(w, esResultsClient, job, artifactKind); err != nil {
			if errors.Is(err, errSandboxArtifactStorageUnavailable) {
				http.NotFound(w, r)
			}
			return
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+job+`.json"`)
	json.NewEncoder(w).Encode(data.Detail)
}
