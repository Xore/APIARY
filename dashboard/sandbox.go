package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
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
	Version         int                   `json:"version"`
	Job             string                `json:"job"`
	SHA256          string                `json:"sha256"`
	CaptureName     string                `json:"capture_name"`
	Source          string                `json:"source"`
	RequestedAt     string                `json:"requested_at"`
	StartedAt       string                `json:"started_at"`
	CompletedAt     string                `json:"completed_at"`
	Duration        float64               `json:"duration_seconds"`
	ExitStatus      string                `json:"exit_status"`
	RunStatus       string                `json:"run_status"`
	GuestStarted    bool                  `json:"guest_started"`
	FailureReason   string                `json:"failure_reason"`
	TimeoutReason   string                `json:"timeout_reason"`
	RiskScore       int                   `json:"risk_score"`
	RiskLevel       string                `json:"risk_level"`
	Network         string                `json:"network"`
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

type sandboxPageData struct {
	pageMeta
	Generated  time.Time
	Rows       []sandboxResult
	Detail     *sandboxResult
	Status     sandboxQueueStatus
	Query      string
	StaticYARA []string
	// Analysis carries the ?analysis= marker set by the submit redirect so the
	// detail page can confirm a queued re-analysis in place.
	Analysis string
}

func sandboxResultsDir() string { return getenv("SANDBOX_RESULTS_DIR", "/sandbox-results") }

// sandboxResultsDirs lists every backend's result directory. The Windows guest
// is a separate host worker with its own spool, so it gets its own mount rather
// than sharing the Linux one; an unset variable means that worker is not
// deployed here, which is the normal state on a Linux-only host.
func sandboxResultsDirs() []string {
	dirs := []string{sandboxResultsDir()}
	if windows := getenv("WINDOWS_SANDBOX_RESULTS_DIR", ""); windows != "" && windows != dirs[0] {
		dirs = append(dirs, windows)
	}
	return dirs
}

func sandboxRequestDirs() []string {
	dirs := []string{}
	for _, dir := range []string{sandboxRequestDir(targetLinux), sandboxRequestDir(targetWindows)} {
		if dir != "" && !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// loadSandboxResults prefers #383's sandbox-analysis-v1 ES mirror (#384),
// falling back to the local JSON files exactly as loadGhidraResults does --
// see its doc comment for the fallback conditions. workbench_orchestrator.go's
// reconcileWorkbenchRun calls loadSandboxResultsLocal directly instead, for
// the same reconciliation-freshness reason as the Ghidra side.
func loadSandboxResults() []sandboxResult {
	if esResultsClient != nil {
		if rows, ok := loadSandboxResultsES(esResultsClient); ok {
			return rows
		}
	}
	return loadSandboxResultsLocal()
}

func loadSandboxResultsES(es *esClient) ([]sandboxResult, bool) {
	raws, err := es.searchNamespace("sandbox-analysis-v1", "sandbox", 10000)
	if err != nil {
		return nil, false
	}
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
	return rows, true
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

// sandboxArtifactFile locates a downloadable artifact across every backend's
// result directory. name is expected to be a job-derived basename, but
// serveSandboxExport's caller derives it from the request path, so it is
// re-validated here rather than trusted: rejecting anything that is not its
// own filepath.Base, or that contains "..", makes escaping the join
// impossible at the choke point instead of a property argued from the
// handler three frames away. Mirrors the ReportPDF check in ghidra.go.
func sandboxArtifactFile(name string) (string, os.FileInfo, bool) {
	if name == "" || name != filepath.Base(name) || strings.Contains(name, "..") {
		return "", nil, false
	}
	for _, dir := range sandboxResultsDirs() {
		path := filepath.Join(dir, name)
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			return path, info, true
		}
	}
	return "", nil, false
}

func normalizeSandboxResult(row *sandboxResult) {
	if row == nil {
		return
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

func sandboxData(job, query string) (sandboxPageData, error) {
	data := sandboxPageData{Generated: time.Now(), Rows: loadSandboxResults(), Status: loadSandboxStatus(), Query: strings.TrimSpace(query)}
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
	if job == "" {
		return data, nil
	}
	for i := range data.Rows {
		if data.Rows[i].Job == job {
			data.Detail = &data.Rows[i]
			attachSandboxDownloads(data.Detail)
			return data, nil
		}
	}
	return data, errors.New("sandbox result not found")
}

func attachSandboxDownloads(result *sandboxResult) {
	if result == nil {
		return
	}
	for _, item := range []struct {
		name    string
		minSize int64
		maxSize int64
		url     *string
		size    *int64
	}{
		{result.Job + ".host.pcap", 24, 64 << 20, &result.HostPCAPURL, &result.HostPCAPSize},
		{result.Job + ".guest.pcap", 24, 64 << 20, &result.GuestPCAPURL, &result.GuestPCAPSize},
		{result.Job + ".diagnostics.zip", 22, 16 << 20, &result.DiagnosticsURL, &result.DiagnosticsSize},
	} {
		_, info, ok := sandboxArtifactFile(item.name)
		if !ok || info.Size() < item.minSize || info.Size() > item.maxSize {
			continue
		}
		*item.url = "/export/sandbox/" + item.name
		*item.size = info.Size()
	}
}

func serveSandboxAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/sandbox/status" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loadSandboxStatus())
		return
	}
	job := ""
	if r.URL.Path != "/api/sandbox" {
		job = strings.TrimPrefix(r.URL.Path, "/api/sandbox/")
	}
	data, err := sandboxData(job, r.URL.Query().Get("q"))
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

func serveSandboxExport(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/export/sandbox/")
	artifactKind := ""
	job := strings.TrimSuffix(name, ".json")
	if strings.HasSuffix(name, ".host.pcap") {
		job = strings.TrimSuffix(name, ".host.pcap")
		artifactKind = "host"
	} else if strings.HasSuffix(name, ".guest.pcap") {
		job = strings.TrimSuffix(name, ".guest.pcap")
		artifactKind = "guest"
	} else if strings.HasSuffix(name, ".diagnostics.zip") {
		job = strings.TrimSuffix(name, ".diagnostics.zip")
		artifactKind = "diagnostics"
	}
	data, err := sandboxData(job, "")
	if err != nil || data.Detail == nil {
		http.NotFound(w, r)
		return
	}
	if artifactKind != "" {
		if !requireAdmin(w, r) {
			return
		}
		expectedURL := data.Detail.HostPCAPURL
		maxSize := int64(64 << 20)
		minSize := int64(24)
		contentType := "application/vnd.tcpdump.pcap"
		if artifactKind == "guest" {
			expectedURL = data.Detail.GuestPCAPURL
		} else if artifactKind == "diagnostics" {
			expectedURL = data.Detail.DiagnosticsURL
			maxSize = 16 << 20
			minSize = 22
			contentType = "application/zip"
		}
		if expectedURL == "" || expectedURL != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		path, info, ok := sandboxArtifactFile(name)
		if !ok || info.Size() < minSize || info.Size() > maxSize {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		http.ServeContent(w, r, name, info.ModTime(), f)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+job+`.json"`)
	json.NewEncoder(w).Encode(data.Detail)
}
