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

type sandboxResult struct {
	Version        int                   `json:"version"`
	Job            string                `json:"job"`
	SHA256         string                `json:"sha256"`
	CaptureName    string                `json:"capture_name"`
	Source         string                `json:"source"`
	RequestedAt    string                `json:"requested_at"`
	StartedAt      string                `json:"started_at"`
	CompletedAt    string                `json:"completed_at"`
	Duration       float64               `json:"duration_seconds"`
	ExitStatus     string                `json:"exit_status"`
	TimeoutReason  string                `json:"timeout_reason"`
	RiskScore      int                   `json:"risk_score"`
	RiskLevel      string                `json:"risk_level"`
	Network        string                `json:"network"`
	FileType       string                `json:"file_type"`
	Platform       string                `json:"platform"`
	AnalysisPath   string                `json:"analysis_path"`
	ExecutionMode  string                `json:"execution_mode"`
	Classification sandboxClassification `json:"classification"`
	Hashes         sandboxHashes         `json:"hashes"`
	Stdout         string                `json:"stdout"`
	Stderr         string                `json:"stderr"`
	RunnerLog      string                `json:"runner_log"`
	ChangedFiles   []string              `json:"changed_files"`
	SocketsBefore  []string              `json:"sockets_before"`
	SocketsAfter   []string              `json:"sockets_after"`
	TopSyscalls    []sandboxCount        `json:"top_syscalls"`
	NetworkSummary sandboxNetwork        `json:"network_summary"`
	Windows        sandboxWindows        `json:"windows_forensics"`
	Artifacts      sandboxArtifacts      `json:"artifacts"`
	Techniques     []sandboxTechnique    `json:"techniques"`
	Truncated      bool                  `json:"truncated"`
	HostPCAPURL    string                `json:"-"`
	HostPCAPSize   int64                 `json:"-"`
	GuestPCAPURL   string                `json:"-"`
	GuestPCAPSize  int64                 `json:"-"`
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
	Generated  time.Time
	Rows       []sandboxResult
	Detail     *sandboxResult
	Status     sandboxQueueStatus
	Query      string
	StaticYARA []string
}

func sandboxResultsDir() string { return getenv("SANDBOX_RESULTS_DIR", "/sandbox-results") }

func loadSandboxResults() []sandboxResult {
	dir := sandboxResultsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	rows := make([]sandboxResult, 0, len(entries))
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
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CompletedAt > rows[j].CompletedAt })
	if len(rows) > 250 {
		rows = rows[:250]
	}
	return rows
}

func loadSandboxStatus() sandboxQueueStatus {
	path := filepath.Join(sandboxResultsDir(), "status.json")
	body, err := os.ReadFile(path)
	if err != nil || len(body) > 256*1024 {
		return sandboxQueueStatus{WorkerState: "unavailable"}
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
		return sandboxQueueStatus{WorkerState: "invalid"}
	}
	status := sandboxQueueStatus{UpdatedAt: raw.UpdatedAt, WorkerState: raw.WorkerState,
		Counts: sandboxQueueCounts{raw.Counts.Queued, raw.Counts.Running, raw.Counts.Completed, raw.Counts.Failed}}
	if entries, err := os.ReadDir(getenv("SANDBOX_REQUEST_DIR", "/sandbox-requests")); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".request") || !hashName.MatchString(strings.TrimSuffix(entry.Name(), ".request")) {
				continue
			}
			status.Handoff++
			if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) > 5*time.Minute {
				status.HandoffOld = true
			}
		}
	}
	for _, item := range raw.Jobs {
		if !hashName.MatchString(item.SHA256) {
			continue
		}
		status.Jobs = append(status.Jobs, sandboxQueueJob{item.SHA256, item.Source, item.CaptureName, item.RequestedAt, item.State})
	}
	if updated, err := time.Parse(time.RFC3339Nano, status.UpdatedAt); err == nil && status.WorkerState == "running" && time.Since(updated) > 10*time.Minute {
		status.WorkerState = "stale"
	}
	return status
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
			attachSandboxPCAPs(data.Detail)
			return data, nil
		}
	}
	return data, errors.New("sandbox result not found")
}

func attachSandboxPCAPs(result *sandboxResult) {
	if result == nil {
		return
	}
	for _, item := range []struct {
		suffix string
		url    *string
		size   *int64
	}{
		{"host", &result.HostPCAPURL, &result.HostPCAPSize},
		{"guest", &result.GuestPCAPURL, &result.GuestPCAPSize},
	} {
		name := result.Job + "." + item.suffix + ".pcap"
		info, err := os.Lstat(filepath.Join(sandboxResultsDir(), name))
		if err != nil || !info.Mode().IsRegular() || info.Size() < 24 || info.Size() > 64<<20 {
			continue
		}
		*item.url = "/export/sandbox/" + name
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
	pcapKind := ""
	job := strings.TrimSuffix(name, ".json")
	if strings.HasSuffix(name, ".host.pcap") {
		job = strings.TrimSuffix(name, ".host.pcap")
		pcapKind = "host"
	} else if strings.HasSuffix(name, ".guest.pcap") {
		job = strings.TrimSuffix(name, ".guest.pcap")
		pcapKind = "guest"
	}
	data, err := sandboxData(job, "")
	if err != nil || data.Detail == nil {
		http.NotFound(w, r)
		return
	}
	if pcapKind != "" {
		if !requireAdmin(w, r) {
			return
		}
		expectedURL := data.Detail.HostPCAPURL
		if pcapKind == "guest" {
			expectedURL = data.Detail.GuestPCAPURL
		}
		if expectedURL == "" || expectedURL != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		path := filepath.Join(sandboxResultsDir(), name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 24 || info.Size() > 64<<20 {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		http.ServeContent(w, r, name, info.ModTime(), f)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+job+`.json"`)
	json.NewEncoder(w).Encode(data.Detail)
}
