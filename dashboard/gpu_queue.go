package main

// gpu_queue.go surfaces analysis/gpu-queue/gpu_queue.py's shared GPU job
// queue (#637 follow-up) to the dashboard: read-only visibility into
// queued/running/completed jobs, plus an abort action for anything still
// queued (a running job's Ollama call has already been committed to --
// abort has no effect once a drainer picks a job up, matching
// gpu_queue.py's own is_abort_requested contract).
//
// ES-only read path, same as every other analyzer result on this page --
// no direct file access, matching the rest of the dashboard.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

const gpuQueueIndex = "gpu-job-queue"

type gpuQueueJob struct {
	ID              string `json:"-"`
	JobID           string `json:"job_id"`
	JobType         string `json:"job_type"`
	Ref             string `json:"ref"`
	Model           string `json:"model"`
	EstimatedVRAMib int    `json:"estimated_vram_mib"`
	Status          string `json:"status"`
	RequestedAt     string `json:"requested_at"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
	AbortRequested  bool   `json:"abort_requested"`
	Error           string `json:"error"`
	Attempts        int    `json:"attempts"`
}

// loadGPUQueue returns every queue entry, most recently requested first.
// nil (not an error) when Elasticsearch isn't configured or the index
// doesn't exist yet -- no consumer has ever deferred a job, same as an
// empty ghidra queue being a normal, common state.
func loadGPUQueue() []gpuQueueJob {
	if esResultsClient == nil {
		return nil
	}
	hits, err := esResultsClient.docSearchAll(gpuQueueIndex, 500)
	if err != nil {
		return nil
	}
	jobs := make([]gpuQueueJob, 0, len(hits))
	for _, hit := range hits {
		var job gpuQueueJob
		if json.Unmarshal(hit.Source, &job) != nil {
			continue
		}
		job.ID = hit.ID
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].RequestedAt > jobs[j].RequestedAt })
	return jobs
}

// abortGPUQueueJob flips one job's abort_requested flag, retrying on a
// concurrent-write conflict -- same pattern as alerts.go's acknowledge().
// Reports false when the job doesn't exist or the write never landed. A
// job already running or finished still gets the flag set (harmless,
// gpu_queue.py's drainer only checks it before starting a queued job) --
// this function doesn't special-case status, the drainer's own read is
// what makes abort a no-op past "queued".
func abortGPUQueueJob(jobID string) bool {
	if esResultsClient == nil {
		return false
	}
	for attempt := 0; attempt < 5; attempt++ {
		hit, found, err := esResultsClient.docGet(gpuQueueIndex, jobID)
		if err != nil || !found {
			return false
		}
		var job map[string]json.RawMessage
		if json.Unmarshal(hit.Source, &job) != nil {
			return false
		}
		job["abort_requested"] = json.RawMessage("true")
		body, err := json.Marshal(job)
		if err != nil {
			return false
		}
		if err := esResultsClient.docIndex(gpuQueueIndex, jobID, body, false, hit.SeqNo, hit.PrimaryTerm); err == nil {
			return true
		} else if err != errESConflict {
			return false
		}
	}
	return false
}

// serveGPUQueueAbort is POST-only, admin-gated, same-origin, and redirects
// back to the calling page on success -- matching ghidra_submit.go's
// serveGhidraSubmit exactly (same trust boundary: an operator action
// against a spool/queue, not sensor data; same plain-form UX as the rest
// of this page, no separate JS/fetch layer needed).
func serveGPUQueueAbort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	if !sameOriginRequest(r) {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	jobID := strings.TrimSpace(r.FormValue("job_id"))
	if jobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}
	if !abortGPUQueueJob(jobID) {
		http.NotFound(w, r)
		return
	}
	target := "/ghidra"
	if parsed, ok := safeReturnPath(r.FormValue("return"), []string{"/ghidra/", "/ghidra"}); ok {
		target = parsed.String()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
