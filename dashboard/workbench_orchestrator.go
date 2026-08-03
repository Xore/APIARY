package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type workbenchRunRequest struct {
	PayloadSHA256  string               `json:"payload_sha256"`
	RecipeID       string               `json:"recipe_id,omitempty"`
	RecipeRevision int                  `json:"recipe_revision,omitempty"`
	RecipeName     string               `json:"recipe_name,omitempty"`
	Analyzers      []workbenchSelection `json:"analyzers,omitempty"`
}

func (s *store) createWorkbenchRun(request workbenchRunRequest, owner string) (workbenchRun, bool, error) {
	if s == nil || s.workbench == nil || !s.workbench.configured() {
		return workbenchRun{}, false, errors.New("analysis workbench persistence is not configured")
	}
	hash := strings.ToLower(strings.TrimSpace(request.PayloadSHA256))
	if !hashName.MatchString(hash) {
		return workbenchRun{}, false, errors.New("invalid payload hash")
	}
	path, err := s.payloadPath(hash)
	if err != nil {
		return workbenchRun{}, false, errWorkbenchNotFound
	}
	head, err := readPayloadHead(path)
	if err != nil {
		return workbenchRun{}, false, errors.New("captured payload is unreadable")
	}
	classification := classifyPayload(head)
	selections := request.Analyzers
	recipeID, recipeRevision := "one-off", 1
	recipeName := strings.TrimSpace(request.RecipeName)
	if recipeName == "" {
		recipeName = "One-off analysis"
	}
	if request.RecipeID != "" {
		recipe, recipeErr := s.workbench.recipe(request.RecipeID, request.RecipeRevision, owner)
		if recipeErr != nil {
			return workbenchRun{}, false, recipeErr
		}
		selections = recipe.Analyzers
		recipeID, recipeRevision, recipeName = recipe.ID, recipe.Revision, recipe.Name
	}
	selections, err = validateWorkbenchSelections(selections)
	if err != nil {
		return workbenchRun{}, false, err
	}
	idempotency := workbenchIdempotency(hash, recipeID, recipeRevision, owner, selections)

	s.workbench.mu.Lock()
	defer s.workbench.mu.Unlock()
	existingRuns := s.workbench.loadRunsLocked()
	for _, existing := range existingRuns {
		if existing.Owner == owner && existing.IdempotencyKey == idempotency {
			return existing, true, nil
		}
	}
	if len(existingRuns) >= workbenchMaxRuns {
		return workbenchRun{}, false, errors.New("analysis run retention limit reached; archive old dashboard state before creating more runs")
	}
	runID, err := randomWorkbenchID("run")
	if err != nil {
		return workbenchRun{}, false, err
	}
	now := time.Now().UTC()
	run := workbenchRun{
		SchemaVersion: workbenchSchemaVersion, ID: runID, PayloadSHA256: hash,
		PayloadKind: classification.Code, Owner: owner, RecipeID: recipeID,
		RecipeRevision: recipeRevision, RecipeName: recipeName,
		RecipeSnapshot: selections, IdempotencyKey: idempotency,
		State: "queued", CreatedAt: now, UpdatedAt: now,
	}
	registry := workbenchRegistry(classification)
	for _, selection := range selections {
		analyzer, _ := workbenchAnalyzerByID(registry, selection.AnalyzerID)
		child := workbenchChild{
			AnalyzerID: analyzer.ID, DisplayName: analyzer.DisplayName,
			State: "queued", Options: selection.Options, CreatedAt: now, UpdatedAt: now,
			Deadline:      now.Add(time.Duration(selection.Options.TimeoutSeconds) * time.Second),
			QueueDeadline: now.Add(time.Duration(selection.Options.MaxQueueAgeSeconds) * time.Second),
			Attempts:      1, Detonates: analyzer.Detonates, GPU: analyzer.GPU, LocalOnly: analyzer.LocalOnly,
		}
		if !analyzer.Applicable || !analyzer.Available {
			child.State, child.Reason = "skipped", analyzer.Reason
		} else if err := s.submitWorkbenchChild(hash, classification, &child); err != nil {
			child.State, child.Reason = "failed", err.Error()
			child.Retryable = child.Attempts <= child.Options.RetryLimit
		}
		run.Children = append(run.Children, child)
	}
	updateWorkbenchRunState(&run)
	if err := s.workbench.persistRunLocked(run); err != nil {
		return workbenchRun{}, false, err
	}
	return run, false, nil
}

func (s *store) submitWorkbenchChild(hash string, classification payloadClassification, child *workbenchChild) error {
	now := time.Now().UTC()
	child.UpdatedAt = now
	switch child.AnalyzerID {
	case "deterministic":
		analysis, err := s.analyzePayload(hash)
		if err != nil {
			return errors.New("deterministic analysis failed")
		}
		child.State = "completed"
		child.ResultURL = "/payload-analysis/" + hash
		child.Summary = fmt.Sprintf("risk %d/100 (%s); %d IOC(s); %d rule match(es)", analysis.RiskScore, analysis.RiskLevel, len(analysis.IOCs), len(analysis.Rules))
		child.Retryable, child.Cancelable = false, false
		return nil
	case "ghidra":
		if err := createWorkbenchMarker(ghidraRequestDir(), hash); err != nil {
			return fmt.Errorf("Ghidra request spool unavailable: %w", err)
		}
		child.State, child.Reason, child.Cancelable = "queued", "waiting for the host-side Ghidra worker", true
		return nil
	case "linux-sandbox":
		if classification.Platform == "Windows" || !classification.Dynamic {
			return errors.New("payload is not compatible with the Linux sandbox")
		}
		if err := createWorkbenchMarker(sandboxRequestDir(targetLinux), hash); err != nil {
			return fmt.Errorf("Linux sandbox request spool unavailable: %w", err)
		}
		child.State, child.Reason, child.Cancelable = "queued", "waiting for the Linux sandbox handoff", true
		return nil
	case "windows-sandbox":
		if classification.Platform != "Windows" || !classification.Dynamic {
			return errors.New("payload is not compatible with the Windows sandbox")
		}
		if err := createWorkbenchMarker(sandboxRequestDir(targetWindows), hash); err != nil {
			return fmt.Errorf("Windows sandbox request spool unavailable: %w", err)
		}
		child.State, child.Reason, child.Cancelable = "queued", "waiting for the Windows sandbox handoff", true
		return nil
	case "revdeck":
		if err := createWorkbenchMarker(revdeckRequestDir(), hash); err != nil {
			return fmt.Errorf("Rev·Deck request spool unavailable: %w", err)
		}
		child.State, child.Reason, child.Cancelable = "queued", "waiting for the host-side Rev·Deck drain", true
		return nil
	default:
		return errors.New("analyzer adapter is not implemented")
	}
}

func createWorkbenchMarker(dir, hash string) error {
	if dir == "" || !hashName.MatchString(hash) {
		return errors.New("backend is not configured")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	pending := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".request") {
			pending++
		}
	}
	if pending >= workbenchMaxQueueDepth {
		return errors.New("queue capacity reached")
	}
	path := filepath.Join(dir, hash+".request")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return file.Close()
}

func workbenchResultAfter(value string, threshold time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.Before(threshold.Add(-time.Second))
}

// reconcileWorkbenchRun re-checks each non-terminal child against the
// analyzers' own result/status files and updates the run accordingly. #348:
// once every child is terminal, nothing about the run can change again --
// terminalWorkbenchState children are already skipped below, but the four
// loadXResults/loadSandboxStatus calls used to run unconditionally anyway,
// each a full directory read + per-file JSON parse. A workbench results page
// listing hundreds of long-finished runs paid that cost, in full, for every
// run, on every view. The second return value reports whether anything
// actually changed, so callers that persist the result can skip writing an
// identical file back to disk for a run that had no work left to do.
func (s *store) reconcileWorkbenchRun(run workbenchRun) (workbenchRun, bool) {
	needsWork := false
	for index := range run.Children {
		if !terminalWorkbenchState(run.Children[index].State) {
			needsWork = true
			break
		}
	}
	if !needsWork {
		return run, false
	}
	now := time.Now().UTC()
	// #384/#404: local disk, not loadGhidraResults/loadRevdeckResults/
	// loadSandboxResults -- this loop polls for job completion to flip run
	// state, and the ES mirror's import interval (5 minutes by default)
	// would delay or miss that transition.
	ghidraResults := loadGhidraResultsLocal()
	revdeckResults := loadRevdeckResultsLocal()
	sandboxResults := loadSandboxResultsLocal()
	sandboxStatus := loadSandboxStatus()
	for index := range run.Children {
		child := &run.Children[index]
		if terminalWorkbenchState(child.State) {
			continue
		}
		child.Stale = false
		switch child.AnalyzerID {
		case "ghidra":
			if result, ok := newestGhidraResult(run.PayloadSHA256, ghidraResults, child.CreatedAt); ok {
				child.UpdatedAt = now
				child.Cancelable = false
				child.ResultURL = "/ghidra/" + run.PayloadSHA256
				if result.ExitStatus == "error" {
					child.State, child.Reason = "failed", firstNonEmpty(result.Error, "Ghidra analysis failed")
					child.Retryable = child.Attempts <= child.Options.RetryLimit
				} else {
					child.State, child.Reason = "completed", ""
					child.Summary = fmt.Sprintf("%d functions; %d imports; %d crypto hit(s)", len(result.Functions), len(result.Imports), len(result.FindCrypt))
				}
				continue
			}
			state, reason := markerState(ghidraRequestDir(), run.PayloadSHA256)
			if state != "" {
				child.State, child.Reason = state, reason
				child.Cancelable = state == "queued"
			}
			child.Stale = loadGhidraStatus().Stale
		case "revdeck":
			if result, ok := newestRevdeckResult(run.PayloadSHA256, revdeckResults, child.CreatedAt); ok {
				child.UpdatedAt = now
				child.Cancelable = false
				child.ResultURL = "/revdeck/" + run.PayloadSHA256
				if result.ExitStatus == "error" || result.RevDeck == nil {
					child.State, child.Reason = "failed", firstNonEmpty(result.Error, "Rev·Deck produced no usable answer")
					child.Retryable = child.Attempts <= child.Options.RetryLimit
				} else {
					child.State, child.Reason = "completed", ""
					child.Summary = fmt.Sprintf("%s (%s): %d tool call(s)", result.RevDeck.Workflow, result.RevDeck.Status, result.RevDeck.ToolCalls)
				}
				continue
			}
			state, reason := markerState(workbenchMarkerDir("revdeck"), run.PayloadSHA256)
			if state != "" {
				child.State, child.Reason = state, reason
				child.Cancelable = state == "queued"
			}
		case "linux-sandbox", "windows-sandbox":
			if result, ok := newestSandboxResult(child.AnalyzerID, run.PayloadSHA256, sandboxResults, child.CreatedAt); ok {
				child.UpdatedAt = now
				child.Cancelable = false
				child.ResultURL = "/sandbox/" + result.Job
				if result.Incomplete || result.RunStatus == "failed" {
					child.State, child.Reason = "failed", firstNonEmpty(result.FailureReason, result.TimeoutReason, "sandbox analysis failed")
					child.Retryable = child.Attempts <= child.Options.RetryLimit
				} else {
					child.State, child.Reason = "completed", ""
					child.Summary = fmt.Sprintf("risk %d/100 (%s); %d ATT&CK technique(s)", result.RiskScore, result.RiskLevel, len(result.Techniques))
				}
				continue
			}
			for _, job := range sandboxStatus.Jobs {
				if job.SHA256 == run.PayloadSHA256 && workbenchResultAfter(job.RequestedAt, child.CreatedAt) {
					child.State = normalizeWorkbenchQueueState(job.State)
					child.Reason = "reported by the sandbox worker"
					child.Cancelable = false
				}
			}
			if child.State == "queued" && !markerExists(workbenchMarkerDir(child.AnalyzerID), run.PayloadSHA256, ".request") {
				child.State, child.Reason, child.Cancelable = "claimed", "accepted by the host-side handoff", false
			}
			child.Stale = sandboxStatus.WorkerState == "stale" || sandboxStatus.HandoffOld
		}
		if child.State == "queued" && now.After(child.QueueDeadline) {
			child.State, child.Reason, child.Cancelable = "timed_out", "maximum queue age exceeded", false
			child.Retryable = child.Attempts <= child.Options.RetryLimit
		} else if !terminalWorkbenchState(child.State) && now.After(child.Deadline) {
			child.State, child.Reason, child.Cancelable = "timed_out", "analysis timeout exceeded", false
			child.Retryable = child.Attempts <= child.Options.RetryLimit
		}
		child.UpdatedAt = now
	}
	updateWorkbenchRunState(&run)
	return run, true
}

func newestGhidraResult(hash string, results []ghidraResult, after time.Time) (ghidraResult, bool) {
	for _, result := range results {
		if result.SHA256 == hash && workbenchResultAfter(result.CompletedAt, after) {
			return result, true
		}
	}
	return ghidraResult{}, false
}

func newestSandboxResult(analyzerID, hash string, results []sandboxResult, after time.Time) (sandboxResult, bool) {
	for _, result := range results {
		wantedPrefix := "linux-"
		if analyzerID == "windows-sandbox" {
			wantedPrefix = "windows-"
		}
		if result.SHA256 == hash && strings.HasPrefix(result.Job, wantedPrefix) && (workbenchResultAfter(result.RequestedAt, after) || workbenchResultAfter(result.CompletedAt, after)) {
			return result, true
		}
	}
	return sandboxResult{}, false
}

func markerState(dir, hash string) (string, string) {
	for _, item := range []struct{ suffix, state, reason string }{
		{".request.running", "running", "claimed by the host-side worker"},
		{".request", "queued", "waiting for the host-side worker"},
		{".request.failed", "failed", "host-side worker marked the request failed"},
		{".request.invalid", "failed", "host-side worker rejected the request"},
		{".request.missing-sample", "failed", "host-side worker could not resolve the captured sample"},
	} {
		if markerExists(dir, hash, item.suffix) {
			return item.state, item.reason
		}
	}
	return "", ""
}

func markerExists(dir, hash, suffix string) bool {
	if dir == "" || !hashName.MatchString(hash) {
		return false
	}
	info, err := os.Lstat(filepath.Join(dir, hash+suffix))
	return err == nil && info.Mode().IsRegular()
}

func normalizeWorkbenchQueueState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "queued", "pending":
		return "queued"
	case "claimed":
		return "claimed"
	case "running":
		return "running"
	case "failed", "error":
		return "failed"
	default:
		return "running"
	}
}

func workbenchMarkerDir(analyzerID string) string {
	switch analyzerID {
	case "ghidra":
		return ghidraRequestDir()
	case "windows-sandbox":
		return sandboxRequestDir(targetWindows)
	case "linux-sandbox":
		return sandboxRequestDir(targetLinux)
	case "revdeck":
		return revdeckRequestDir()
	default:
		return ""
	}
}

func (s *store) getWorkbenchRun(id, owner string) (workbenchRun, error) {
	s.workbench.mu.Lock()
	defer s.workbench.mu.Unlock()
	run, err := s.workbench.loadRunLocked(id, owner)
	if err != nil {
		return workbenchRun{}, err
	}
	reconciled, changed := s.reconcileWorkbenchRun(run)
	if !changed {
		return reconciled, nil
	}
	err = s.workbench.persistRunLocked(reconciled)
	return reconciled, err
}

func (s *store) workbenchChildAction(runID, analyzerID, action, owner string) (workbenchRun, error) {
	s.workbench.mu.Lock()
	defer s.workbench.mu.Unlock()
	run, err := s.workbench.loadRunLocked(runID, owner)
	if err != nil {
		return workbenchRun{}, err
	}
	run, _ = s.reconcileWorkbenchRun(run)
	index := -1
	for i := range run.Children {
		if run.Children[i].AnalyzerID == analyzerID {
			index = i
			break
		}
	}
	if index < 0 {
		return workbenchRun{}, errWorkbenchNotFound
	}
	child := &run.Children[index]
	switch action {
	case "cancel":
		if !child.Cancelable || child.State != "queued" {
			return workbenchRun{}, errors.New("only a queued child can be cancelled")
		}
		dir := workbenchMarkerDir(analyzerID)
		marker := filepath.Join(dir, run.PayloadSHA256+".request")
		if dir == "" || filepath.Base(marker) != run.PayloadSHA256+".request" {
			return workbenchRun{}, errors.New("analyzer does not support cancellation")
		}
		if err := os.Remove(marker); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return workbenchRun{}, errors.New("request was already claimed and cannot be cancelled")
			}
			return workbenchRun{}, err
		}
		child.State, child.Reason, child.Cancelable, child.Retryable = "cancelled", "queued request cancelled", false, child.Attempts <= child.Options.RetryLimit
	case "retry":
		if !child.Retryable || child.Attempts > child.Options.RetryLimit {
			return workbenchRun{}, errors.New("retry limit reached or child is not retryable")
		}
		path, pathErr := s.payloadPath(run.PayloadSHA256)
		if pathErr != nil {
			return workbenchRun{}, errWorkbenchNotFound
		}
		head, readErr := readPayloadHead(path)
		if readErr != nil {
			return workbenchRun{}, readErr
		}
		child.Attempts++
		child.CreatedAt = time.Now().UTC()
		child.Deadline = child.CreatedAt.Add(time.Duration(child.Options.TimeoutSeconds) * time.Second)
		child.QueueDeadline = child.CreatedAt.Add(time.Duration(child.Options.MaxQueueAgeSeconds) * time.Second)
		child.Reason, child.Summary, child.ResultURL, child.Stale = "", "", "", false
		child.Retryable, child.Cancelable = false, false
		if err := s.submitWorkbenchChild(run.PayloadSHA256, classifyPayload(head), child); err != nil {
			child.State, child.Reason = "failed", err.Error()
			child.Retryable = child.Attempts <= child.Options.RetryLimit
		}
	default:
		return workbenchRun{}, errors.New("unknown child action")
	}
	updateWorkbenchRunState(&run)
	err = s.workbench.persistRunLocked(run)
	return run, err
}
