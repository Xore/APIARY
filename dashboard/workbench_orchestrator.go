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
	runID := "run_" + idempotency

	// createMu serializes this whole check-then-submit-then-persist sequence
	// within this process (see its own doc comment on workbenchService) --
	// submitWorkbenchChild below has real side effects (host-worker request
	// marker files) that must not run twice for a genuinely simultaneous
	// duplicate submission, even though createOrReuseRun's own atomic
	// Elasticsearch create is what makes the *persisted* dedup safe across
	// processes.
	s.workbench.createMu.Lock()
	defer s.workbench.createMu.Unlock()

	if existing, err := s.workbench.findRun(runID, owner); err == nil {
		return existing, true, nil
	}
	count, err := s.workbench.countRuns()
	if err != nil {
		return workbenchRun{}, false, err
	}
	if count >= workbenchMaxRuns {
		return workbenchRun{}, false, errors.New("analysis run retention limit reached; archive old dashboard state before creating more runs")
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
	result, reused, err := s.workbench.createOrReuseRun(run)
	if err != nil {
		return workbenchRun{}, false, err
	}
	return result, reused, nil
}

// trueSHA256 resolves a payload's real, content-derived SHA-256 -- distinct
// from its primary on-disk identity, which for a Dionaea capture is that
// sensor's own MD5 (#364's own comment on serveWorkbenchPage documents this
// same split). #787: confirmed live that the Ghidra and Rev·Deck host-side
// worker scripts both reject any request marker whose filename doesn't
// match a strict 64-hex-char SHA-256 regex outright ("skipping malformed
// request"), renaming it to *.request.invalid and never processing it --
// so every Dionaea-sourced payload (the overwhelming majority of real
// captures) silently never got Ghidra/Rev·Deck analysis at all, no matter
// how many times an operator queued it. staticAnalysisFor already computes
// and ES-caches the real hash as part of the same work "deterministic local
// analysis" always runs, so this is a cache hit whenever that has already
// run for this payload, not a second full-file read.
func (s *store) trueSHA256(hash string) (string, error) {
	path, err := s.payloadPath(hash)
	if err != nil {
		return "", err
	}
	static, err := s.staticAnalysisFor(path)
	if err != nil {
		return "", err
	}
	if !hashName.MatchString(static.SHA256) {
		return "", errors.New("payload static analysis did not produce a usable SHA-256")
	}
	return static.SHA256, nil
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
		sha256, err := s.trueSHA256(hash)
		if err != nil {
			return fmt.Errorf("could not resolve the payload's true SHA-256: %w", err)
		}
		if err := createWorkbenchMarker(ghidraRequestDir(), sha256); err != nil {
			return fmt.Errorf("Ghidra request spool unavailable: %w", err)
		}
		child.TargetHash = sha256
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
	case "windows-ghosts":
		if classification.Platform != "Windows" || !classification.Dynamic {
			return errors.New("payload is not compatible with the Windows detonation route")
		}
		if err := createWorkbenchMarker(sandboxRequestDir(targetGhosts), hash); err != nil {
			return fmt.Errorf("GHOSTS sandbox request spool unavailable: %w", err)
		}
		child.State, child.Reason, child.Cancelable = "queued", "waiting for the WAN-permitted GHOSTS sandbox handoff", true
		return nil
	case "revdeck":
		sha256, err := s.trueSHA256(hash)
		if err != nil {
			return fmt.Errorf("could not resolve the payload's true SHA-256: %w", err)
		}
		if err := createWorkbenchMarker(revdeckRequestDir(), sha256); err != nil {
			return fmt.Errorf("Rev·Deck request spool unavailable: %w", err)
		}
		child.TargetHash = sha256
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
			// #787: TargetHash is the resolved true SHA-256 (see
			// submitWorkbenchChild/trueSHA256) -- the Ghidra worker names
			// its results and its request markers by that, never by
			// run.PayloadSHA256 (a Dionaea capture's own MD5 identity).
			// The fallback keeps any run created before this fix (none in
			// a fresh install, but a live upgrade could have one in
			// flight) behaving exactly as it did previously rather than
			// losing track of an already-queued job.
			ghidraHash := firstNonEmpty(child.TargetHash, run.PayloadSHA256)
			if result, ok := newestGhidraResult(ghidraHash, ghidraResults, child.CreatedAt); ok {
				child.UpdatedAt = now
				child.Cancelable = false
				child.ResultURL = "/ghidra/" + ghidraHash
				if result.ExitStatus == "error" {
					child.State, child.Reason = "failed", firstNonEmpty(result.Error, "Ghidra analysis failed")
					child.Retryable = child.Attempts <= child.Options.RetryLimit
				} else {
					child.State, child.Reason = "completed", ""
					child.Summary = fmt.Sprintf("%d functions; %d imports; %d crypto hit(s)", len(result.Functions), len(result.Imports), len(result.FindCrypt))
				}
				continue
			}
			state, reason := markerState(ghidraRequestDir(), ghidraHash)
			if state != "" {
				child.State, child.Reason = state, reason
				child.Cancelable = state == "queued"
				// #1114: a .request.failed/.request.invalid/.request.missing-sample
				// marker is just as terminal-failed as a result-based failure
				// above, which does set this -- without it, an operator who
				// hits one of these has no "Retry child" button, only
				// changing an analyzer option to force a new idempotency key
				// or resubmitting from scratch.
				if state == "failed" {
					child.Retryable = child.Attempts <= child.Options.RetryLimit
				}
			}
			child.Stale = loadGhidraStatus().Stale
		case "revdeck":
			// #787: same TargetHash split as the ghidra case above.
			revdeckHash := firstNonEmpty(child.TargetHash, run.PayloadSHA256)
			if result, ok := newestRevdeckResult(revdeckHash, revdeckResults, child.CreatedAt); ok {
				child.UpdatedAt = now
				child.Cancelable = false
				child.ResultURL = "/revdeck/" + revdeckHash
				if result.ExitStatus == "error" || result.RevDeck == nil {
					child.State, child.Reason = "failed", firstNonEmpty(result.Error, "Rev·Deck produced no usable answer")
					child.Retryable = child.Attempts <= child.Options.RetryLimit
				} else {
					child.State, child.Reason = "completed", ""
					child.Summary = fmt.Sprintf("%s (%s): %d tool call(s)", result.RevDeck.Workflow, result.RevDeck.Status, result.RevDeck.ToolCalls)
				}
				continue
			}
			state, reason := markerState(workbenchMarkerDir("revdeck"), revdeckHash)
			if state != "" {
				child.State, child.Reason = state, reason
				child.Cancelable = state == "queued"
				// #1114: see the matching comment in the ghidra case above.
				if state == "failed" {
					child.Retryable = child.Attempts <= child.Options.RetryLimit
				}
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
		switch analyzerID {
		case "windows-sandbox":
			wantedPrefix = "windows-"
		case "windows-ghosts":
			// #498: sandbox/ghosts/run_pending.sh names its result file
			// windows-ghosts-<job>.json, not windows-<job>.json -- a plain
			// "windows-" prefix would also match, but distinct prefixes
			// keep a windows-ghosts child from ever matching a windows-sandbox
			// result (or vice versa) if both ever complete for the same hash.
			wantedPrefix = "windows-ghosts-"
		}
		// "windows-ghosts-" and "windows-" overlap (both name a Windows job),
		// so a windows-sandbox child must not accept a windows-ghosts result.
		if analyzerID == "windows-sandbox" && strings.HasPrefix(result.Job, "windows-ghosts-") {
			continue
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
	case "windows-ghosts":
		return sandboxRequestDir(targetGhosts)
	case "linux-sandbox":
		return sandboxRequestDir(targetLinux)
	case "revdeck":
		return revdeckRequestDir()
	default:
		return ""
	}
}

func (s *store) getWorkbenchRun(id, owner string) (workbenchRun, error) {
	return s.workbench.updateRun(id, owner, func(run *workbenchRun) (bool, error) {
		reconciled, changed := s.reconcileWorkbenchRun(*run)
		*run = reconciled
		return changed, nil
	})
}

func (s *store) workbenchChildAction(runID, analyzerID, action, owner string) (workbenchRun, error) {
	return s.workbench.updateRun(runID, owner, func(run *workbenchRun) (bool, error) {
		*run, _ = s.reconcileWorkbenchRun(*run)
		index := -1
		for i := range run.Children {
			if run.Children[i].AnalyzerID == analyzerID {
				index = i
				break
			}
		}
		if index < 0 {
			return false, errWorkbenchNotFound
		}
		child := &run.Children[index]
		switch action {
		case "cancel":
			if !child.Cancelable || child.State != "queued" {
				return false, errors.New("only a queued child can be cancelled")
			}
			// #787: the request marker for ghidra/revdeck was filed under
			// child.TargetHash (the resolved true SHA-256), not
			// run.PayloadSHA256 -- see submitWorkbenchChild. Cancelling by
			// the wrong name would always fail with "already claimed."
			cancelHash := firstNonEmpty(child.TargetHash, run.PayloadSHA256)
			dir := workbenchMarkerDir(analyzerID)
			marker := filepath.Join(dir, cancelHash+".request")
			if dir == "" || filepath.Base(marker) != cancelHash+".request" {
				return false, errors.New("analyzer does not support cancellation")
			}
			if err := os.Remove(marker); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return false, errors.New("request was already claimed and cannot be cancelled")
				}
				return false, err
			}
			child.State, child.Reason, child.Cancelable, child.Retryable = "cancelled", "queued request cancelled", false, child.Attempts <= child.Options.RetryLimit
		case "retry":
			if !child.Retryable || child.Attempts > child.Options.RetryLimit {
				return false, errors.New("retry limit reached or child is not retryable")
			}
			path, pathErr := s.payloadPath(run.PayloadSHA256)
			if pathErr != nil {
				return false, errWorkbenchNotFound
			}
			head, readErr := readPayloadHead(path)
			if readErr != nil {
				return false, readErr
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
			return false, errors.New("unknown child action")
		}
		updateWorkbenchRunState(run)
		return true, nil
	})
}
