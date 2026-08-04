package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	workbenchSchemaVersion = 1
	workbenchMaxRuns       = 500
	workbenchMaxRecipes    = 100
	workbenchMaxQueueDepth = 200
)

var (
	errWorkbenchNotFound = errors.New("workbench record not found")
	errWorkbenchConflict = errors.New("workbench revision conflict")
)

// workbenchOptions is deliberately closed and typed. The browser cannot pass
// endpoint URLs, paths, commands, container names, prompts, model names or an
// unrestricted JSON object. These are orchestration controls the dashboard
// itself implements, independent of backend internals.
type workbenchOptions struct {
	TimeoutSeconds     int `json:"timeout_seconds"`
	MaxQueueAgeSeconds int `json:"max_queue_age_seconds"`
	RetryLimit         int `json:"retry_limit"`
}

type workbenchSelection struct {
	AnalyzerID string           `json:"analyzer_id"`
	Options    workbenchOptions `json:"options"`
}

type workbenchRecipe struct {
	SchemaVersion int                  `json:"schema_version"`
	ID            string               `json:"id"`
	Revision      int                  `json:"revision"`
	Name          string               `json:"name"`
	Description   string               `json:"description,omitempty"`
	Owner         string               `json:"owner"`
	Scope         string               `json:"scope"`
	CreatedAt     time.Time            `json:"created_at"`
	Analyzers     []workbenchSelection `json:"analyzers"`
}

type workbenchChild struct {
	AnalyzerID    string           `json:"analyzer_id"`
	DisplayName   string           `json:"display_name"`
	State         string           `json:"state"`
	Reason        string           `json:"reason,omitempty"`
	Summary       string           `json:"summary,omitempty"`
	ResultURL     string           `json:"result_url,omitempty"`
	Options       workbenchOptions `json:"options"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	Deadline      time.Time        `json:"deadline"`
	QueueDeadline time.Time        `json:"queue_deadline"`
	Attempts      int              `json:"attempts"`
	Retryable     bool             `json:"retryable"`
	Cancelable    bool             `json:"cancelable"`
	Detonates     bool             `json:"detonates"`
	GPU           bool             `json:"gpu_consuming"`
	LocalOnly     bool             `json:"local_only"`
	Stale         bool             `json:"stale"`
}

type workbenchRun struct {
	SchemaVersion  int                  `json:"schema_version"`
	ID             string               `json:"id"`
	PayloadSHA256  string               `json:"payload_sha256"`
	PayloadKind    string               `json:"payload_kind"`
	Owner          string               `json:"owner"`
	RecipeID       string               `json:"recipe_id,omitempty"`
	RecipeRevision int                  `json:"recipe_revision"`
	RecipeName     string               `json:"recipe_name"`
	RecipeSnapshot []workbenchSelection `json:"recipe_snapshot"`
	IdempotencyKey string               `json:"idempotency_key"`
	State          string               `json:"state"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
	Children       []workbenchChild     `json:"children"`
}

type workbenchOptionSchema struct {
	TimeoutMinSeconds  int `json:"timeout_min_seconds"`
	TimeoutMaxSeconds  int `json:"timeout_max_seconds"`
	QueueAgeMinSeconds int `json:"queue_age_min_seconds"`
	QueueAgeMaxSeconds int `json:"queue_age_max_seconds"`
	RetryLimitMax      int `json:"retry_limit_max"`
}

type workbenchAnalyzer struct {
	ID              string                `json:"id"`
	DisplayName     string                `json:"display_name"`
	Description     string                `json:"description"`
	AcceptedKinds   []string              `json:"accepted_kinds"`
	Availability    string                `json:"availability"`
	Available       bool                  `json:"available"`
	Applicable      bool                  `json:"applicable"`
	Reason          string                `json:"reason"`
	ResultLinkShape string                `json:"result_link_shape"`
	RequiredRole    string                `json:"required_role"`
	Confirmation    string                `json:"confirmation"`
	Concurrency     string                `json:"concurrency_class"`
	LocalOnly       bool                  `json:"local_only"`
	ExternallySends bool                  `json:"externally_publishing"`
	Detonates       bool                  `json:"detonates"`
	GPU             bool                  `json:"gpu_consuming"`
	DefaultOptions  workbenchOptions      `json:"default_options"`
	OptionSchema    workbenchOptionSchema `json:"option_schema"`
}

// #405/#36 decision, superseded: workbench run/recipe state used to stay
// local-disk-only, unlike ghidra/sandbox/github_analysis/revdeck's
// ES-mirror-with-local-fallback pattern (#403/#404) -- deliberately, not by
// omission. The reason was findOrCreateRun's idempotency check (same owner
// + idempotency key returns the existing run instead of submitting a
// duplicate analysis) needing read-your-own-write consistency an async,
// multi-minute-interval ES *mirror* could not give across dashboard
// instances: both could miss each other's very-recent run and each submit
// the same expensive Ghidra/sandbox job.
//
// That comment itself named the fix: "a genuinely synchronous store (not an
// async mirror) as the primary copy." This is that store (#405 follow-up):
// a run's own document ID *is* its idempotency key (workbenchIdempotency),
// so creating a run is one atomic Elasticsearch op_type=create -- a
// concurrent duplicate submission collides on the same ID and gets the
// existing run back (errESConflict -> docGet -> reused=true), the same
// guarantee the old in-process sync.Mutex gave, now enforced by
// Elasticsearch itself and therefore correct across multiple dashboard
// instances too, which the mutex-based version never was (confirmed by
// reading the old code: correctness there rested entirely on a single
// process's mutex around a directory scan, nothing made it safe across
// instances sharing the same w.root). Recipes get the analogous treatment:
// each revision is its own document (recipeID+":"+revision), also written
// via op_type=create, so two racing saves can't both claim the same
// revision number -- see reports_es.go for the general shape this follows.
type workbenchService struct {
	es *esClient
	// createMu serializes createWorkbenchRun's own check-then-submit-then-
	// persist sequence within one process -- ES's atomic op_type=create on
	// the run document (see createOrReuseRun, workbench_es.go) is what makes
	// idempotent dedup safe across *processes*, but submitWorkbenchChild's
	// side effects (creating a host-worker .request marker file) happen
	// BEFORE that create call, so two goroutines in this same process racing
	// an identical duplicate submission could otherwise both decide "not
	// found yet" and both submit child jobs before either persists. This
	// mutex closes that single-process window (the same guarantee the old
	// global w.mu gave, just narrowed to the one code path that actually
	// needs it -- reads and in-place run updates use per-document
	// compare-and-swap instead and no longer serialize behind each other).
	createMu sync.Mutex
}

func newWorkbenchService(es *esClient) *workbenchService {
	return &workbenchService{es: es}
}

func (w *workbenchService) configured() bool { return w != nil && w.es != nil }

func defaultWorkbenchOptions(id string) workbenchOptions {
	switch id {
	case "ghidra":
		return workbenchOptions{TimeoutSeconds: 7200, MaxQueueAgeSeconds: 1800, RetryLimit: 1}
	case "linux-sandbox", "windows-sandbox":
		return workbenchOptions{TimeoutSeconds: 1800, MaxQueueAgeSeconds: 900, RetryLimit: 1}
	default:
		return workbenchOptions{TimeoutSeconds: 60, MaxQueueAgeSeconds: 60, RetryLimit: 0}
	}
}

func validateWorkbenchOptions(id string, options *workbenchOptions) error {
	if options.TimeoutSeconds == 0 && options.MaxQueueAgeSeconds == 0 && options.RetryLimit == 0 {
		*options = defaultWorkbenchOptions(id)
	}
	if options.RetryLimit < 0 || options.RetryLimit > 3 {
		return errors.New("retry_limit must be between 0 and 3")
	}
	minTimeout, maxTimeout := 10, 86400
	if id == "deterministic" {
		minTimeout, maxTimeout = 5, 300
	}
	if options.TimeoutSeconds < minTimeout || options.TimeoutSeconds > maxTimeout {
		return fmt.Errorf("timeout_seconds must be between %d and %d", minTimeout, maxTimeout)
	}
	if options.MaxQueueAgeSeconds < 10 || options.MaxQueueAgeSeconds > 86400 {
		return errors.New("max_queue_age_seconds must be between 10 and 86400")
	}
	return nil
}

func validateWorkbenchSelections(selections []workbenchSelection) ([]workbenchSelection, error) {
	if len(selections) == 0 || len(selections) > 5 {
		return nil, errors.New("select between one and five analyzers")
	}
	allowed := map[string]bool{"deterministic": true, "ghidra": true, "linux-sandbox": true, "windows-sandbox": true, "windows-ghosts": true, "revdeck": true}
	seen := map[string]bool{}
	out := make([]workbenchSelection, 0, len(selections))
	for _, selection := range selections {
		selection.AnalyzerID = strings.TrimSpace(selection.AnalyzerID)
		if !allowed[selection.AnalyzerID] || seen[selection.AnalyzerID] {
			return nil, fmt.Errorf("unknown or duplicate analyzer %q", selection.AnalyzerID)
		}
		if err := validateWorkbenchOptions(selection.AnalyzerID, &selection.Options); err != nil {
			return nil, fmt.Errorf("%s: %w", selection.AnalyzerID, err)
		}
		seen[selection.AnalyzerID] = true
		out = append(out, selection)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AnalyzerID < out[j].AnalyzerID })
	return out, nil
}

func workbenchRegistry(classification payloadClassification) []workbenchAnalyzer {
	optionSchema := workbenchOptionSchema{TimeoutMinSeconds: 10, TimeoutMaxSeconds: 86400, QueueAgeMinSeconds: 10, QueueAgeMaxSeconds: 86400, RetryLimitMax: 3}
	localSchema := optionSchema
	localSchema.TimeoutMinSeconds, localSchema.TimeoutMaxSeconds = 5, 300
	codeLike := classification.Category == "executable" || classification.Category == "library" || classification.Category == "binary"
	ghidraConfigured := directoryUsable(ghidraRequestDir(), true) && directoryUsable(ghidraResultsDir(), false)
	ghidraHealthy := ghidraConfigured && !loadGhidraStatus().Stale
	revdeckConfigured := directoryUsable(revdeckRequestDir(), true) && directoryUsable(revdeckResultsDir(), false)
	linuxApplicable := classification.Dynamic && classification.Platform != "Windows"
	windowsApplicable := classification.Dynamic && classification.Platform == "Windows"
	linuxConfigured := directoryUsable(sandboxRequestDir(targetLinux), true) && directoryUsable(sandboxResultsDir(), false)
	windowsConfigured := directoryUsable(sandboxRequestDir(targetWindows), true) && directoryUsable(getenv("WINDOWS_SANDBOX_RESULTS_DIR", ""), false)
	// windowsApplicable, not its own ghostsApplicable: any payload the
	// isolated Windows route accepts is also compatible with the
	// WAN-permitted one -- the guests run the same golden-image base
	// (#326). This is a deliberate second, opt-in route to the same
	// payload class, not a payload-class distinction of its own, which is
	// why it needs the loud warning below rather than a quieter
	// "applicable" reason.
	ghostsConfigured := directoryUsable(sandboxRequestDir(targetGhosts), true) && directoryUsable(getenv("GHOSTS_SANDBOX_RESULTS_DIR", ""), false)
	items := []workbenchAnalyzer{
		{ID: "deterministic", DisplayName: "Deterministic local analysis", Description: "Hashes, type, entropy, strings, IOC extraction, YARA and bounded structural checks. The sample is never executed.", AcceptedKinds: []string{"all"}, Availability: "configured", Available: true, Applicable: true, Reason: "available for every captured payload", ResultLinkShape: "/payload-analysis/{sha256}", RequiredRole: "admin", Confirmation: "none", Concurrency: "cpu", LocalOnly: true, DefaultOptions: defaultWorkbenchOptions("deterministic"), OptionSchema: localSchema},
		{ID: "ghidra", DisplayName: "Ghidra headless", Description: "Disassembly plus deterministic statictools and the approved local advisory model slot.", AcceptedKinds: []string{"executable", "library", "binary"}, Availability: availabilityName(ghidraConfigured, ghidraHealthy), Available: ghidraHealthy, Applicable: codeLike, Reason: analyzerReason(codeLike, ghidraConfigured, ghidraHealthy, "payload does not contain a supported code image", "Ghidra spool is not configured", "Ghidra status is stale"), ResultLinkShape: "/ghidra/{sha256}", RequiredRole: "admin", Confirmation: "none", Concurrency: "shared-gpu", LocalOnly: true, GPU: true, DefaultOptions: defaultWorkbenchOptions("ghidra"), OptionSchema: optionSchema},
		{ID: "linux-sandbox", DisplayName: "Linux sandbox", Description: "Dynamic detonation in the isolated Linux KVM runner with its fixed network policy.", AcceptedKinds: []string{"linux", "cross-platform"}, Availability: availabilityName(linuxConfigured, linuxConfigured), Available: linuxConfigured, Applicable: linuxApplicable, Reason: analyzerReason(linuxApplicable, linuxConfigured, linuxConfigured, "payload is not compatible with the Linux detonation route", "Linux sandbox spool is not configured", "Linux sandbox is unavailable"), ResultLinkShape: "/sandbox/{job}", RequiredRole: "admin", Confirmation: "detonation", Concurrency: "linux-kvm", LocalOnly: true, Detonates: true, DefaultOptions: defaultWorkbenchOptions("linux-sandbox"), OptionSchema: optionSchema},
		{ID: "windows-sandbox", DisplayName: "Windows sandbox", Description: "Dynamic detonation in the isolated Windows KVM runner. The protected live VM cannot be selected here.", AcceptedKinds: []string{"windows"}, Availability: availabilityName(windowsConfigured, windowsConfigured), Available: windowsConfigured, Applicable: windowsApplicable, Reason: analyzerReason(windowsApplicable, windowsConfigured, windowsConfigured, "payload is not compatible with the Windows detonation route", "Windows sandbox spool is not configured", "Windows sandbox is unavailable"), ResultLinkShape: "/sandbox/{job}", RequiredRole: "admin", Confirmation: "detonation", Concurrency: "windows-kvm", LocalOnly: true, Detonates: true, DefaultOptions: defaultWorkbenchOptions("windows-sandbox"), OptionSchema: optionSchema},
		// #331/#300/#325: the one detonation route in this Workbench where
		// the payload gets REAL internet access. Every other route
		// (linux-sandbox, windows-sandbox) is air-gapped -- FakeNet/INetSim
		// answer everything, so C2 checkins and second-stage downloads go
		// nowhere real. This guest inverts that on purpose (GHOSTS'
		// realism), on its own dedicated network (virbr-ghosts) with a
		// host firewall policy blocking RFC1918/LAN and nothing else --
		// verified live in #325, not just configured. DisplayName and
		// Description are deliberately loud about this rather than reading
		// like just another sandbox option in the list, per #327.
		{ID: "windows-ghosts", DisplayName: "Windows sandbox (WAN-permitted, GHOSTS)", Description: "⚠ Real internet access. Dynamic detonation on a separate, WAN-permitted Windows guest with a GHOSTS-driven NPC persona -- unlike every other route here, this guest can reach real infrastructure (C2 checkins, second-stage downloads, exfiltration all go somewhere real, not FakeNet/INetSim). The host's LAN/RFC1918 ranges are firewalled off, but the internet is not. Only choose this for samples where real network behavior is the point.", AcceptedKinds: []string{"windows"}, Availability: availabilityName(ghostsConfigured, ghostsConfigured), Available: ghostsConfigured, Applicable: windowsApplicable, Reason: analyzerReason(windowsApplicable, ghostsConfigured, ghostsConfigured, "payload is not compatible with the Windows detonation route", "GHOSTS sandbox spool is not configured", "GHOSTS sandbox is unavailable"), ResultLinkShape: "/sandbox/{job}", RequiredRole: "admin", Confirmation: "detonation", Concurrency: "windows-ghosts-kvm", LocalOnly: true, Detonates: true, DefaultOptions: defaultWorkbenchOptions("windows-sandbox"), OptionSchema: optionSchema},
		// Standalone adapter (#78): its own submission path (drain_revdeck() in
		// ghidra-worker.py drains REVDECK_REQUEST_DIR independently of the
		// Ghidra spool) and its own result link (/revdeck/{sha256}), separate
		// from the "revdeck" field embedded inside a "ghidra" analyzer result
		// above -- a user can now select this without also running a full,
		// redundant Ghidra analysis just to get Rev\u00b7Deck's opinion. Configured
		// means the standalone spool directories exist, the same signal
		// ghidraConfigured uses; this Go process still cannot see
		// REVDECK_API_BASE (a host-worker-only setting), so a configured-but-
		// unset backend surfaces as a per-request failure result
		// (drain_revdeck() writes exit_status "error"), not as unavailable
		// here -- same gap ghidraConfigured/ghidraHealthy already accepts for
		// GHIDRA_API_BASE.
		{ID: "revdeck", DisplayName: "Rev\u00b7Deck / GhidrAssist", Description: "Rev\u00b7Deck's own bounded, autonomous tool-calling loop against the Ghidra REST service, run standalone rather than embedded inside a full Ghidra analysis.", AcceptedKinds: []string{"executable", "library"}, Availability: availabilityName(revdeckConfigured, revdeckConfigured), Available: revdeckConfigured, Applicable: codeLike, Reason: analyzerReason(codeLike, revdeckConfigured, revdeckConfigured, "payload does not contain a supported code image", "Rev\u00b7Deck spool is not configured", "Rev\u00b7Deck spool is not configured"), ResultLinkShape: "/revdeck/{sha256}", RequiredRole: "admin", Confirmation: "none", Concurrency: "shared-gpu", LocalOnly: true, GPU: true, DefaultOptions: defaultWorkbenchOptions("ghidra"), OptionSchema: optionSchema},
	}
	return items
}

func availabilityName(configured, healthy bool) string {
	if !configured {
		return "unconfigured"
	}
	if !healthy {
		return "unavailable"
	}
	return "configured"
}

func analyzerReason(applicable, configured, healthy bool, incompatible, unconfigured, unhealthy string) string {
	if !applicable {
		return incompatible
	}
	if !configured {
		return unconfigured
	}
	if !healthy {
		return unhealthy
	}
	return "ready"
}

func directoryUsable(path string, writable bool) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	if !writable {
		return true
	}
	return info.Mode().Perm()&0o222 != 0
}

func workbenchAnalyzerByID(items []workbenchAnalyzer, id string) (workbenchAnalyzer, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return workbenchAnalyzer{}, false
}

func randomWorkbenchID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(value[:]), nil
}

func workbenchIdempotency(hash, recipeID string, revision int, owner string, selections []workbenchSelection) string {
	body, _ := json.Marshal(selections)
	sum := sha256.Sum256([]byte(hash + "\x00" + recipeID + "\x00" + fmt.Sprint(revision) + "\x00" + owner + "\x00" + string(body)))
	return hex.EncodeToString(sum[:])
}

// validWorkbenchID checks a random, non-deterministic id (recipe ids: a
// fresh recipe still gets a random id via randomWorkbenchID -- only run ids
// became deterministic, see validWorkbenchRunID below).
func validWorkbenchID(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, prefix))
	return err == nil
}

// validWorkbenchRunID checks the deterministic "run_"+idempotencyKey shape
// (64 hex chars, a SHA-256 digest) -- see workbenchIdempotency and the
// package comment on workbenchService for why a run's id is its own
// idempotency key rather than a random value.
func validWorkbenchRunID(id string) bool {
	const prefix = "run_"
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, prefix))
	return err == nil
}

// Storage (recipes and runs, both Elasticsearch-backed) lives in
// workbench_es.go: listRecipes, saveRecipe, recipe, findRun,
// listRunsForOwnerAndHash/listRuns/listRunsForOwner, and the create/update
// primitives createOrReuseRunLocked-equivalent used by
// workbench_orchestrator.go.

func terminalWorkbenchState(state string) bool {
	switch state {
	case "completed", "skipped", "failed", "timed_out", "cancelled":
		return true
	default:
		return false
	}
}

func updateWorkbenchRunState(run *workbenchRun) {
	counts := map[string]int{}
	for _, child := range run.Children {
		counts[child.State]++
	}
	switch {
	case counts["queued"]+counts["claimed"]+counts["running"] > 0:
		run.State = "running"
	case counts["completed"] > 0 && counts["failed"]+counts["timed_out"]+counts["cancelled"]+counts["skipped"] > 0:
		run.State = "partial"
	case counts["completed"] > 0:
		run.State = "completed"
	case counts["timed_out"] > 0:
		run.State = "timed_out"
	case counts["failed"] > 0:
		run.State = "failed"
	case counts["cancelled"] > 0:
		run.State = "cancelled"
	default:
		run.State = "completed"
	}
	run.UpdatedAt = time.Now().UTC()
}
