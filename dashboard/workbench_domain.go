package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// #405/#36 decision: workbench run/recipe state stays local-disk-only,
// unlike ghidra/sandbox/github_analysis/revdeck's ES-mirror-with-
// local-fallback pattern (#403/#404) -- deliberately, not by omission.
//
// Every one of those four is a read-only mirror of results an EXTERNAL
// worker produces once and never revises; the dashboard only ever reads
// them, so a few minutes of import lag just means a page is briefly stale,
// never wrong. A workbench run is the opposite shape: this service is the
// SOLE writer, mutates a run repeatedly over its lifecycle (queued ->
// running -> completed/failed via persistRunLocked), and — critically —
// findOrCreateRun's idempotency check (same owner + idempotency key returns
// the existing run instead of submitting a duplicate analysis) depends on
// seeing its own immediately-preceding write. An async ES mirror on a
// multi-minute import interval cannot give two dashboard instances that
// guarantee: both could miss each other's very-recent run and each submit
// the same expensive Ghidra/sandbox job.
//
// Real multi-instance support for this specific state needs either a
// shared filesystem for w.root (outside this service's control) or a
// genuinely synchronous store (not an async mirror) as the primary copy —
// both bigger, riskier changes than the read-only migrations, and neither
// is warranted by anything reported against this stack so far. Revisit if
// that changes; don't silently re-decide this by adding an ES read path
// here later without re-reading this comment first.
type workbenchService struct {
	mu   sync.Mutex
	root string
}

func newWorkbenchService(root string) *workbenchService {
	return &workbenchService{root: strings.TrimSpace(root)}
}

func (w *workbenchService) configured() bool { return w != nil && w.root != "" }

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

func (w *workbenchService) recipesPath() string { return filepath.Join(w.root, "recipes.json") }
func (w *workbenchService) runsDir() string     { return filepath.Join(w.root, "runs") }

func readBoundedJSON(path string, value any) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("workbench document is not a bounded regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, value)
}

func (w *workbenchService) loadRecipesLocked() []workbenchRecipe {
	var recipes []workbenchRecipe
	if !w.configured() || readBoundedJSON(w.recipesPath(), &recipes) != nil {
		return nil
	}
	valid := recipes[:0]
	for _, recipe := range recipes {
		if recipe.SchemaVersion == workbenchSchemaVersion && validWorkbenchID(recipe.ID, "recipe_") && recipe.Revision > 0 && recipe.Owner != "" {
			valid = append(valid, recipe)
		}
	}
	return valid
}

func validWorkbenchID(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, prefix))
	return err == nil
}

func (w *workbenchService) listRecipes(owner string) []workbenchRecipe {
	w.mu.Lock()
	defer w.mu.Unlock()
	all := w.loadRecipesLocked()
	visible := make([]workbenchRecipe, 0, len(all))
	for _, recipe := range all {
		if recipe.Scope == "shared" || recipe.Owner == owner {
			visible = append(visible, recipe)
		}
	}
	sort.Slice(visible, func(i, j int) bool {
		if visible[i].CreatedAt.Equal(visible[j].CreatedAt) {
			return visible[i].Revision > visible[j].Revision
		}
		return visible[i].CreatedAt.After(visible[j].CreatedAt)
	})
	return visible
}

func (w *workbenchService) saveRecipe(input workbenchRecipe, owner string, baseRevision int) (workbenchRecipe, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.configured() {
		return workbenchRecipe{}, errors.New("workbench persistence is not configured")
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if len(input.Name) < 2 || len(input.Name) > 80 || len(input.Description) > 400 {
		return workbenchRecipe{}, errors.New("recipe name or description is outside the allowed length")
	}
	if input.Scope != "private" && input.Scope != "shared" {
		return workbenchRecipe{}, errors.New("recipe scope must be private or shared")
	}
	selections, err := validateWorkbenchSelections(input.Analyzers)
	if err != nil {
		return workbenchRecipe{}, err
	}
	recipes := w.loadRecipesLocked()
	if len(recipes) >= workbenchMaxRecipes {
		return workbenchRecipe{}, errors.New("recipe limit reached")
	}
	if input.ID == "" {
		input.ID, err = randomWorkbenchID("recipe")
		input.Revision = 1
	} else {
		if !validWorkbenchID(input.ID, "recipe_") {
			return workbenchRecipe{}, errors.New("invalid recipe id")
		}
		latest := 0
		for _, recipe := range recipes {
			if recipe.ID == input.ID {
				if recipe.Owner != owner {
					return workbenchRecipe{}, errWorkbenchNotFound
				}
				latest = max(latest, recipe.Revision)
			}
		}
		if latest == 0 {
			return workbenchRecipe{}, errWorkbenchNotFound
		}
		if baseRevision != latest {
			return workbenchRecipe{}, errWorkbenchConflict
		}
		input.Revision = latest + 1
	}
	if err != nil {
		return workbenchRecipe{}, err
	}
	input.SchemaVersion = workbenchSchemaVersion
	input.Owner = owner
	input.CreatedAt = time.Now().UTC()
	input.Analyzers = selections
	recipes = append(recipes, input)
	body, err := json.MarshalIndent(recipes, "", "  ")
	if err != nil {
		return workbenchRecipe{}, err
	}
	if err := atomicWriteFile(w.recipesPath(), body); err != nil {
		return workbenchRecipe{}, err
	}
	return input, nil
}

func (w *workbenchService) recipe(id string, revision int, owner string) (workbenchRecipe, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, recipe := range w.loadRecipesLocked() {
		if recipe.ID == id && recipe.Revision == revision && (recipe.Scope == "shared" || recipe.Owner == owner) {
			return recipe, nil
		}
	}
	return workbenchRecipe{}, errWorkbenchNotFound
}

func (w *workbenchService) loadRunsLocked() []workbenchRun {
	entries, err := os.ReadDir(w.runsDir())
	if err != nil {
		return nil
	}
	runs := make([]workbenchRun, 0, min(len(entries), workbenchMaxRuns))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || len(runs) >= workbenchMaxRuns {
			continue
		}
		var run workbenchRun
		if readBoundedJSON(filepath.Join(w.runsDir(), entry.Name()), &run) == nil && run.SchemaVersion == workbenchSchemaVersion && validWorkbenchID(run.ID, "run_") {
			runs = append(runs, run)
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.After(runs[j].CreatedAt) })
	return runs
}

func (w *workbenchService) persistRunLocked(run workbenchRun) error {
	body, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(w.runsDir(), run.ID+".json"), body)
}

func (w *workbenchService) findRun(id, owner string) (workbenchRun, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.loadRunLocked(id, owner)
}

func (w *workbenchService) loadRunLocked(id, owner string) (workbenchRun, error) {
	if !validWorkbenchID(id, "run_") {
		return workbenchRun{}, errWorkbenchNotFound
	}
	var run workbenchRun
	if readBoundedJSON(filepath.Join(w.runsDir(), id+".json"), &run) != nil || run.ID != id || run.Owner != owner {
		return workbenchRun{}, errWorkbenchNotFound
	}
	return run, nil
}

func (w *workbenchService) listRuns(hash, owner string) []workbenchRun {
	return w.listRunsForOwnerAndHash(owner, hash, 25)
}

func (w *workbenchService) listRunsForOwner(owner string, limit int) []workbenchRun {
	return w.listRunsForOwnerAndHash(owner, "", limit)
}

func (w *workbenchService) listRunsForOwnerAndHash(owner, hash string, limit int) []workbenchRun {
	w.mu.Lock()
	defer w.mu.Unlock()
	if limit <= 0 || limit > workbenchMaxRuns {
		limit = workbenchMaxRuns
	}
	var visible []workbenchRun
	for _, run := range w.loadRunsLocked() {
		if run.Owner == owner && (hash == "" || run.PayloadSHA256 == hash) {
			visible = append(visible, run)
			if len(visible) == limit {
				break
			}
		}
	}
	return visible
}

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
