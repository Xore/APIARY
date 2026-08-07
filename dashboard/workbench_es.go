package main

// workbench_es.go — #405 follow-up: Payload Workbench recipe/run storage,
// Elasticsearch-backed. See workbench_domain.go's package comment on
// workbenchService for the full design rationale (why this was previously
// local-disk-only, and why a run's document ID being its own idempotency
// key makes atomic op_type=create the right primitive here). No local
// fallback: every method below returns an error when es is nil, same
// posture as #494/#483/#475.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const workbenchRunsIndex = "dashboard-workbench-runs-v1"
const workbenchRecipesIndex = "dashboard-workbench-recipes-v1"

// workbenchUpdateRetries bounds updateRun's read-modify-write retry loop
// against a losing compare-and-swap -- the same shape and reasoning as
// alertManager's alertWriteRetries (alerts.go).
const workbenchUpdateRetries = 5

func workbenchRecipeDocID(id string, revision int) string {
	return id + ":" + strconv.Itoa(revision)
}

// listRecipes returns every recipe visible to owner (their own private
// recipes plus every shared one), newest-then-highest-revision first.
func (w *workbenchService) listRecipes(owner string) []workbenchRecipe {
	if !w.configured() {
		return nil
	}
	hits, err := w.es.docSearchAll(workbenchRecipesIndex, 10000)
	if err != nil {
		return nil
	}
	visible := make([]workbenchRecipe, 0, len(hits))
	for _, hit := range hits {
		var recipe workbenchRecipe
		if json.Unmarshal(hit.Source, &recipe) != nil {
			continue
		}
		if recipe.SchemaVersion != workbenchSchemaVersion || !validWorkbenchID(recipe.ID, "recipe_") || recipe.Revision <= 0 || recipe.Owner == "" {
			continue
		}
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

// saveRecipe creates a new recipe (input.ID == "") or a new revision of an
// existing one, enforcing the same optimistic-concurrency contract the
// local-file version did (a stale baseRevision returns errWorkbenchConflict
// rather than silently overwriting a concurrent save) -- except the
// compare-and-swap is now Elasticsearch's own op_type=create on the
// revision-numbered document (workbenchRecipeDocID), not a whole-file
// rewrite guarded by a mutex.
func (w *workbenchService) saveRecipe(input workbenchRecipe, owner string, baseRevision int) (workbenchRecipe, error) {
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
	hits, err := w.es.docSearchAll(workbenchRecipesIndex, 10000)
	if err != nil {
		return workbenchRecipe{}, err
	}
	if input.ID == "" {
		// #883: workbenchMaxRecipes bounds how many distinct recipes exist,
		// not how many revision documents they've accumulated -- every save
		// (including an edit to an already-existing recipe) writes a new
		// workbenchRecipeDocID(id, revision) document that's never pruned,
		// so counting raw hits here let ordinary editing activity alone
		// permanently exhaust the cap. Only a genuinely new recipe ID needs
		// to check it; an edit of an existing recipe is handled below.
		ids := make(map[string]bool, len(hits))
		for _, hit := range hits {
			var recipe workbenchRecipe
			if json.Unmarshal(hit.Source, &recipe) != nil {
				continue
			}
			ids[recipe.ID] = true
		}
		if len(ids) >= workbenchMaxRecipes {
			return workbenchRecipe{}, errors.New("recipe limit reached")
		}
		input.ID, err = randomWorkbenchID("recipe")
		if err != nil {
			return workbenchRecipe{}, err
		}
		input.Revision = 1
	} else {
		if !validWorkbenchID(input.ID, "recipe_") {
			return workbenchRecipe{}, errors.New("invalid recipe id")
		}
		latest := 0
		for _, hit := range hits {
			var recipe workbenchRecipe
			if json.Unmarshal(hit.Source, &recipe) != nil || recipe.ID != input.ID {
				continue
			}
			if recipe.Owner != owner {
				return workbenchRecipe{}, errWorkbenchNotFound
			}
			latest = max(latest, recipe.Revision)
		}
		if latest == 0 {
			return workbenchRecipe{}, errWorkbenchNotFound
		}
		if baseRevision != latest {
			return workbenchRecipe{}, errWorkbenchConflict
		}
		input.Revision = latest + 1
	}
	input.SchemaVersion = workbenchSchemaVersion
	input.Owner = owner
	input.CreatedAt = time.Now().UTC()
	input.Analyzers = selections
	body, err := json.Marshal(input)
	if err != nil {
		return workbenchRecipe{}, err
	}
	// create=true: this exact revision number is written exactly once --
	// two racing saves both computing "latest+1" from the same read collide
	// here instead of one silently clobbering the other.
	if err := w.es.docIndex(workbenchRecipesIndex, workbenchRecipeDocID(input.ID, input.Revision), body, true, 0, 0); err != nil {
		if errors.Is(err, errESConflict) {
			return workbenchRecipe{}, errWorkbenchConflict
		}
		return workbenchRecipe{}, err
	}
	return input, nil
}

func (w *workbenchService) recipe(id string, revision int, owner string) (workbenchRecipe, error) {
	if !w.configured() {
		return workbenchRecipe{}, errWorkbenchNotFound
	}
	hit, found, err := w.es.docGet(workbenchRecipesIndex, workbenchRecipeDocID(id, revision))
	if err != nil || !found {
		return workbenchRecipe{}, errWorkbenchNotFound
	}
	var recipe workbenchRecipe
	if json.Unmarshal(hit.Source, &recipe) != nil {
		return workbenchRecipe{}, errWorkbenchNotFound
	}
	if recipe.Scope != "shared" && recipe.Owner != owner {
		return workbenchRecipe{}, errWorkbenchNotFound
	}
	return recipe, nil
}

// findRun fetches one run by id, scoped to owner -- the same cross-owner
// isolation the local-file version enforced (a run belonging to a different
// owner reports errWorkbenchNotFound, not a permission error, so its
// existence isn't leaked).
func (w *workbenchService) findRun(id, owner string) (workbenchRun, error) {
	if !w.configured() || !validWorkbenchRunID(id) {
		return workbenchRun{}, errWorkbenchNotFound
	}
	hit, found, err := w.es.docGet(workbenchRunsIndex, id)
	if err != nil || !found {
		return workbenchRun{}, errWorkbenchNotFound
	}
	var run workbenchRun
	if json.Unmarshal(hit.Source, &run) != nil || run.ID != id || run.Owner != owner {
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
	if !w.configured() {
		return nil
	}
	if limit <= 0 || limit > workbenchMaxRuns {
		limit = workbenchMaxRuns
	}
	hits, err := w.es.docSearchAll(workbenchRunsIndex, 10000)
	if err != nil {
		return nil
	}
	all := make([]workbenchRun, 0, len(hits))
	for _, hit := range hits {
		var run workbenchRun
		if json.Unmarshal(hit.Source, &run) == nil && run.SchemaVersion == workbenchSchemaVersion && validWorkbenchRunID(run.ID) {
			all = append(all, run)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	visible := make([]workbenchRun, 0, limit)
	for _, run := range all {
		if run.Owner == owner && (hash == "" || run.PayloadSHA256 == hash) {
			visible = append(visible, run)
			if len(visible) == limit {
				break
			}
		}
	}
	return visible
}

// countRuns backs createWorkbenchRun's retention check (reject a new run
// past workbenchMaxRuns rather than silently pruning old ones -- an
// operator archiving/investigating old runs must not have them vanish
// underneath them, unlike #475's generated-report retention which is
// disposable by design).
func (w *workbenchService) countRuns() (int, error) {
	if !w.configured() {
		return 0, errors.New("workbench persistence is not configured")
	}
	hits, err := w.es.docSearchAll(workbenchRunsIndex, 10000)
	if err != nil {
		return 0, err
	}
	return len(hits), nil
}

// createOrReuseRun is the atomic half of createWorkbenchRun: run.ID is
// already the request's own idempotency key (see workbenchIdempotency), so
// op_type=create either wins (a genuinely new run) or collides with an
// identical prior submission -- in which case the existing run is fetched
// and returned as reused=true, the same "duplicate submission returns the
// original" contract the old in-process mutex enforced, now safe across
// dashboard instances too since Elasticsearch's own create semantics are
// what's doing the compare-and-swap, not a process-local lock.
func (w *workbenchService) createOrReuseRun(run workbenchRun) (workbenchRun, bool, error) {
	if !w.configured() {
		return workbenchRun{}, false, errors.New("analysis workbench persistence is not configured")
	}
	body, err := json.Marshal(run)
	if err != nil {
		return workbenchRun{}, false, err
	}
	err = w.es.docIndex(workbenchRunsIndex, run.ID, body, true, 0, 0)
	if err == nil {
		return run, false, nil
	}
	if !errors.Is(err, errESConflict) {
		return workbenchRun{}, false, err
	}
	hit, found, getErr := w.es.docGet(workbenchRunsIndex, run.ID)
	if getErr != nil || !found {
		return workbenchRun{}, false, fmt.Errorf("workbench run creation conflict could not be resolved: %w", getErr)
	}
	var existing workbenchRun
	if json.Unmarshal(hit.Source, &existing) != nil {
		return workbenchRun{}, false, errors.New("existing workbench run is corrupt")
	}
	return existing, true, nil
}

// updateRun is the read-modify-write primitive every in-place run mutation
// (reconciliation on read, a child cancel/retry action) goes through:
// fetch, let mutate decide the new state and whether anything actually
// changed, and persist only if so -- preserving the local-file version's
// "skip the write entirely when reconciliation found nothing new" behavior
// (TestReconcileWorkbenchRunSkipsWorkOnceEveryChildIsTerminal), just via a
// conditional Elasticsearch write instead of comparing file mtimes. mutate
// returning an error aborts without writing and propagates that error
// directly (a child action's own validation failure -- "only a queued child
// can be cancelled" and friends -- not a storage problem). A lost
// compare-and-swap race retries against a fresh read, same shape as
// alertManager's own retry loop.
func (w *workbenchService) updateRun(id, owner string, mutate func(*workbenchRun) (bool, error)) (workbenchRun, error) {
	if !w.configured() {
		return workbenchRun{}, errors.New("workbench persistence is not configured")
	}
	if !validWorkbenchRunID(id) {
		return workbenchRun{}, errWorkbenchNotFound
	}
	for attempt := 0; attempt < workbenchUpdateRetries; attempt++ {
		hit, found, err := w.es.docGet(workbenchRunsIndex, id)
		if err != nil {
			return workbenchRun{}, err
		}
		if !found {
			return workbenchRun{}, errWorkbenchNotFound
		}
		var run workbenchRun
		if json.Unmarshal(hit.Source, &run) != nil || run.ID != id || run.Owner != owner {
			return workbenchRun{}, errWorkbenchNotFound
		}
		changed, mutateErr := mutate(&run)
		if mutateErr != nil {
			return workbenchRun{}, mutateErr
		}
		if !changed {
			return run, nil
		}
		body, err := json.Marshal(run)
		if err != nil {
			return workbenchRun{}, err
		}
		err = w.es.docIndex(workbenchRunsIndex, id, body, false, hit.SeqNo, hit.PrimaryTerm)
		if err == nil {
			return run, nil
		}
		if !errors.Is(err, errESConflict) {
			return workbenchRun{}, err
		}
		// Lost a race against a concurrent update (another reconcile-on-read,
		// or a child action) -- retry from a fresh read.
	}
	return workbenchRun{}, errors.New("workbench run update conflict; retry")
}
