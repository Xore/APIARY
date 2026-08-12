package main

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type workbenchPageData struct {
	pageMeta
	Generated      time.Time
	SHA256         string
	Classification payloadClassification
	Analyzers      []workbenchAnalyzer
	ModelStatus    workbenchModelStatus
	// Correlation is #354's "ask the backend if this hash is known" advisory
	// -- shown before the operator picks analyzers and submits, since this
	// is the actual decision point a redundant run gets queued from. Never
	// disables or blocks analyzer selection either way.
	Correlation hashCorrelation
}

type workbenchResultsCounts struct {
	Total     int
	Active    int
	Completed int
	Partial   int
	Failed    int
}

type workbenchResultsPageData struct {
	pageMeta
	Generated time.Time
	Query     string
	Runs      []workbenchRun
	Counts    workbenchResultsCounts
}

// evidenceResultsPageData (#1139, #1180-adjacent) backs the merged
// /payload-workbench/results page: workbench runs, sandbox detonations,
// GitHub-analysis publications, and Ghidra static analyses each keep their
// own sub-page-data (own Query, own Rows/Runs), rendered as four tabs of
// one page rather than four separate routes. Sandbox, GitHub, and Ghidra
// are always list-mode here (Detail is nil) -- their own detail pages
// remain separate routes, untouched by this consolidation.
type evidenceResultsPageData struct {
	pageMeta
	Generated time.Time
	Workbench workbenchResultsPageData
	Sandbox   sandboxPageData
	GitHub    githubAnalysisPageData
	Ghidra    ghidraPageData
}

// SetNonce shadows pageMeta's own promoted method: renderPage only ever
// calls SetNonce once, against this page's own top-level pageMeta, but the
// GitHub and Ghidra panels it embeds (githubanalysisresultspanel/
// ghidraresultspanel, rendered here as {{template "githubanalysisresultspanel"
// .GitHub}}/{{template "ghidraresultspanel" .Ghidra}}) each carry their own,
// separate pageMeta -- and each needs a real nonce on its own warming-state
// inline reload script (#1156-follow-up, matching overview.html/
// payloads.html's own `<script nonce="{{.Nonce}}">` convention) when
// rendered inside this merged page, not just via the standalone (redirect-
// only) /github-analysis or /ghidra routes where .Nonce already resolves to
// this same top-level struct.
func (d *evidenceResultsPageData) SetNonce(n string) {
	d.pageMeta.SetNonce(n)
	d.GitHub.Nonce = n
	d.Ghidra.Nonce = n
}

func (s *store) workbenchResultsData(query, owner string) workbenchResultsPageData {
	data := workbenchResultsPageData{Generated: time.Now(), Query: strings.TrimSpace(query)}
	if s == nil || s.workbench == nil || !s.workbench.configured() {
		return data
	}
	needle := strings.ToLower(data.Query)
	// #1157: listRunsForOwner already did one docSearchAll and returned
	// fully-populated workbenchRun docs -- getWorkbenchRun used to be
	// called again per candidate anyway, and unlike its name suggests it
	// is not a cheap re-read: it's updateRun's full read-mutate-maybe-write
	// cycle, a fresh docGet (redundant with the search hit already in
	// hand) purely to get a current SeqNo/PrimaryTerm for an optimistic-
	// concurrency write. That's up to workbenchMaxRuns (500) sequential ES
	// round trips, synchronously, on every load of this listing -- the
	// actual reason it "loaded all results and only then finished," worse
	// than the whole-index-fetch antipattern #1153/#1156 already covered
	// elsewhere. reconcileWorkbenchRun itself is pure and already skips
	// its own expensive local-file reads for any run whose children are
	// all terminal (see its own #348 comment) -- call it directly against
	// the in-memory candidate instead, for display only. This trades away
	// this one code path's side effect of opportunistically persisting a
	// freshly-reconciled state back to ES; that persistence still happens
	// via getWorkbenchRun on the single-run detail page (and hp-workbench.js's
	// 4s poll of it while a run is active), which is the low-latency path
	// that comment was actually protecting -- nothing else reads
	// workbenchRunsIndex's raw persisted State outside this reconcile-on-
	// read layer (see workbench_es.go), so a stale-until-next-visit
	// persisted doc for a run nobody revisits is a display-only concern,
	// and this function's own output is never stale, since it reconciles
	// every candidate before returning it.
	for _, candidate := range s.workbench.listRunsForOwner(owner, workbenchMaxRuns) {
		run, _ := s.reconcileWorkbenchRun(candidate)
		if needle != "" && !workbenchRunMatches(run, needle) {
			continue
		}
		data.Runs = append(data.Runs, run)
		switch run.State {
		case "queued", "running":
			data.Counts.Active++
		case "completed":
			data.Counts.Completed++
		case "partial":
			data.Counts.Partial++
		default:
			data.Counts.Failed++
		}
	}
	data.Counts.Total = len(data.Runs)
	return data
}

// workbenchCardTarget is the results-list card's click-through destination
// and findings summary. #350: the card always linked to the recipe/
// orchestration page and showed a generic "N analyzers" line instead of
// what was actually found -- for the common case of one child analyzer per
// run (#351: the workbench now queues even a plain Linux sandbox run this
// way), jump straight to that child's own detailed findings page instead of
// the orchestration page, and surface its summary inline so the finding is
// visible without an extra click. A run with more than one child has no
// single "the" findings page, so it keeps linking to the orchestration
// page, which already lists every child's own summary and native result
// link once loaded.
type workbenchCardTarget struct {
	Href    string
	Summary string
}

func workbenchRunSummary(run workbenchRun) workbenchCardTarget {
	target := workbenchCardTarget{Href: "/payload-workbench/" + run.PayloadSHA256}
	if len(run.Children) == 1 {
		child := run.Children[0]
		if child.State == "completed" && child.ResultURL != "" {
			target.Href = child.ResultURL
		}
		target.Summary = child.Summary
		return target
	}
	for _, child := range run.Children {
		if child.Summary != "" {
			target.Summary = child.Summary
			break
		}
	}
	return target
}

func workbenchRunMatches(run workbenchRun, needle string) bool {
	values := []string{run.ID, run.PayloadSHA256, run.PayloadKind, run.RecipeName, run.State}
	for _, child := range run.Children {
		values = append(values, child.AnalyzerID, child.DisplayName, child.State, child.Summary, child.Reason)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func (s *store) serveWorkbenchResults(w http.ResponseWriter, r *http.Request, tmpl *template.Template) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := workbenchIdentity(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	data := evidenceResultsPageData{Generated: time.Now()}
	data.Workbench = s.workbenchResultsData(q.Get("q"), identity.Subject)
	data.Sandbox, _ = sandboxData("", q.Get("sandbox_q"))
	data.GitHub, _ = s.githubAnalysisData("", q.Get("github_q"))
	data.Ghidra, _ = s.ghidraData("", q.Get("ghidra_q"))
	renderPage(w, tmpl, "workbench-results", &data)
}

type workbenchRecipeRequest struct {
	ID           string               `json:"id,omitempty"`
	BaseRevision int                  `json:"base_revision,omitempty"`
	Name         string               `json:"name"`
	Description  string               `json:"description,omitempty"`
	Scope        string               `json:"scope"`
	Analyzers    []workbenchSelection `json:"analyzers"`
}

func workbenchIdentity(w http.ResponseWriter, r *http.Request) (authenticatedIdentity, bool) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("DASHBOARD_REQUIRE_ADMIN")), "true") {
		return authenticatedIdentity{Subject: "local-dashboard-admin", Username: "local-admin", Role: "admin"}, true
	}
	identity, err := resolveIdentity(r)
	if err != nil {
		if errors.Is(err, errIdentityUnavailable) {
			http.Error(w, "authorization service unavailable", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "administrator role required", http.StatusForbidden)
		}
		return authenticatedIdentity{}, false
	}
	if identity.Role != "admin" {
		http.Error(w, "administrator role required", http.StatusForbidden)
		return authenticatedIdentity{}, false
	}
	return identity, true
}

func decodeWorkbenchJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return false
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "request must contain one JSON document", http.StatusBadRequest)
		return false
	}
	return true
}

func writeWorkbenchJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *store) serveWorkbenchPage(w http.ResponseWriter, r *http.Request, tmpl *template.Template) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	hash := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/payload-workbench/")))
	if !hashName.MatchString(hash) {
		http.NotFound(w, r)
		return
	}
	path, err := s.payloadPath(hash)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	head, err := readPayloadHead(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	classification := classifyPayload(head)
	// This page deliberately only reads the payload's head, not the full
	// file (kept lightweight, #352/#364), so it has no cheaper way to know
	// the true content SHA-256 when hash itself is a Dionaea capture's
	// on-disk MD5 identity (#364). Local-store matching (Ghidra/sandbox/
	// GitHub-analysis, all keyed by true SHA-256) can therefore under-report
	// "known" for such a payload here -- the Elasticsearch side still
	// matches correctly either way, since hashQuery checks both hash
	// fields for whatever hash it's given. The scoped loaders below
	// (#1142) preserve this exact behavior: querying file.hash.sha256 for
	// an MD5 value simply finds nothing, same as the old whole-index-scan-
	// for-row.SHA256==hash did.
	var ghidraResults []ghidraResult
	if row, ok := loadGhidraResultByHash(esResultsClient, hash); ok {
		ghidraResults = []ghidraResult{row}
	}
	sandboxResults := loadSandboxResultsByHash(esResultsClient, hash)
	var githubResults []githubAnalysisResult
	if row, ok := loadGitHubAnalysisResultByHash(esResultsClient, hash); ok {
		githubResults = []githubAnalysisResult{row}
	}
	data := workbenchPageData{
		Generated: time.Now(), SHA256: hash, Classification: classification,
		Analyzers:   workbenchRegistry(classification),
		ModelStatus: loadWorkbenchModelStatus(),
		Correlation: s.correlateHash(hash, "", ghidraResults, sandboxResults, githubResults),
	}
	renderPage(w, tmpl, "payload-workbench", &data)
}

func (s *store) serveWorkbenchRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := workbenchIdentity(w, r); !ok {
		return
	}
	hash := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/payload-workbench/registry/")))
	if !hashName.MatchString(hash) {
		http.NotFound(w, r)
		return
	}
	path, err := s.payloadPath(hash)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	head, err := readPayloadHead(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeWorkbenchJSON(w, http.StatusOK, map[string]any{
		"payload_sha256": hash,
		"payload_kind":   classifyPayload(head).Code,
		"analyzers":      workbenchRegistry(classifyPayload(head)),
		"model_status":   loadWorkbenchModelStatus(),
		"external_publication": map[string]any{
			"included_in_run_all": false,
			"route":               "/payload-workbench/results#github",
			"reason":              "Captured material leaves the local trust boundary and retains its separate administrator confirmation and dry-run gates.",
		},
	})
}

func (s *store) serveWorkbenchRecipes(w http.ResponseWriter, r *http.Request) {
	identity, ok := workbenchIdentity(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeWorkbenchJSON(w, http.StatusOK, map[string]any{"recipes": s.workbench.listRecipes(identity.Subject)})
	case http.MethodPost:
		if !sameOriginRequest(r) {
			http.Error(w, "same-origin request required", http.StatusForbidden)
			return
		}
		var request workbenchRecipeRequest
		if !decodeWorkbenchJSON(w, r, &request) {
			return
		}
		recipe, err := s.workbench.saveRecipe(workbenchRecipe{ID: request.ID, Name: request.Name, Description: request.Description, Scope: request.Scope, Analyzers: request.Analyzers}, identity.Subject, request.BaseRevision)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errWorkbenchConflict) {
				status = http.StatusConflict
			} else if errors.Is(err, errWorkbenchNotFound) {
				status = http.StatusNotFound
			}
			s.auditWorkbench(identity, r, "workbench.recipe.save", "error")
			http.Error(w, err.Error(), status)
			return
		}
		s.auditWorkbench(identity, r, "workbench.recipe.save", "success")
		writeWorkbenchJSON(w, http.StatusCreated, recipe)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
	}
}

func (s *store) serveWorkbenchRuns(w http.ResponseWriter, r *http.Request) {
	identity, ok := workbenchIdentity(w, r)
	if !ok {
		return
	}
	if r.URL.Path == "/api/payload-workbench/runs" {
		switch r.Method {
		case http.MethodGet:
			hash := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sha256")))
			if hash != "" && !hashName.MatchString(hash) {
				http.Error(w, "invalid payload hash", http.StatusBadRequest)
				return
			}
			runs := s.workbench.listRuns(hash, identity.Subject)
			for index := range runs {
				runs[index], _ = s.reconcileWorkbenchRun(runs[index])
			}
			writeWorkbenchJSON(w, http.StatusOK, map[string]any{"runs": runs})
		case http.MethodPost:
			if !sameOriginRequest(r) {
				http.Error(w, "same-origin request required", http.StatusForbidden)
				return
			}
			var request workbenchRunRequest
			if !decodeWorkbenchJSON(w, r, &request) {
				return
			}
			run, reused, err := s.createWorkbenchRun(request, identity.Subject)
			if err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, errWorkbenchNotFound) {
					status = http.StatusNotFound
				}
				s.auditWorkbench(identity, r, "workbench.run.create", "error")
				http.Error(w, err.Error(), status)
				return
			}
			s.auditWorkbench(identity, r, "workbench.run.create", map[bool]string{true: "duplicate", false: "success"}[reused])
			status := http.StatusCreated
			if reused {
				status = http.StatusOK
			}
			writeWorkbenchJSON(w, status, map[string]any{"run": run, "reused": reused})
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		}
		return
	}
	s.serveWorkbenchRunByID(w, r, identity)
}

func (s *store) serveWorkbenchRunByID(w http.ResponseWriter, r *http.Request, identity authenticatedIdentity) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/payload-workbench/runs/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 1 && r.Method == http.MethodGet {
		run, err := s.getWorkbenchRun(parts[0], identity.Subject)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		writeWorkbenchJSON(w, http.StatusOK, run)
		return
	}
	if len(parts) != 4 || parts[1] != "children" || (parts[3] != "retry" && parts[3] != "cancel") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOriginRequest(r) {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	run, err := s.workbenchChildAction(parts[0], parts[2], parts[3], identity.Subject)
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, errWorkbenchNotFound) {
			status = http.StatusNotFound
		}
		s.auditWorkbench(identity, r, "workbench.child."+parts[3], "error")
		http.Error(w, err.Error(), status)
		return
	}
	s.auditWorkbench(identity, r, "workbench.child."+parts[3], "success")
	writeWorkbenchJSON(w, http.StatusOK, run)
}

func (s *store) auditWorkbench(identity authenticatedIdentity, r *http.Request, action, result string) {
	if s == nil || s.settings == nil || s.settings.audit == nil {
		return
	}
	s.settings.audit.log(auditEvent{
		Actor: identity.Subject, Username: identity.Username, RequestID: requestID(r), ClientIP: clientIP(r),
		Action: action, Fields: []string{"payload_sha256", "recipe_snapshot", "analyzer_id"}, Result: result,
	})
}
