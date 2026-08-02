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

func (s *store) serveWorkbenchIndex(w http.ResponseWriter, r *http.Request, tmpl *template.Template) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	data := s.payloadsData(payloadsFilter{})
	if len(data.Files) > 50 {
		data.Files = data.Files[:50]
	}
	renderPage(w, tmpl, "payload-workbench-index", &data)
}

func (s *store) workbenchResultsData(query, owner string) workbenchResultsPageData {
	data := workbenchResultsPageData{Generated: time.Now(), Query: strings.TrimSpace(query)}
	if s == nil || s.workbench == nil || !s.workbench.configured() {
		return data
	}
	needle := strings.ToLower(data.Query)
	for _, candidate := range s.workbench.listRunsForOwner(owner, workbenchMaxRuns) {
		run, err := s.getWorkbenchRun(candidate.ID, owner)
		if err != nil {
			continue
		}
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
	data := s.workbenchResultsData(r.URL.Query().Get("q"), identity.Subject)
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
		return authenticatedIdentity{Subject: "local-dashboard-admin", Username: "local-admin", Role: "admin", Generation: 1}, true
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
	data := workbenchPageData{
		Generated: time.Now(), SHA256: hash, Classification: classification,
		Analyzers: workbenchRegistry(classification), ModelStatus: loadWorkbenchModelStatus(),
		Correlation: s.correlateHash(hash),
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
			"route":               "/github-analysis",
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
