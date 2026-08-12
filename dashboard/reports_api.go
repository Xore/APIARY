package main

// reports_api.go — the administrator endpoints of the Reports studio (R2):
//
//	GET    /api/reports/templates                  template and element catalog
//	GET    /api/reports/payload-options            #653: payload picker search results
//	GET    /api/reports/definitions                saved definitions (+ ETag)
//	POST   /api/reports/definitions                create (server-assigned id)
//	GET    /api/reports/definitions/{id}           one definition
//	PATCH  /api/reports/definitions/{id}           full-field replace
//	DELETE /api/reports/definitions/{id}
//	POST   /api/reports/definitions/{id}/generate  render now and store the PDF
//	POST   /api/reports/payloads/{hash}/generate   #474: one-click payload PDF, no saved definition
//	GET    /api/reports/generated                  generated history (newest first)
//	GET    /api/reports/generated/{id}/pdf         inline view; ?download=1 attachment
//	DELETE /api/reports/generated/{id}
//
// Every endpoint requires a live-introspected administrator identity through
// the shared guard (same-origin and per-subject write limits on mutations).
// Definition mutations accept an optional If-Match for optimistic
// concurrency, exactly like the settings configuration API. This is the only
// surface that produces PDFs: the per-page export buttons and the legacy
// /export/report.pdf endpoint were removed in R2.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxReportBody bounds a definition payload; definitions are small documents.
const maxReportBody = 32 << 10

// reportStudioGuard enforces administrator access and resolves the store.
func (s *store) reportStudioGuard(w http.ResponseWriter, r *http.Request, write bool) bool {
	if s == nil || s.reports == nil {
		http.Error(w, "reports studio unavailable", http.StatusServiceUnavailable)
		return false
	}
	_, ok := s.adminSettingsIdentity(w, r, write)
	return ok
}

func writeReportsJSON(w http.ResponseWriter, etag string, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeReportStoreError maps store failures onto the settings API contract's
// status codes (conflicts, validation, missing records, read-only stores stay
// distinguishable without parsing text) -- reports_store.go returns the same
// sentinel errors settings_store.go does. Not a passthrough to
// writePreferenceError: that hardcoded "preferences changed concurrently;
// reload and retry" for errStaleRevision, which is the wrong subsystem's name
// on a report-definition conflict (#211) and reads as evidence of a bug in
// the wrong place entirely.
func writeReportStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errStaleRevision):
		http.Error(w, "this report definition changed concurrently; reload and retry", http.StatusConflict)
	case errors.Is(err, errSettingsValidation):
		// Validation messages name fields and bounds, never values.
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	case errors.Is(err, errUnknownRecord):
		http.Error(w, "no reports record yet; reload the page first", http.StatusNotFound)
	case errors.Is(err, errStoreReadOnly):
		http.Error(w, "reports store is read-only; contact an administrator", http.StatusServiceUnavailable)
	case errors.Is(err, errReportsStorageUnavailable):
		http.Error(w, "generated-report storage is unavailable; Elasticsearch is not configured", http.StatusServiceUnavailable)
	default:
		http.Error(w, "report definition could not be saved", http.StatusInternalServerError)
	}
}

func (s *store) serveReportTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if !s.reportStudioGuard(w, r, false) {
		return
	}
	var overrides map[string]reportPresetOverride
	if s.settings != nil {
		cfg, _ := s.settings.config.Get()
		overrides = cfg.Presentation.ReportPresets
	}
	writeReportsJSON(w, "", http.StatusOK, map[string]any{
		"templates": reportTemplateCatalogWithOverrides(overrides),
		"elements":  reportElementCatalog,
		"windows":   []string{"1h", "6h", "24h", "7d", "30d"},
		"themes":    []string{"dark", "light"},
	})
}

// reportPayloadOptionsLimit bounds /api/reports/payload-options the same way
// every other bounded list on this dashboard is capped (25-30 rows) -- a
// picker narrows a search, it does not browse the full inventory.
const reportPayloadOptionsLimit = 30

// reportPayloadOption is one row of Report Studio's payload picker (#653):
// enough to identify a captured payload plus, per the issue's explicit ask,
// which analysis sources already exist for it (correlateHash, the same
// cross-source check payload-workbench already uses), so an operator can
// tell at a glance which payloads have enough analysis depth to make a
// meaningful report before picking one.
type reportPayloadOption struct {
	Hash     string `json:"hash"`
	Kind     string `json:"kind"`
	SizeH    string `json:"size_h"`
	MtimeUTC string `json:"mtime_utc"`
	Sandbox  bool   `json:"sandbox"`
	Ghidra   bool   `json:"ghidra"`
	GitHub   bool   `json:"github"`
}

// serveReportPayloadOptions backs the payload template's picker in the
// designer (#653) -- the payload template requires scope.hash
// (reports_store.go's validateDefinition), and until this endpoint existed
// there was no way to search captured payloads and see what to set it to
// from inside Report Studio at all; the only working path was the separate
// /api/reports/payloads/{hash}/generate shortcut reached from an individual
// payload's own analysis page, which bypasses the designer entirely.
func (s *store) serveReportPayloadOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if !s.reportStudioGuard(w, r, false) {
		return
	}
	// payloadsData, not a direct disk scan: this dashboard reads payload
	// inventory through Elasticsearch only (the same rule #403 established
	// for sensor/event data) -- payload-inventory-worker owns the disk walk
	// itself (#1201/#1223), refreshPayloadCacheAsync just reads its output
	// back, never called directly from a request handler.
	data := s.payloadsData(payloadsFilter{Hash: r.URL.Query().Get("q")})
	files := data.Files
	if len(files) > reportPayloadOptionsLimit {
		files = files[:reportPayloadOptionsLimit]
	}
	// Loaded once for the whole search, not once per file below: see
	// correlateHash's own doc comment -- each of these fetches up to 10000
	// documents from ES regardless of hash, so calling it inside this loop
	// (as this used to) meant up to reportPayloadOptionsLimit separate
	// fetches per source for one search-as-you-type keystroke.
	ghidraResults, sandboxResults, githubResults := loadGhidraResults(), loadSandboxResults(), loadGitHubAnalysisResults()
	options := make([]reportPayloadOption, 0, len(files))
	for _, file := range files {
		correlation := s.correlateHash(file.Hash, "", ghidraResults, sandboxResults, githubResults)
		options = append(options, reportPayloadOption{
			Hash:     file.Hash,
			Kind:     file.Kind,
			SizeH:    file.SizeH,
			MtimeUTC: file.MtimeUTC,
			Sandbox:  len(correlation.Sandbox) > 0,
			Ghidra:   correlation.Ghidra != nil,
			GitHub:   correlation.GitHub != nil,
		})
	}
	writeReportsJSON(w, "", http.StatusOK, map[string]any{"payloads": options})
}

func (s *store) serveReportDefinitions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.reportStudioGuard(w, r, false) {
			return
		}
		doc, etag := s.reports.document()
		writeReportsJSON(w, etag, http.StatusOK, map[string]any{"definitions": doc.Definitions})
	case http.MethodPost:
		s.createReportDefinition(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
	}
}

func (s *store) createReportDefinition(w http.ResponseWriter, r *http.Request) {
	if !s.reportStudioGuard(w, r, true) {
		return
	}
	def, ok := decodeReportDefinition(w, r)
	if !ok {
		return
	}
	if def.ID != "" {
		http.Error(w, "id is assigned by the server; omit it when creating a definition", http.StatusBadRequest)
		return
	}
	created, etag, err := s.reports.putDefinition(r.Header.Get("If-Match"), def)
	if err != nil {
		writeReportStoreError(w, err)
		return
	}
	writeReportsJSON(w, etag, http.StatusCreated, map[string]any{"definition": created})
}

func decodeReportDefinition(w http.ResponseWriter, r *http.Request) (reportDefinition, bool) {
	if contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))); !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "Content-Type: application/json required", http.StatusUnsupportedMediaType)
		return reportDefinition{}, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReportBody))
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return reportDefinition{}, false
	}
	var def reportDefinition
	if !strictDecode(body, &def) {
		http.Error(w, "invalid or unknown report definition fields", http.StatusBadRequest)
		return reportDefinition{}, false
	}
	return def, true
}

func (s *store) serveReportDefinitionByID(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/reports/definitions/")
	id, action, _ := strings.Cut(tail, "/")
	if !validReportID(id, "rep_") {
		http.NotFound(w, r)
		return
	}
	switch action {
	case "":
		switch r.Method {
		case http.MethodGet:
			if !s.reportStudioGuard(w, r, false) {
				return
			}
			def, ok := s.reports.definition(id)
			if !ok {
				http.NotFound(w, r)
				return
			}
			writeReportsJSON(w, "", http.StatusOK, map[string]any{"definition": def})
		case http.MethodPatch:
			s.replaceReportDefinition(w, r, id)
		case http.MethodDelete:
			s.removeReportDefinition(w, r, id)
		default:
			w.Header().Set("Allow", "GET, PATCH, DELETE")
			http.Error(w, "GET, PATCH, or DELETE required", http.StatusMethodNotAllowed)
		}
	case "generate":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		s.generateReport(w, r, id, "manual")
	default:
		http.NotFound(w, r)
	}
}

func (s *store) replaceReportDefinition(w http.ResponseWriter, r *http.Request, id string) {
	if !s.reportStudioGuard(w, r, true) {
		return
	}
	def, ok := decodeReportDefinition(w, r)
	if !ok {
		return
	}
	if def.ID != "" && def.ID != id {
		http.Error(w, "id in the body must match the path or be omitted", http.StatusBadRequest)
		return
	}
	def.ID = id
	updated, etag, err := s.reports.putDefinition(r.Header.Get("If-Match"), def)
	if err != nil {
		writeReportStoreError(w, err)
		return
	}
	writeReportsJSON(w, etag, http.StatusOK, map[string]any{"definition": updated})
}

func (s *store) removeReportDefinition(w http.ResponseWriter, r *http.Request, id string) {
	if !s.reportStudioGuard(w, r, true) {
		return
	}
	if err := s.reports.deleteDefinition(r.Header.Get("If-Match"), id); err != nil {
		writeReportStoreError(w, err)
		return
	}
	_, etag := s.reports.document()
	writeReportsJSON(w, etag, http.StatusOK, map[string]any{"deleted": id})
}

// generateReport renders a definition immediately and records the PDF. The
// scheduled path (R4) shares this renderer with origin "schedule".
func (s *store) generateReport(w http.ResponseWriter, r *http.Request, id, origin string) {
	if !s.reportStudioGuard(w, r, true) {
		return
	}
	meta, etag, err := s.renderDefinitionToStored(id, origin)
	if err != nil {
		writeReportStoreError(w, err)
		return
	}
	writeReportsJSON(w, etag, http.StatusCreated, map[string]any{"generated": meta})
}

// serveGeneratePayloadReport backs #474's payload-page "Generate PDF"
// button: POST /api/reports/payloads/{hash}/generate. Synchronous, like
// generateReport above -- report_pdf.go's writer is an in-process, hand-
// rolled PDF emitter (no external process to poll), so there is no
// background job to report progress on; the caller's own fetch await is the
// only "progress indicator" needed.
func (s *store) serveGeneratePayloadReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !s.reportStudioGuard(w, r, true) {
		return
	}
	hash := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/reports/payloads/"), "/generate")
	meta, etag, err := s.generatePayloadReport(hash, "manual")
	if err != nil {
		writeReportStoreError(w, err)
		return
	}
	writeReportsJSON(w, etag, http.StatusCreated, map[string]any{"generated": meta})
}

// renderDefinitionToStored is the generation pipeline shared by the manual
// API and the scheduler: resolve the definition, render the PDF from live
// telemetry (or the referenced sandbox/payload artifact), and persist it.
func (s *store) renderDefinitionToStored(id, origin string) (generatedReport, string, error) {
	// #787: definitionFresh, not definition -- generating right after saving
	// a definition is the normal designer flow, and the two requests can
	// land on different dashboard replicas. See GetFresh's own comment.
	def, ok := s.reports.definitionFresh(id)
	if !ok {
		return generatedReport{}, "", fmt.Errorf("%w: no report definition with this id", errUnknownRecord)
	}
	pdf, title, err := s.renderDefinitionPDFBytes(def)
	if err != nil {
		return generatedReport{}, "", err
	}
	return s.reports.addGenerated(generatedReport{
		DefinitionID: def.ID,
		Name:         def.Name,
		Template:     def.Template,
		Theme:        def.Theme,
		Title:        title,
		Origin:       origin,
	}, pdf)
}

// renderDefinitionPDFBytes is renderDefinitionToStored's rendering step,
// pulled out on its own so #474's payload report can share it against an
// ephemeral, never-persisted definition (generatePayloadReport below)
// instead of requiring a saved definition id like the designer flow does.
func (s *store) renderDefinitionPDFBytes(def reportDefinition) ([]byte, string, error) {
	template, _ := reportTemplateByID(def.Template)
	title := strings.TrimSpace(def.Branding.Title)
	if title == "" {
		title = template.Title
	}
	now := time.Now()
	switch {
	case template.Sandbox:
		data, err := sandboxData(def.Scope.Job, "")
		if err != nil || data.Detail == nil {
			return nil, "", fmt.Errorf("%w: scope.job does not resolve to a completed sandbox result", errSettingsValidation)
		}
		return renderThemedSandboxReportPDF(*data.Detail, now, pdfThemeNamed(def.Theme), def.Branding.pdf()), title, nil
	case template.Payload:
		analysis, err := s.analyzePayload(def.Scope.Hash)
		if err != nil {
			return nil, "", fmt.Errorf("%w: scope.hash does not resolve to a captured payload", errSettingsValidation)
		}
		return renderThemedPayloadReportPDF(analysis, now, pdfThemeNamed(def.Theme), def.Branding.pdf()), title, nil
	case template.Ghidra:
		data, err := s.ghidraData(def.Scope.Hash, "")
		if err != nil || data.Detail == nil {
			return nil, "", fmt.Errorf("%w: scope.hash does not resolve to a completed ghidra result", errSettingsValidation)
		}
		return renderThemedGhidraReportPDF(*data.Detail, now, pdfThemeNamed(def.Theme), def.Branding.pdf()), title, nil
	default:
		data := s.reportDataFor(def.Scope.filter(now))
		data.Title = title
		return renderDefinitionPDF(data, def), title, nil
	}
}

// generatePayloadReport is #474's one-click "Generate PDF" trigger on the
// payload detail page: unlike the designer flow, it never requires the
// operator to first create and save a named report definition. It builds an
// ephemeral, never-persisted definition scoped to this one hash and reuses
// the exact same rendering/storage/serving pipeline every other Reports
// studio PDF goes through -- the generated record and its file land in the
// same reports document and are viewable/deletable from Reports studio like
// any other, they just have no DefinitionID (nothing to look back up).
func (s *store) generatePayloadReport(hash, origin string) (generatedReport, string, error) {
	if !hashName.MatchString(hash) {
		return generatedReport{}, "", fmt.Errorf("%w: invalid payload id", errSettingsValidation)
	}
	def := reportDefinition{Template: "payload", Theme: "dark", Scope: reportScope{Hash: hash}}
	pdf, title, err := s.renderDefinitionPDFBytes(def)
	if err != nil {
		return generatedReport{}, "", err
	}
	return s.reports.addGenerated(generatedReport{
		Name:     "Payload " + hash,
		Template: def.Template,
		Theme:    def.Theme,
		Title:    title,
		Origin:   origin,
	}, pdf)
}

func (s *store) serveReportsGenerated(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if !s.reportStudioGuard(w, r, false) {
		return
	}
	all, err := s.reports.listGenerated()
	if err != nil {
		writeReportStoreError(w, err)
		return
	}
	// listGenerated returns oldest first; the API serves newest first.
	ordered := make([]generatedReport, len(all))
	for index, meta := range all {
		ordered[len(all)-1-index] = meta
	}
	writeReportsJSON(w, "", http.StatusOK, map[string]any{"generated": ordered})
}

func (s *store) serveReportGeneratedByID(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/reports/generated/")
	id, action, _ := strings.Cut(tail, "/")
	if !validReportID(id, "gen_") {
		http.NotFound(w, r)
		return
	}
	switch action {
	case "pdf":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		s.serveGeneratedPDF(w, r, id)
	case "":
		if r.Method != http.MethodDelete {
			w.Header().Set("Allow", "DELETE")
			http.Error(w, "DELETE required", http.StatusMethodNotAllowed)
			return
		}
		if !s.reportStudioGuard(w, r, true) {
			return
		}
		if err := s.reports.deleteGenerated(id); err != nil {
			writeReportStoreError(w, err)
			return
		}
		writeReportsJSON(w, "", http.StatusOK, map[string]any{"deleted": id})
	default:
		http.NotFound(w, r)
	}
}

func (s *store) serveGeneratedPDF(w http.ResponseWriter, r *http.Request, id string) {
	if !s.reportStudioGuard(w, r, false) {
		return
	}
	meta, body, err := s.reports.generatedPDF(id)
	if err != nil {
		if errors.Is(err, errUnknownRecord) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "generated report is no longer available", http.StatusGone)
		return
	}
	disposition := "inline"
	if r.URL.Query().Get("download") == "1" {
		disposition = "attachment"
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", disposition+`; filename="`+reportDownloadName(meta)+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(body)
}

// reportDownloadName derives a filesystem-safe download name from the report
// metadata: the design name plus the generation timestamp.
func reportDownloadName(meta generatedReport) string {
	name := strings.ToLower(meta.Name)
	if name == "" {
		name = meta.Template
	}
	var clean strings.Builder
	dash := false
	for _, char := range name {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			clean.WriteRune(char)
			dash = false
		} else if !dash {
			clean.WriteByte('-')
			dash = true
		}
	}
	base := strings.Trim(clean.String(), "-")
	if base == "" {
		base = "report"
	}
	return "honeypot-" + base + "-" + meta.CreatedAt.UTC().Format("20060102-1504") + ".pdf"
}
