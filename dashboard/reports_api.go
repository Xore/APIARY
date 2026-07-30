package main

// reports_api.go — the administrator endpoints of the Reports studio (R2):
//
//	GET    /api/reports/templates                  template and element catalog
//	GET    /api/reports/definitions                saved definitions (+ ETag)
//	POST   /api/reports/definitions                create (server-assigned id)
//	GET    /api/reports/definitions/{id}           one definition
//	PATCH  /api/reports/definitions/{id}           full-field replace
//	DELETE /api/reports/definitions/{id}
//	POST   /api/reports/definitions/{id}/generate  render now and store the PDF
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
	"fmt"
	"io"
	"net/http"
	"os"
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

// writeReportStoreError maps store failures onto the settings API contract:
// conflicts, validation, missing records, and read-only stores stay
// distinguishable without parsing text.
func writeReportStoreError(w http.ResponseWriter, err error) {
	writePreferenceError(w, err)
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
	writeReportsJSON(w, "", http.StatusOK, map[string]any{
		"templates": reportTemplateCatalog(),
		"elements":  reportElementCatalog,
		"windows":   []string{"1h", "6h", "24h", "7d", "30d"},
		"themes":    []string{"dark", "light"},
	})
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

// renderDefinitionToStored is the generation pipeline shared by the manual
// API and the scheduler: resolve the definition, render the PDF from live
// telemetry (or the referenced sandbox run), and persist it.
func (s *store) renderDefinitionToStored(id, origin string) (generatedReport, string, error) {
	def, ok := s.reports.definition(id)
	if !ok {
		return generatedReport{}, "", fmt.Errorf("%w: no report definition with this id", errUnknownRecord)
	}
	template, _ := reportTemplateByID(def.Template)
	title := strings.TrimSpace(def.Branding.Title)
	if title == "" {
		title = template.Title
	}
	now := time.Now()
	var pdf []byte
	if template.Sandbox {
		data, err := sandboxData(def.Scope.Job, "")
		if err != nil || data.Detail == nil {
			return generatedReport{}, "", fmt.Errorf("%w: scope.job does not resolve to a completed sandbox result", errSettingsValidation)
		}
		pdf = renderThemedSandboxReportPDF(*data.Detail, now, pdfThemeNamed(def.Theme), def.Branding.pdf())
	} else {
		data := s.reportDataFor(def.Scope.filter(now))
		data.Title = title
		pdf = renderDefinitionPDF(data, def)
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

func (s *store) serveReportsGenerated(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if !s.reportStudioGuard(w, r, false) {
		return
	}
	doc, etag := s.reports.document()
	// The document stores oldest first; the API serves newest first.
	ordered := make([]generatedReport, 0, len(doc.Generated))
	for index := len(doc.Generated) - 1; index >= 0; index-- {
		ordered = append(ordered, doc.Generated[index])
	}
	writeReportsJSON(w, etag, http.StatusOK, map[string]any{"generated": ordered})
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
		if err := s.reports.deleteGenerated(r.Header.Get("If-Match"), id); err != nil {
			writeReportStoreError(w, err)
			return
		}
		_, etag := s.reports.document()
		writeReportsJSON(w, etag, http.StatusOK, map[string]any{"deleted": id})
	default:
		http.NotFound(w, r)
	}
}

func (s *store) serveGeneratedPDF(w http.ResponseWriter, r *http.Request, id string) {
	if !s.reportStudioGuard(w, r, false) {
		return
	}
	meta, ok := s.reports.generated(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := os.ReadFile(s.reports.generatedPath(meta))
	if err != nil {
		http.Error(w, "generated report file is no longer available", http.StatusGone)
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
