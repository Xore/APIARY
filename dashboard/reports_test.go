package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newReportTestStore builds a store with a reports studio and a settings
// service backed by temporary state, for API-level tests. Generated-report
// storage (#475) and, since #787, report definitions/config/users are all
// Elasticsearch-backed, so this wires one in-memory ES document-store stub
// (memESDocStore, alerts_test.go) shared by all of them, matching the real
// single-cluster deployment.
func newReportTestStore(t *testing.T) *store {
	t.Helper()
	dir := t.TempDir()
	esStore := newMemESDocStore()
	esSrv := httptest.NewServer(esStore.handler())
	t.Cleanup(esSrv.Close)
	es := newESClient(esSrv.URL, "")
	return &store{
		settings: newSettingsService(
			es,
			filepath.Join(dir, "audit.jsonl"),
			filepath.Join(dir, "history.jsonl"),
		),
		reports: newReportStore(es),
	}
}

func sampleDefinition(template string) reportDefinition {
	preset, _ := reportTemplateByID(template)
	def := reportDefinition{
		Name:     "Weekly review",
		Template: template,
		Theme:    preset.Theme,
		Elements: append([]string(nil), preset.Elements...),
		Scope:    reportScope{Window: preset.Window},
	}
	if preset.Sandbox {
		def.Scope.Job = "linux-20260729T164848Z-cbe0b83cb4a0"
	}
	if preset.Payload || preset.Ghidra {
		def.Scope.Hash = strings.Repeat("a", 64)
	}
	return def
}

// TestWriteReportStoreErrorUsesReportWording proves report-definition
// conflicts get their own message rather than writePreferenceError's
// hardcoded "preferences changed concurrently" -- the wrong subsystem's
// name on a resource that is not a preference (#211).
func TestWriteReportStoreErrorUsesReportWording(t *testing.T) {
	w := httptest.NewRecorder()
	writeReportStoreError(w, errStaleRevision)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusConflict)
	}
	body := strings.TrimSpace(w.Body.String())
	if strings.Contains(body, "preferences") {
		t.Fatalf("report conflict message still names preferences: %q", body)
	}
	if !strings.Contains(body, "report definition") {
		t.Fatalf("report conflict message does not name the actual resource: %q", body)
	}
}

// TestReportTemplateCatalogValid proves every published preset produces a
// valid definition, so the designer can always start from a template.
func TestReportTemplateCatalogValid(t *testing.T) {
	templates := reportTemplateCatalog()
	if len(templates) < 7 {
		t.Fatalf("template catalog = %d entries, want at least 7", len(templates))
	}
	for _, template := range templates {
		def := sampleDefinition(template.ID)
		if err := validateDefinitionFields(def); err != nil {
			t.Fatalf("template %q does not produce a valid definition: %v", template.ID, err)
		}
	}
}

// #477: overrides replace only Name/Description, and an id absent from
// (or no longer present in) the compiled catalog is silently ignored rather
// than injected as a phantom entry or causing an error.
func TestReportTemplateCatalogWithOverrides(t *testing.T) {
	base := reportTemplateCatalog()
	overridden := reportTemplateCatalogWithOverrides(map[string]reportPresetOverride{
		"executive":  {Name: "Board summary", Description: "Custom copy"},
		"unknown-id": {Name: "should be ignored"},
	})
	if len(overridden) != len(base) {
		t.Fatalf("overridden catalog length = %d, want %d (no phantom entries)", len(overridden), len(base))
	}
	for i, template := range overridden {
		if template.ID != base[i].ID || template.Theme != base[i].Theme || template.Window != base[i].Window {
			t.Fatalf("structural fields must stay compiled for %q: got %#v, base %#v", template.ID, template, base[i])
		}
		if template.ID == "executive" {
			if template.Name != "Board summary" || template.Description != "Custom copy" {
				t.Fatalf("executive override not applied: %#v", template)
			}
			continue
		}
		if template.Name != base[i].Name || template.Description != base[i].Description {
			t.Fatalf("non-overridden template %q must keep its compiled copy, got %#v", template.ID, template)
		}
	}

	// A blank override field falls back to the compiled default rather than
	// clearing the copy to empty text.
	blankOverridden := reportTemplateCatalogWithOverrides(map[string]reportPresetOverride{
		"executive": {Name: "", Description: "Only description changed"},
	})
	for _, template := range blankOverridden {
		if template.ID != "executive" {
			continue
		}
		if template.Name != base[0].Name {
			t.Fatalf("blank name override must keep the compiled default, got %q", template.Name)
		}
		if template.Description != "Only description changed" {
			t.Fatalf("non-blank description override must apply, got %q", template.Description)
		}
	}
}

func TestReportPresetRowsForCarriesDefaultsAndOverridesSeparately(t *testing.T) {
	rows := reportPresetRowsFor(map[string]reportPresetOverride{
		"executive": {Name: "Board summary"},
	})
	catalog := reportTemplateCatalog()
	if len(rows) != len(catalog) {
		t.Fatalf("rows = %d, want %d", len(rows), len(catalog))
	}
	for _, row := range rows {
		template, ok := reportTemplateByID(row.ID)
		if !ok {
			t.Fatalf("row %q does not name a known template", row.ID)
		}
		if row.DefaultName != template.Name || row.DefaultDescription != template.Description {
			t.Fatalf("row %q defaults must mirror the compiled catalog untouched: %#v", row.ID, row)
		}
		if row.ID == "executive" {
			if row.OverrideName != "Board summary" || row.OverrideDescription != "" {
				t.Fatalf("executive row override = %#v, want name set and description empty", row)
			}
			continue
		}
		if row.OverrideName != "" || row.OverrideDescription != "" {
			t.Fatalf("row %q must have no override when none was given: %#v", row.ID, row)
		}
	}
}

func TestValidateDefinitionFields(t *testing.T) {
	valid := sampleDefinition("custom")
	cases := []struct {
		name   string
		mutate func(*reportDefinition)
		want   string // expected field in the validation message; "" means valid
	}{
		{"valid custom", func(*reportDefinition) {}, ""},
		{"name required", func(d *reportDefinition) { d.Name = "  " }, "name"},
		{"name too long", func(d *reportDefinition) { d.Name = strings.Repeat("n", maxReportName+1) }, "name"},
		{"unknown template", func(d *reportDefinition) { d.Template = "nope" }, "template"},
		{"bad theme", func(d *reportDefinition) { d.Theme = "sepia" }, "theme"},
		{"no elements", func(d *reportDefinition) { d.Elements = nil }, "elements"},
		{"unknown element", func(d *reportDefinition) { d.Elements = []string{elementCover, "charts"} }, "elements"},
		{"duplicate element", func(d *reportDefinition) { d.Elements = []string{elementCover, elementMetrics, elementMetrics} }, "elements"},
		{"appendix negative", func(d *reportDefinition) { d.AppendixLimit = -1 }, "appendix_limit"},
		{"appendix too large", func(d *reportDefinition) { d.AppendixLimit = maxReportAppendix + 1 }, "appendix_limit"},
		{"bad window", func(d *reportDefinition) { d.Scope.Window = "48h" }, "scope.window"},
		{"bad type", func(d *reportDefinition) { d.Scope.Type = "everything" }, "scope.type"},
		{"job on telemetry template", func(d *reportDefinition) { d.Scope.Job = "job-1" }, "scope.job"},
		{"branding title too long", func(d *reportDefinition) { d.Branding.Title = strings.Repeat("t", 81) }, "branding.title"},
		{"scope text too long", func(d *reportDefinition) { d.Scope.Text = strings.Repeat("q", 201) }, "scope.text"},
		{"sandbox missing job", func(d *reportDefinition) {
			*d = sampleDefinition("sandbox")
			d.Scope.Job = ""
		}, "scope.job"},
		{"sandbox with elements", func(d *reportDefinition) {
			*d = sampleDefinition("sandbox")
			d.Elements = []string{elementCover}
		}, "elements"},
		{"valid sandbox", func(d *reportDefinition) { *d = sampleDefinition("sandbox") }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def := valid
			def.Elements = append([]string(nil), valid.Elements...)
			tc.mutate(&def)
			err := validateDefinitionFields(def)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}
				return
			}
			if !errors.Is(err, errSettingsValidation) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation error = %v, want a settings validation error naming %q", err, tc.want)
			}
		})
	}
}

func TestNormalizeReportElements(t *testing.T) {
	got := normalizeReportElements([]string{elementParameters, elementMetrics, elementCover, elementFindings})
	want := []string{elementCover, elementMetrics, elementFindings, elementParameters}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("normalizeReportElements() = %v, want %v", got, want)
	}
}

func TestReportStoreDefinitionCRUD(t *testing.T) {
	esStore := newMemESDocStore()
	esSrv := httptest.NewServer(esStore.handler())
	defer esSrv.Close()
	store := newReportStore(newESClient(esSrv.URL, ""))

	created, etag, err := store.putDefinition("", sampleDefinition("executive"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !validReportID(created.ID, "rep_") || created.Created.IsZero() || created.Updated.IsZero() {
		t.Fatalf("created definition missing server fields: %+v", created)
	}
	if etag == "" {
		t.Fatal("create returned no ETag")
	}

	created.Name = "Board briefing"
	if _, _, err := store.putDefinition("", created); err != nil {
		t.Fatalf("replace: %v", err)
	}
	loaded, ok := store.definition(created.ID)
	if !ok || loaded.Name != "Board briefing" || !loaded.Created.Equal(created.Created) {
		t.Fatalf("replaced definition = %+v (found %t), want renamed with preserved creation time", loaded, ok)
	}

	if _, _, err := store.putDefinition(`"r0-000000000000"`, created); !errors.Is(err, errStaleRevision) {
		t.Fatalf("stale If-Match error = %v, want errStaleRevision", err)
	}

	if err := store.deleteDefinition("", created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.deleteDefinition("", created.ID); !errors.Is(err, errUnknownRecord) {
		t.Fatalf("second delete error = %v, want errUnknownRecord", err)
	}
}

// TestReportStoreGeneratedRetention proves generated PDFs land in
// Elasticsearch, the history prunes to the retention cap, and pruned
// records are actually deleted there (#475).
func TestReportStoreGeneratedRetention(t *testing.T) {
	esStore := newMemESDocStore()
	esSrv := httptest.NewServer(esStore.handler())
	defer esSrv.Close()
	store := newReportStore(newESClient(esSrv.URL, ""))
	store.maxGenerated = 3
	pdf := []byte("%PDF-1.4\nfake\n%%EOF\n")

	var kept []generatedReport
	for i := 0; i < 5; i++ {
		meta, _, err := store.addGenerated(generatedReport{
			Name: fmt.Sprintf("Report %d", i), Template: "custom", Theme: "dark", Title: "T", Origin: "manual",
		}, pdf)
		if err != nil {
			t.Fatalf("addGenerated %d: %v", i, err)
		}
		kept = append(kept, meta)
		// Each addGenerated stamps CreatedAt from time.Now(); force distinct
		// timestamps so pruneGenerated's oldest-first sort is deterministic
		// even when the loop runs fast enough to land in the same instant.
		time.Sleep(time.Millisecond)
	}
	all, err := store.listGenerated()
	if err != nil {
		t.Fatalf("listGenerated: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("generated history = %d entries, want retention cap 3", len(all))
	}
	for _, meta := range kept[:2] {
		if _, ok := store.generated(meta.ID); ok {
			t.Fatalf("pruned record %s still present", meta.ID)
		}
	}
	for _, meta := range kept[2:] {
		if _, ok := store.generated(meta.ID); !ok {
			t.Fatalf("retained record %s missing", meta.ID)
		}
	}

	victim := all[0]
	if err := store.deleteGenerated(victim.ID); err != nil {
		t.Fatalf("deleteGenerated: %v", err)
	}
	if _, ok := store.generated(victim.ID); ok {
		t.Fatal("deleted generated record still present")
	}
}

// TestReportsAPIEndToEnd walks the whole studio flow over HTTP: catalog,
// create, generate, view, download, delete — with the administrator guard
// and optimistic concurrency enforced.
func TestReportsAPIEndToEnd(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	s := newReportTestStore(t)

	call := func(method, path string, body any, mutate func(*http.Request)) *httptest.ResponseRecorder {
		var reader *bytes.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			reader = bytes.NewReader(raw)
		} else {
			reader = bytes.NewReader(nil)
		}
		request := httptest.NewRequest(method, path, reader)
		addIdentityTestCookie(request)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if mutate != nil {
			mutate(request)
		}
		response := httptest.NewRecorder()
		switch {
		case path == "/api/reports/templates":
			s.serveReportTemplates(response, request)
		case path == "/api/reports/definitions":
			s.serveReportDefinitions(response, request)
		case strings.HasPrefix(path, "/api/reports/definitions/"):
			s.serveReportDefinitionByID(response, request)
		case path == "/api/reports/generated":
			s.serveReportsGenerated(response, request)
		default:
			s.serveReportGeneratedByID(response, request)
		}
		return response
	}
	sameOrigin := func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }

	// The designer's catalog.
	catalog := call(http.MethodGet, "/api/reports/templates", nil, nil)
	if catalog.Code != http.StatusOK || !strings.Contains(catalog.Body.String(), `"executive"`) || !strings.Contains(catalog.Body.String(), `"event_appendix"`) {
		t.Fatalf("templates catalog = status %d", catalog.Code)
	}

	// Create a branded light-theme definition.
	def := sampleDefinition("custom")
	def.Name = "Board briefing"
	def.Theme = "light"
	def.Branding = reportBranding{Title: "Board Security Briefing", Author: "SOC", FooterLeft: "CONFIDENTIAL - BOARD"}
	created := call(http.MethodPost, "/api/reports/definitions", def, sameOrigin)
	if created.Code != http.StatusCreated {
		t.Fatalf("create definition = status %d body %s", created.Code, created.Body.String())
	}
	var createdPayload struct {
		Definition reportDefinition `json:"definition"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdPayload); err != nil || !validReportID(createdPayload.Definition.ID, "rep_") {
		t.Fatalf("create response = %s", created.Body.String())
	}
	defID := createdPayload.Definition.ID
	etag := created.Header().Get("ETag")

	// Validation failures name fields and map to 422.
	bad := def
	bad.Theme = "sepia"
	if response := call(http.MethodPost, "/api/reports/definitions", bad, sameOrigin); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid definition = status %d, want 422", response.Code)
	}

	// Optimistic concurrency: a stale If-Match conflicts.
	update := createdPayload.Definition
	update.Name = "Board briefing v2"
	conflict := call(http.MethodPatch, "/api/reports/definitions/"+defID, update, func(r *http.Request) {
		sameOrigin(r)
		r.Header.Set("If-Match", `"r0-000000000000"`)
	})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("stale If-Match = status %d, want 409", conflict.Code)
	}
	replaced := call(http.MethodPatch, "/api/reports/definitions/"+defID, update, func(r *http.Request) {
		sameOrigin(r)
		r.Header.Set("If-Match", etag)
	})
	if replaced.Code != http.StatusOK {
		t.Fatalf("replace definition = status %d body %s", replaced.Code, replaced.Body.String())
	}

	// Generate: the definition renders against the (empty) telemetry window.
	generated := call(http.MethodPost, "/api/reports/definitions/"+defID+"/generate", nil, sameOrigin)
	if generated.Code != http.StatusCreated {
		t.Fatalf("generate = status %d body %s", generated.Code, generated.Body.String())
	}
	var generatedPayload struct {
		Generated generatedReport `json:"generated"`
	}
	if err := json.Unmarshal(generated.Body.Bytes(), &generatedPayload); err != nil || generatedPayload.Generated.ID == "" {
		t.Fatalf("generate response = %s", generated.Body.String())
	}
	gen := generatedPayload.Generated
	if gen.Origin != "manual" || gen.Title != "Board Security Briefing" || gen.SizeBytes <= 0 {
		t.Fatalf("generated metadata = %+v", gen)
	}

	// History serves newest first.
	history := call(http.MethodGet, "/api/reports/generated", nil, nil)
	if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), gen.ID) {
		t.Fatalf("generated history = status %d body %s", history.Code, history.Body.String())
	}

	// Inline view and attachment download.
	inline := call(http.MethodGet, "/api/reports/generated/"+gen.ID+"/pdf", nil, nil)
	if inline.Code != http.StatusOK || !bytes.HasPrefix(inline.Body.Bytes(), []byte("%PDF-1.4")) {
		t.Fatalf("inline pdf = status %d", inline.Code)
	}
	if disposition := inline.Header().Get("Content-Disposition"); !strings.HasPrefix(disposition, "inline") {
		t.Fatalf("inline disposition = %q", disposition)
	}
	if !strings.Contains(inline.Body.String(), "CONFIDENTIAL - BOARD") {
		t.Fatal("generated PDF must carry the definition branding")
	}
	download := call(http.MethodGet, "/api/reports/generated/"+gen.ID+"/pdf?download=1", nil, nil)
	disposition := download.Header().Get("Content-Disposition")
	if !strings.HasPrefix(disposition, "attachment") || !strings.Contains(disposition, "board-briefing") {
		t.Fatalf("download disposition = %q", disposition)
	}

	// Delete the artifact, then the definition.
	if response := call(http.MethodDelete, "/api/reports/generated/"+gen.ID, nil, sameOrigin); response.Code != http.StatusOK {
		t.Fatalf("delete generated = status %d", response.Code)
	}
	if gone := call(http.MethodGet, "/api/reports/generated/"+gen.ID+"/pdf", nil, nil); gone.Code != http.StatusNotFound {
		t.Fatalf("deleted pdf = status %d, want 404", gone.Code)
	}
	if response := call(http.MethodDelete, "/api/reports/definitions/"+defID, nil, sameOrigin); response.Code != http.StatusOK {
		t.Fatalf("delete definition = status %d", response.Code)
	}
}

// TestReportsAPIRequiresAdmin proves the studio rejects non-admin identities
// on reads and mutations alike.
func TestReportsAPIRequiresAdmin(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "user")
	s := newReportTestStore(t)

	read := httptest.NewRecorder()
	s.serveReportDefinitions(read, func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/reports/definitions", nil)
		addIdentityTestCookie(r)
		return r
	}())
	if read.Code != http.StatusForbidden {
		t.Fatalf("non-admin read = status %d, want 403", read.Code)
	}

	write := httptest.NewRecorder()
	s.createReportDefinition(write, func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/reports/definitions", strings.NewReader(`{"name":"x","template":"custom","theme":"dark","elements":["cover"]}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		addIdentityTestCookie(r)
		return r
	}())
	if write.Code != http.StatusForbidden {
		t.Fatalf("non-admin create = status %d, want 403", write.Code)
	}
}

// TestRenderDefinitionPDFRespectsElements proves the element selection drives
// the rendered document: unselected sections are absent.
func TestRenderDefinitionPDFRespectsElements(t *testing.T) {
	def := sampleDefinition("custom")
	def.Elements = []string{elementCover, elementMetrics, elementParameters}
	data := sampleReportData(testTime())
	body := string(renderDefinitionPDF(data, def))
	for _, want := range []string{"Executive summary", "Report parameters and limitations"} {
		if !strings.Contains(body, want) {
			t.Fatalf("definition PDF missing selected section %q", want)
		}
	}
	for _, absent := range []string{"Top sensors", "Top source addresses", "Evidence appendix", "Operational dashboard alerts"} {
		if strings.Contains(body, absent) {
			t.Fatalf("definition PDF must not render unselected section %q", absent)
		}
	}
}

// TestGenerateSandboxReportThroughPipeline proves the sandbox template turns a
// referenced analysis run into a stored, themed PDF.
func TestGenerateSandboxReportThroughPipeline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	job := "linux-20260729T164848Z-cbe0b83cb4a0"
	result := `{
		"version":3,
		"job":"` + job + `",
		"sha256":"` + strings.Repeat("c", 64) + `",
		"run_status":"completed",
		"guest_started":true,
		"risk_score":22,
		"risk_level":"low",
		"duration_seconds":14.5,
		"network_summary":{"dns_queries":["ntp.ubuntu.com"]}
	}`
	if err := os.WriteFile(filepath.Join(dir, job+".json"), []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newReportTestStore(t)
	def := sampleDefinition("sandbox")
	def.Branding.FooterLeft = "CONFIDENTIAL - SANDBOX"
	created, _, err := s.reports.putDefinition("", def)
	if err != nil {
		t.Fatalf("create sandbox definition: %v", err)
	}
	meta, _, err := s.renderDefinitionToStored(created.ID, "schedule")
	if err != nil {
		t.Fatalf("generate sandbox report: %v", err)
	}
	_, body, err := s.reports.generatedPDF(meta.ID)
	if err != nil {
		t.Fatalf("read generated sandbox pdf: %v", err)
	}
	text := string(body)
	for _, want := range []string{"Sandbox Dynamic Analysis Report", "CONFIDENTIAL - SANDBOX", "ntp.ubuntu.com"} {
		if !strings.Contains(text, want) {
			t.Fatalf("sandbox report missing %q", want)
		}
	}
	if meta.Origin != "schedule" {
		t.Fatalf("origin = %q, want schedule", meta.Origin)
	}

	// An unresolvable job fails validation instead of producing an empty PDF.
	def.Scope.Job = "no-such-job"
	created2, _, err := s.reports.putDefinition("", def)
	if err != nil {
		t.Fatalf("create dangling sandbox definition: %v", err)
	}
	if _, _, err := s.renderDefinitionToStored(created2.ID, "manual"); !errors.Is(err, errSettingsValidation) {
		t.Fatalf("dangling job error = %v, want settings validation", err)
	}
}

func TestReportDownloadName(t *testing.T) {
	meta := generatedReport{Name: "Board Briefing / Q3", Template: "executive"}
	got := reportDownloadName(meta)
	if !strings.HasPrefix(got, "honeypot-board-briefing-q3-") || !strings.HasSuffix(got, ".pdf") {
		t.Fatalf("reportDownloadName() = %q", got)
	}
}

func testTime() (t0 time.Time) {
	return time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
}
