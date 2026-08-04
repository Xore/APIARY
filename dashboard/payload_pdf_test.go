package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newPayloadReportTestStore is newReportTestStore plus a real captured
// payload on disk, for #474's payload-report pipeline tests.
func newPayloadReportTestStore(t *testing.T, hash string, content []byte) *store {
	t.Helper()
	s := newReportTestStore(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, hash), content, 0o600); err != nil {
		t.Fatal(err)
	}
	s.payloadDirs = []string{dir}
	return s
}

// TestGeneratePayloadReportThroughPipeline proves the payload template turns
// a captured artifact into a stored, themed PDF -- the payload counterpart
// to TestGenerateSandboxReportThroughPipeline.
func TestGeneratePayloadReportThroughPipeline(t *testing.T) {
	hash := strings.Repeat("a", 64)
	s := newPayloadReportTestStore(t, hash, []byte("#!/bin/sh\necho hi\n"))

	meta, _, err := s.generatePayloadReport(hash, "manual")
	if err != nil {
		t.Fatalf("generate payload report: %v", err)
	}
	if meta.Template != "payload" {
		t.Fatalf("Template = %q, want payload", meta.Template)
	}
	if meta.DefinitionID != "" {
		t.Fatalf("DefinitionID = %q, want empty -- this path never persists a definition", meta.DefinitionID)
	}
	if meta.Origin != "manual" {
		t.Fatalf("Origin = %q, want manual", meta.Origin)
	}
	body, err := os.ReadFile(s.reports.generatedPath(meta))
	if err != nil {
		t.Fatalf("read generated payload pdf: %v", err)
	}
	text := string(body)
	for _, want := range []string{"Payload Analysis Report", hash} {
		if !strings.Contains(text, want) {
			t.Fatalf("payload report missing %q", want)
		}
	}
}

// TestGeneratePayloadReportRejectsUnknownHash proves an unresolvable hash
// fails validation instead of producing an empty/misleading PDF.
func TestGeneratePayloadReportRejectsUnknownHash(t *testing.T) {
	s := newPayloadReportTestStore(t, strings.Repeat("a", 64), []byte("content"))
	if _, _, err := s.generatePayloadReport(strings.Repeat("b", 64), "manual"); !errors.Is(err, errSettingsValidation) {
		t.Fatalf("unknown hash error = %v, want settings validation", err)
	}
}

// TestGeneratePayloadReportRejectsMalformedHash covers the path-injection
// guard: a value that isn't hash-shaped must never reach analyzePayload.
func TestGeneratePayloadReportRejectsMalformedHash(t *testing.T) {
	s := newPayloadReportTestStore(t, strings.Repeat("a", 64), []byte("content"))
	if _, _, err := s.generatePayloadReport("../../etc/passwd", "manual"); !errors.Is(err, errSettingsValidation) {
		t.Fatalf("malformed hash error = %v, want settings validation", err)
	}
}

// TestServeGeneratePayloadReportRequiresIdentity proves the HTTP handler
// goes through the same reportStudioGuard every other Reports studio
// mutation does -- an unauthenticated request (no introspection service
// configured in this test store, same as every other reports_test.go HTTP
// handler test) must not reach generatePayloadReport at all. The generation
// logic itself is covered directly by TestGeneratePayloadReportThroughPipeline
// (mirroring TestGenerateSandboxReportThroughPipeline's own convention of
// testing the store method under the guard rather than the guard itself).
func TestServeGeneratePayloadReportRequiresIdentity(t *testing.T) {
	hash := strings.Repeat("c", 64)
	s := newPayloadReportTestStore(t, hash, []byte("payload bytes"))

	req := httptest.NewRequest(http.MethodPost, "/api/reports/payloads/"+hash+"/generate", nil)
	rec := httptest.NewRecorder()
	s.serveGeneratePayloadReport(rec, req)
	if rec.Code == http.StatusCreated {
		t.Fatal("expected the request to be rejected without a configured identity service")
	}
}

func TestServeGeneratePayloadReportRejectsGET(t *testing.T) {
	s := newPayloadReportTestStore(t, strings.Repeat("d", 64), []byte("x"))
	req := httptest.NewRequest(http.MethodGet, "/api/reports/payloads/"+strings.Repeat("d", 64)+"/generate", nil)
	rec := httptest.NewRecorder()
	s.serveGeneratePayloadReport(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// TestReportTemplateCatalogIncludesPayload guards against #474's template
// silently disappearing from the catalog the designer UI reads.
func TestReportTemplateCatalogIncludesPayload(t *testing.T) {
	template, ok := reportTemplateByID("payload")
	if !ok || !template.Payload {
		t.Fatalf("payload template missing or not marked Payload: %+v", template)
	}
}
