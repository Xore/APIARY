package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestProblemReportStore(t *testing.T) *store {
	t.Helper()
	esStore := newMemESDocStore()
	srv := httptest.NewServer(esStore.handler())
	t.Cleanup(srv.Close)
	es := newESClient(srv.URL, "")
	s := &store{es: es}
	return s
}

func TestRedactCapturedTextStripsCommonSecretFields(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"password field", `{"password":"hunter2"}`},
		{"api key field", `api_key=sk-abc123def456`},
		{"authorization header", "Authorization: Bearer eyJhbGciOi.abc.def"},
		{"cookie header", "Cookie: session=abc123; other=xyz"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redactCapturedText(c.in)
			if strings.Contains(got, "hunter2") || strings.Contains(got, "sk-abc123def456") ||
				strings.Contains(got, "eyJhbGciOi.abc.def") || strings.Contains(got, "abc123; other=xyz") {
				t.Fatalf("redactCapturedText(%q) = %q, still contains the secret", c.in, got)
			}
			if !strings.Contains(got, "[redacted]") {
				t.Fatalf("redactCapturedText(%q) = %q, expected a [redacted] marker", c.in, got)
			}
		})
	}
}

func TestRedactCapturedTextTruncatesOversizedInput(t *testing.T) {
	in := strings.Repeat("a", maxCapturedTextBytes+500)
	got := redactCapturedText(in)
	if len(got) > maxCapturedTextBytes+50 {
		t.Fatalf("redactCapturedText did not truncate: got length %d", len(got))
	}
	if !strings.HasSuffix(got, "...[truncated]") {
		t.Fatalf("redactCapturedText(oversized) = %q, expected a truncation marker", got)
	}
}

func TestSubmitProblemReportRejectsWhenFeatureDisabled(t *testing.T) {
	s := newTestProblemReportStore(t)
	// s.settings is nil, so problemReportButtonEnabled() falls back to
	// defaultDashboardConfig(), which defaults the toggle to false (#1147:
	// off by default, an operator opts in deliberately).
	req := httptest.NewRequest(http.MethodPost, "/api/problem-reports", strings.NewReader(`{"expected":"x"}`))
	req = withIdentity(req, authenticatedIdentity{Subject: "0123456789abcdef", Role: "operator"})
	rec := httptest.NewRecorder()
	s.serveProblemReports(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when the feature is disabled, got %d: %s", rec.Code, rec.Body.String())
	}
}

// enableProblemReportButton gives s a real settings service (against the
// same in-memory ES fixture) with behavior.show_problem_report_button
// turned on -- problemReportButtonEnabled() checks s.settings.config first,
// so a nil settings service always falls back to the (off-by-default)
// compiled default.
func enableProblemReportButton(t *testing.T, s *store) {
	t.Helper()
	dir := t.TempDir()
	s.settings = newSettingsService(s.es, dir+"/audit.jsonl", dir+"/history.jsonl")
	_, _, err := s.settings.config.Update("", func(c *dashboardConfig) error {
		c.Behavior.ShowProblemReportButton = true
		return nil
	})
	if err != nil {
		t.Fatalf("enable problem report button: %v", err)
	}
}

func TestSubmitProblemReportRequiresExpectedField(t *testing.T) {
	s := newTestProblemReportStore(t)
	enableProblemReportButton(t, s)

	req := httptest.NewRequest(http.MethodPost, "/api/problem-reports", strings.NewReader(`{"expected":""}`))
	req = withIdentity(req, authenticatedIdentity{Subject: "0123456789abcdef", Role: "operator"})
	rec := httptest.NewRecorder()
	s.serveProblemReports(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an empty expected field, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSubmitProblemReportSucceedsAndRedactsBeforeStoring(t *testing.T) {
	s := newTestProblemReportStore(t)
	enableProblemReportButton(t, s)

	body, _ := json.Marshal(problemReportSubmission{
		Page:        "/overview",
		Expected:    "the page should load",
		Actual:      "it 500'd",
		DOMSnapshot: `<div data-token="Authorization: Bearer supersecrettoken123">x</div>`,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/problem-reports", bytes.NewReader(body))
	req = withIdentity(req, authenticatedIdentity{Subject: "0123456789abcdef", Username: "alice", Role: "operator"})
	rec := httptest.NewRecorder()
	s.serveProblemReports(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("expected a report id in the response, got %s (err=%v)", rec.Body.String(), err)
	}

	hit, found, err := s.es.docGet(problemReportsIndex, created.ID)
	if err != nil || !found {
		t.Fatalf("expected the report to be stored under its id: found=%v err=%v", found, err)
	}
	var stored problemReport
	if err := json.Unmarshal(hit.Source, &stored); err != nil {
		t.Fatalf("unmarshal stored report: %v", err)
	}
	if stored.Status != "open" {
		t.Fatalf("expected a freshly submitted report to be status=open, got %q", stored.Status)
	}
	if stored.SubmittedBy != "0123456789abcdef" {
		t.Fatalf("expected submitted_by to come from the resolved identity, got %q", stored.SubmittedBy)
	}
	if strings.Contains(stored.DOMSnapshot, "supersecrettoken123") {
		t.Fatalf("expected the stored DOM snapshot to be redacted, got %q", stored.DOMSnapshot)
	}
}

func TestListProblemReportsRequiresAdmin(t *testing.T) {
	s := newTestProblemReportStore(t)
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")

	req := httptest.NewRequest(http.MethodGet, "/api/problem-reports", nil)
	req = withIdentity(req, authenticatedIdentity{Subject: "0123456789abcdef", Role: "operator"})
	rec := httptest.NewRecorder()
	s.serveProblemReports(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-admin GET, got %d: %s", rec.Code, rec.Body.String())
	}
}
