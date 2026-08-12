package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// TestRefreshProblemReportsCacheAsyncNoopWithoutES mirrors
// TestRefreshGithubAnalysisCacheAsyncNoopWithoutES (github_analysis_test.go,
// #1156-follow-up): with no s.es configured, the cache must stay
// unpopulated.
func TestRefreshProblemReportsCacheAsyncNoopWithoutES(t *testing.T) {
	s := &store{}
	s.refreshProblemReportsCacheAsync()
	if !s.problemReportsCacheAt.IsZero() {
		t.Fatal("refreshProblemReportsCacheAsync populated the cache without a configured es client")
	}
}

// TestRefreshProblemReportsCacheAsyncPopulatesFromES proves the background
// refresh actually fills the cache from Elasticsearch and sorts it newest
// first -- runs in a goroutine, so poll briefly rather than asserting
// synchronously, the same pattern
// TestRefreshGithubAnalysisCacheAsyncPopulatesFromES uses.
func TestRefreshProblemReportsCacheAsyncPopulatesFromES(t *testing.T) {
	s := newTestProblemReportStore(t)
	older := problemReport{ID: "older", SubmittedAt: time.Now().Add(-time.Hour), Status: "open"}
	newer := problemReport{ID: "newer", SubmittedAt: time.Now(), Status: "open"}
	for _, rep := range []problemReport{older, newer} {
		doc, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.es.docIndex(problemReportsIndex, rep.ID, doc, true, 0, 0); err != nil {
			t.Fatalf("seed report %s: %v", rep.ID, err)
		}
	}

	s.refreshProblemReportsCacheAsync()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.problemReportsMu.Lock()
		ready := !s.problemReportsCacheAt.IsZero()
		s.problemReportsMu.Unlock()
		if ready {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.problemReportsMu.Lock()
	cache := append([]problemReport(nil), s.problemReportsCache...)
	s.problemReportsMu.Unlock()
	if len(cache) != 2 {
		t.Fatalf("expected both ES-seeded reports to reach the cache, got %+v", cache)
	}
	if cache[0].ID != "newer" || cache[1].ID != "older" {
		t.Fatalf("expected the cache sorted newest first, got %+v", cache)
	}
}

// TestRefreshProblemReportsCacheAsyncSkipsWhileWarm mirrors
// TestRefreshGithubAnalysisCacheAsyncSkipsWhileWarm: the TTL guard must
// prevent a redundant Elasticsearch round trip while the last successful
// refresh is still within problemReportsCacheTTL.
func TestRefreshProblemReportsCacheAsyncSkipsWhileWarm(t *testing.T) {
	var requests int
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	s.problemReportsCacheAt = time.Now() // already warm
	s.refreshProblemReportsCacheAsync()
	// No goroutine should even be spawned -- the TTL guard returns
	// synchronously -- but give any accidental one a moment to prove it
	// wrong before asserting.
	time.Sleep(50 * time.Millisecond)
	if requests != 0 {
		t.Fatalf("expected no Elasticsearch request while the cache is still within TTL, got %d", requests)
	}
}

// TestServeProblemReportsPageServesSkeletonBeforeFirstRefresh covers the
// #1157 follow-up: a request that reaches serveProblemReportsPage before
// refreshProblemReportsCacheAsync's first cycle ever completes must render
// the Loading skeleton, not the real "no reports" empty state -- and must
// never block on the synchronous ES fetch this handler used to make on
// every single request.
func TestServeProblemReportsPageServesSkeletonBeforeFirstRefresh(t *testing.T) {
	s := newTestProblemReportStore(t)
	// Simulates the moment a request reaches the handler while
	// refreshProblemReportsCacheAsync's background goroutine is still
	// running its very first cycle -- set directly rather than racing the
	// real (near-instant, in-process) ES stub round trip.
	s.problemReportsRefreshing = true
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))

	req := httptest.NewRequest(http.MethodGet, "/admin/problem-reports", nil)
	req = withIdentity(req, authenticatedIdentity{Subject: "0123456789abcdef", Role: "admin"})
	rec := httptest.NewRecorder()
	s.serveProblemReportsPage(rec, req, tmpl)

	body := rec.Body.String()
	if !strings.Contains(body, "skeleton") {
		t.Fatalf("expected a skeleton placeholder while the cache has never been populated, got: %s", body)
	}
	if strings.Contains(body, "No problem reports have been submitted yet.") {
		t.Fatal("must not show the real empty-state text while still warming up")
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
