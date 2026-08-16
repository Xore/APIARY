package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// llmAnalysisSearchStub serves /llm-analysis/_search with raw JSON hits
// (not a typed slice, unlike esSearchStub in ml_anomalies_test.go) so a test
// can include a deliberately malformed hit alongside well-formed ones --
// proving refreshLLMAnalysis() skips the bad one instead of discarding the
// whole poll (#150's "malformed" acceptance state).
func llmAnalysisSearchStub(rawHits []json.RawMessage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type hit struct {
			Source json.RawMessage `json:"_source"`
		}
		hits := make([]hit, len(rawHits))
		for i, raw := range rawHits {
			hits[i] = hit{Source: raw}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{"hits": hits},
		})
	}
}

func rawDoc(t *testing.T, doc llmAnalysisDoc) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRefreshLLMAnalysisCoversEveryDocType proves the poll path accepts
// every doc_type llm-worker/worker.py's base_document() actually writes
// (session, payload, report, error) into one shared cache (#150's
// acceptance criteria: "session, payload, report, error... states").
func TestRefreshLLMAnalysisCoversEveryDocType(t *testing.T) {
	docs := []llmAnalysisDoc{
		{Timestamp: "2026-08-01T10:00:00Z", AnalysisID: "a1", DocType: "session", SessionID: "sess-1", Severity: "high", Summary: "brute-forced ssh then ran whoami"},
		{Timestamp: "2026-08-01T10:01:00Z", AnalysisID: "a2", DocType: "payload", PayloadSHA256: "deadbeef", Severity: "critical", Summary: "downloader shell script"},
		{Timestamp: "2026-08-01T10:02:00Z", AnalysisID: "a3", DocType: "report", Summary: "daily summary of 40 sessions"},
		{Timestamp: "2026-08-01T10:03:00Z", AnalysisID: "a4", DocType: "error", ErrorCode: "model_timeout", Error: "ollama request timed out"},
	}
	raws := make([]json.RawMessage, len(docs))
	for i, d := range docs {
		raws[i] = rawDoc(t, d)
	}
	srv := httptest.NewServer(llmAnalysisSearchStub(raws))
	defer srv.Close()

	s := &store{es: newESClient(srv.URL, ""), llmAnalysis: &llmAnalysisStore{}}
	s.refreshLLMAnalysis()

	got := s.llmAnalysis.snapshot()
	if len(got) != 4 {
		t.Fatalf("expected 4 cached docs, got %d: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, d := range got {
		seen[d.DocType] = true
		if !d.AIGenerated() {
			t.Fatalf("AIGenerated() must always be true, got false for %+v", d)
		}
	}
	for _, want := range []string{"session", "payload", "report", "error"} {
		if !seen[want] {
			t.Fatalf("expected doc_type %q in cache, got %+v", want, got)
		}
	}
}

// TestRefreshLLMAnalysisSkipsMalformedHitsWithoutLosingTheRest (#150's
// "malformed" acceptance state): one hit whose _source isn't valid JSON for
// llmAnalysisDoc (a bare string instead of an object) must not discard the
// well-formed hits in the same poll.
func TestRefreshLLMAnalysisSkipsMalformedHitsWithoutLosingTheRest(t *testing.T) {
	good := rawDoc(t, llmAnalysisDoc{Timestamp: "2026-08-01T10:00:00Z", AnalysisID: "a1", DocType: "session", Summary: "ok"})
	malformed := json.RawMessage(`"this is not an object"`)
	srv := httptest.NewServer(llmAnalysisSearchStub([]json.RawMessage{good, malformed}))
	defer srv.Close()

	s := &store{es: newESClient(srv.URL, ""), llmAnalysis: &llmAnalysisStore{}}
	s.refreshLLMAnalysis()

	got := s.llmAnalysis.snapshot()
	if len(got) != 1 || got[0].AnalysisID != "a1" {
		t.Fatalf("expected exactly the one well-formed doc to survive, got %+v", got)
	}
}

// TestRefreshLLMAnalysisMissingIndexLeavesCacheEmpty (#150's "missing-index"
// acceptance state): llm-worker may never have run on this deployment (its
// #66 dependency undeployed), or the dashboard may be redeployed ahead of
// it -- either way, refreshLLMAnalysis must not panic and must leave the
// cache in a normal, empty, servable state, exactly as
// TestFetchESOverviewReturnsFalseOnQueryFailure expects of its own ES
// consumer.
func TestRefreshLLMAnalysisMissingIndexLeavesCacheEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"type":"index_not_found_exception"}}`, http.StatusNotFound)
	}))
	defer srv.Close()

	s := &store{es: newESClient(srv.URL, ""), llmAnalysis: &llmAnalysisStore{}}
	s.refreshLLMAnalysis()

	if got := s.llmAnalysis.snapshot(); len(got) != 0 {
		t.Fatalf("expected an empty cache after a missing-index response, got %+v", got)
	}
	// The API endpoint must still answer cleanly, not 500 or panic.
	rr := httptest.NewRecorder()
	s.serveLLMAnalysisAPI(rr, httptest.NewRequest(http.MethodGet, "/api/llm/analysis", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from the API with an empty cache, got %d", rr.Code)
	}
	var body []llmAnalysisDoc
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected a valid JSON array, got %q: %v", rr.Body.String(), err)
	}
	if len(body) != 0 {
		t.Fatalf("expected an empty JSON array, got %+v", body)
	}
}

// TestServeLLMAnalysisAPINilStoreServesEmptyArray covers the store never
// having been initialised at all (ELASTICSEARCH_URL unset in main()) --
// distinct from the missing-index case above, which has a store but an
// empty cache.
func TestServeLLMAnalysisAPINilStoreServesEmptyArray(t *testing.T) {
	s := &store{}
	rr := httptest.NewRecorder()
	s.serveLLMAnalysisAPI(rr, httptest.NewRequest(http.MethodGet, "/api/llm/analysis", nil))
	if rr.Body.String() != "[]\n" {
		t.Fatalf("expected an empty JSON array body, got %q", rr.Body.String())
	}
}

// TestServeLLMAnalysisAPIFiltersAndLimits proves type/severity filtering and
// the default/max limit clamp, mirroring the equivalent ml-anomalies test
// coverage for serveMLAnomaliesAPI.
func TestServeLLMAnalysisAPIFiltersAndLimits(t *testing.T) {
	s := &store{llmAnalysis: &llmAnalysisStore{}}
	s.llmAnalysis.absorb([]llmAnalysisDoc{
		{Timestamp: "2026-08-01T10:00:00Z", DocType: "session", Severity: "low"},
		{Timestamp: "2026-08-01T10:01:00Z", DocType: "payload", Severity: "critical"},
		{Timestamp: "2026-08-01T10:02:00Z", DocType: "session", Severity: "critical"},
	})

	rr := httptest.NewRecorder()
	s.serveLLMAnalysisAPI(rr, httptest.NewRequest(http.MethodGet, "/api/llm/analysis?doc_type=session&severity=critical", nil))
	var body []llmAnalysisDoc
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body[0].Timestamp != "2026-08-01T10:02:00Z" {
		t.Fatalf("expected exactly the one session+critical doc, got %+v", body)
	}

	rr2 := httptest.NewRecorder()
	s.serveLLMAnalysisAPI(rr2, httptest.NewRequest(http.MethodGet, "/api/llm/analysis?limit=1", nil))
	var body2 []llmAnalysisDoc
	if err := json.Unmarshal(rr2.Body.Bytes(), &body2); err != nil {
		t.Fatal(err)
	}
	if len(body2) != 1 {
		t.Fatalf("expected limit=1 to return exactly one doc, got %d", len(body2))
	}
	// Newest first.
	if body2[0].Timestamp != "2026-08-01T10:02:00Z" {
		t.Fatalf("expected the newest doc first, got %+v", body2)
	}
}

// TestLLMAnalysisDocEvidenceLink covers all three EvidenceLink() branches:
// session (links back to every event in that session), payload (links to
// the payload's own entry), and report (no single source, empty link).
func TestLLMAnalysisDocEvidenceLink(t *testing.T) {
	session := llmAnalysisDoc{DocType: "session", SessionID: "sess-1"}
	wantQ := url.Values{"q": {`honeypot.session:"sess-1"`}}.Encode()
	if got := session.EvidenceLink(); got != "/history?"+wantQ {
		t.Fatalf("session EvidenceLink() = %q, want /history?%s", got, wantQ)
	}

	payload := llmAnalysisDoc{DocType: "payload", PayloadSHA256: "deadbeef"}
	if got := payload.EvidenceLink(); got != "/payloads?q=deadbeef" {
		t.Fatalf("payload EvidenceLink() = %q, want /payloads?q=deadbeef", got)
	}

	report := llmAnalysisDoc{DocType: "report"}
	if got := report.EvidenceLink(); got != "" {
		t.Fatalf("report EvidenceLink() = %q, want empty (no single source document)", got)
	}

	emptySession := llmAnalysisDoc{DocType: "session"}
	if got := emptySession.EvidenceLink(); got != "" {
		t.Fatalf("session with no SessionID: EvidenceLink() = %q, want empty", got)
	}
}

// TestLLMAnalysisDataAppliesFilterToPage proves /llm-analysis's
// server-rendered page data respects the same filter serveLLMAnalysisAPI
// does, mirroring mlAnomaliesData's identical contract.
func TestLLMAnalysisDataAppliesFilterToPage(t *testing.T) {
	s := &store{llmAnalysis: &llmAnalysisStore{}}
	s.llmAnalysis.absorb([]llmAnalysisDoc{
		{Timestamp: "2026-08-01T10:00:00Z", DocType: "session", Severity: "low"},
		{Timestamp: "2026-08-01T10:01:00Z", DocType: "payload", Severity: "critical"},
	})
	page := s.llmAnalysisData(httptest.NewRequest(http.MethodGet, "/llm-analysis?doc_type=payload", nil))
	if len(page.Docs) != 1 || page.Docs[0].DocType != "payload" {
		t.Fatalf("expected exactly the one payload doc, got %+v", page.Docs)
	}
	if len(page.Filters) != 1 || page.Filters[0] != "doc_type = payload" {
		t.Fatalf("expected the filter bar to describe the active filter, got %+v", page.Filters)
	}
}

// TestLLMAnalysisDataNilStoreReturnsEmptyPage covers rendering /llm-analysis
// with Elasticsearch disabled entirely (s.es nil, s.llmAnalysis nil,
// main()'s normal state when ELASTICSEARCH_URL is unset) -- must not panic.
func TestLLMAnalysisDataNilStoreReturnsEmptyPage(t *testing.T) {
	s := &store{}
	page := s.llmAnalysisData(httptest.NewRequest(http.MethodGet, "/llm-analysis", nil))
	if page.Enabled {
		t.Fatal("expected Enabled=false with no ES client configured")
	}
	if len(page.Docs) != 0 {
		t.Fatalf("expected no docs, got %+v", page.Docs)
	}
}

// llmAnalysisAlertMessages mirrors ghidraAlertMessages (ghidra_test.go):
// s.alerts nil means "no dedupe sink configured", so every qualifying check
// emits -- exactly what a unit test wants.
func llmAnalysisAlertMessages(t *testing.T, docs []llmAnalysisDoc) []string {
	t.Helper()
	s := &store{llmAnalysis: &llmAnalysisStore{}}
	s.llmAnalysis.absorb(docs)
	var messages []string
	llmAnalysisAlerts(s, &messages, false)
	return messages
}

// TestLLMAnalysisAlertsSilentWhenUnconfigured (#154 item 9 follow-up):
// llm-worker's dashboard support (#150) may be deployed ahead of #66's
// worker, or Elasticsearch may not be configured at all -- alerting about a
// subsystem nobody has wired up yet is pure noise, same reasoning as
// ghidraAlerts'/githubAnalysisAlerts' own Configured checks.
func TestLLMAnalysisAlertsSilentWhenUnconfigured(t *testing.T) {
	var messages []string
	llmAnalysisAlerts(&store{}, &messages, false)
	if len(messages) != 0 {
		t.Fatalf("unconfigured store produced alerts: %v", messages)
	}
}

// TestLLMAnalysisAlertsOnAnalysisError mirrors TestGhidraAlertsOnFailedResult:
// a doc_type=error document (the worker's own analysis failure) alerts with
// its reason, unconditionally -- not gated by severity, since it has none.
func TestLLMAnalysisAlertsOnAnalysisError(t *testing.T) {
	messages := llmAnalysisAlertMessages(t, []llmAnalysisDoc{
		{AnalysisID: "err-1", DocType: "error", ErrorCode: "model_timeout", Error: "ollama request timed out"},
	})
	if !hasAlert(messages, "llm-analysis failed") || !hasAlert(messages, "ollama request timed out") {
		t.Fatalf("error doc did not alert with its reason: %v", messages)
	}
}

// TestLLMAnalysisAlertsOnHighSeverity mirrors TestGhidraAlertsOnHighAIRisk:
// a session/payload doc scored high/critical by the model alerts, the
// message says it's an unverified model guess (not a fact the reader should
// trust without checking), and a severity outside the configured set stays
// quiet -- same env-var-driven allowlist pattern as GHIDRA_ALERT_RISK_LEVELS.
// The evidence link itself (passed to s.alerts.observe, not part of the
// messages slice this helper returns) is covered directly by
// TestLLMAnalysisDocEvidenceLink.
func TestLLMAnalysisAlertsOnHighSeverity(t *testing.T) {
	docs := []llmAnalysisDoc{
		{AnalysisID: "sess-1", DocType: "session", SessionID: "sess-1", Severity: "high", Model: "qwen3.5:9b", Intent: "recon-then-download"},
	}
	messages := llmAnalysisAlertMessages(t, docs)
	if !hasAlert(messages, "llm-analysis flagged session") {
		t.Fatalf("high severity did not alert: %v", messages)
	}
	if !hasAlert(messages, "UNVERIFIED") {
		t.Errorf("severity alert does not mark itself unverified: %v", messages)
	}

	t.Setenv("LLM_ANALYSIS_ALERT_SEVERITIES", "critical")
	if messages := llmAnalysisAlertMessages(t, docs); hasAlert(messages, "flagged") {
		t.Fatalf("a severity outside the configured set alerted: %v", messages)
	}
}

// TestLLMAnalysisAlertsSkipsLowSeverityAndReports proves the two things
// deliberately excluded from alerting: a low/medium severity doc (below the
// default high/critical threshold) and a "report" doc_type (an aggregate
// over many sessions, not evidence of one actor's behavior -- the same
// reasoning EvidenceLink() already applies).
func TestLLMAnalysisAlertsSkipsLowSeverityAndReports(t *testing.T) {
	messages := llmAnalysisAlertMessages(t, []llmAnalysisDoc{
		{AnalysisID: "sess-2", DocType: "session", Severity: "low"},
		{AnalysisID: "report-2026-08-05", DocType: "report", Severity: "critical"},
	})
	if len(messages) != 0 {
		t.Fatalf("low severity and report doc_type must not alert: %v", messages)
	}
}
