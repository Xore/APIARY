package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const hashCorrelationSample = `{
  "hits": {
    "total": {"value": 2},
    "hits": [
      {"_index": "honeypot-v2-2026.08.02", "_source": {"@timestamp": "2026-08-02T12:00:00Z", "event": {"sensor": "cowrie"}}},
      {"_index": "honeypot-v2-2026.08.01", "_source": {"@timestamp": "2026-08-01T09:00:00Z", "event": {"sensor": "dionaea"}}}
    ]
  }
}`

// TestCorrelateHashChecksEverySourceIncludingGhidra (#354): correlateHash is
// the first place Ghidra, sandbox, GitHub-analysis, and Elasticsearch
// sighting history are all checked together for one hash -- previously
// Ghidra results weren't surfaced on /payload-analysis at all.
func TestCorrelateHashChecksEverySourceIncludingGhidra(t *testing.T) {
	// esResultsClient (loadGhidraResults/loadSandboxResults/
	// loadGitHubAnalysisResults, #1103) is a separate client from s.es
	// below (the sighting-history search correlateHash also does) -- two
	// distinct servers, since correlationSearchStub answers every path with
	// the same fixed sighting-history body, not per-index result docs.
	esResultsClientFor(t, map[string][]map[string]any{
		"ghidra-analysis-v1": {
			{"ghidra": map[string]any{"version": 1, "sha256": shaA, "exit_status": "ok", "completed_at": "2026-08-02T10:00:00Z"}},
		},
		"sandbox-analysis-v1": {
			{"sandbox": map[string]any{"version": 1, "job": "linux-x", "sha256": shaA, "completed_at": "2026-08-02T11:00:00Z"}},
		},
		"github-analysis-v1": {
			{"github_analysis": map[string]any{"sha256": shaA, "exit_status": "ok", "family": "Mirai"}},
		},
	})

	var gotPath string
	es := httptest.NewServer(correlationSearchStub(t, &gotPath, hashCorrelationSample))
	defer es.Close()

	// altID simulates a Dionaea capture's on-disk MD5 identity, distinct
	// from its true content SHA-256 (shaA) -- the bug this two-argument
	// signature exists to fix: an earlier version of this code only ever
	// queried Elasticsearch with the true SHA-256, silently missing every
	// Dionaea sighting (which Elasticsearch only ever has under
	// file.hash.md5, keyed by the MD5, not the SHA-256).
	altID := "0123456789abcdef0123456789abcdef"
	s := &store{es: newESClient(es.URL, "")}
	// Loaded explicitly here, same as every real caller does now (#1142):
	// correlateHash no longer fetches these itself, see its own doc
	// comment.
	result := s.correlateHash(shaA, altID, loadGhidraResults(), loadSandboxResults(), loadGitHubAnalysisResults())

	if !result.Known {
		t.Fatal("expected Known=true when every source has a result")
	}
	if result.Ghidra == nil || result.Ghidra.ExitStatus != "ok" {
		t.Fatalf("Ghidra result not found: %+v", result.Ghidra)
	}
	if len(result.Sandbox) != 1 || result.Sandbox[0].Job != "linux-x" {
		t.Fatalf("sandbox result not found: %+v", result.Sandbox)
	}
	if result.GitHub == nil || result.GitHub.Family != "Mirai" {
		t.Fatalf("GitHub-analysis result not found: %+v", result.GitHub)
	}
	if !result.ESAvailable || result.ESSightings != 2 {
		t.Fatalf("ES sightings not found: available=%v sightings=%d", result.ESAvailable, result.ESSightings)
	}
	for _, want := range []string{`file.hash.sha256:"` + shaA + `"`, `file.hash.md5:"` + shaA + `"`, `file.hash.sha256:"` + altID + `"`, `file.hash.md5:"` + altID + `"`} {
		if !strings.Contains(gotPath, url.QueryEscape(want)) {
			t.Fatalf("query is missing %q -- both identifiers must be checked against both hash fields: %s", want, gotPath)
		}
	}
}

// TestCorrelateHashReportsUnknownWhenNothingMatches (#354): a hash with no
// results anywhere must report Known=false, not a false positive from an
// empty-but-truthy struct.
func TestCorrelateHashReportsUnknownWhenNothingMatches(t *testing.T) {
	t.Setenv("GHIDRA_RESULTS_DIR", t.TempDir())
	t.Setenv("SANDBOX_RESULTS_DIR", t.TempDir())
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())

	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	result := s.correlateHash(shaB, "", nil, nil, nil)
	if result.Known {
		t.Fatalf("expected Known=false with no matches anywhere, got %+v", result)
	}
}

// TestCorrelateHashRejectsMalformedInputWithoutQuerying (#354): mirrors the
// IP-correlation defense (#354 phase 2) -- a malformed value must never
// reach the Lucene query string.
func TestCorrelateHashRejectsMalformedInputWithoutQuerying(t *testing.T) {
	called := false
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	for _, bad := range []string{"", "not-a-hash", `abc" OR "1`, "toolong" + strings.Repeat("a", 200)} {
		if result := s.correlateHash(bad, "", nil, nil, nil); result.Known {
			t.Errorf("correlateHash(%q) should never report Known=true for malformed input, got %+v", bad, result)
		}
	}
	if called {
		t.Fatal("malformed primary must never reach the Elasticsearch query")
	}
}

// TestCorrelateHashRejectsMalformedAltID (#354): a well-formed primary must
// still be queried, but a malformed altID (or one that happens to equal
// primary) must never be added as a second query clause.
func TestCorrelateHashRejectsMalformedAltID(t *testing.T) {
	var gotPath string
	es := httptest.NewServer(correlationSearchStub(t, &gotPath, `{"hits":{"total":{"value":0},"hits":[]}}`))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	for _, bad := range []string{"not-a-hash", `abc" OR "1`, shaA} {
		gotPath = ""
		s.correlateHash(shaA, bad, nil, nil, nil)
		if gotPath == "" {
			t.Fatal("a well-formed primary must still be queried even when altID is malformed")
		}
		if strings.Count(gotPath, "file.hash.sha256") != 1 {
			t.Fatalf("altID %q must not add a second query clause (malformed, or a no-op duplicate of primary): %s", bad, gotPath)
		}
	}
}

// TestCorrelateHashFlagsTruncationWhenSightingsExceedReturnedRecords (#887):
// correlate() caps how many records it actually returns (200) but reports
// Elasticsearch's true total hit count separately -- when a hash has more
// sightings than fit in that cap, the oldest record in the returned,
// newest-first page is NOT the hash's true first sighting, and callers must
// be told that rather than silently trusting it.
func TestCorrelateHashFlagsTruncationWhenSightingsExceedReturnedRecords(t *testing.T) {
	es := httptest.NewServer(correlationSearchStub(t, new(string), `{
	  "hits": {
	    "total": {"value": 5000},
	    "hits": [
	      {"_index": "honeypot-v2-2026.08.02", "_source": {"@timestamp": "2026-08-02T12:00:00Z", "event": {"sensor": "cowrie"}}},
	      {"_index": "honeypot-v2-2026.08.01", "_source": {"@timestamp": "2026-08-01T09:00:00Z", "event": {"sensor": "dionaea"}}}
	    ]
	  }
	}`))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	result := s.correlateHash(shaA, "", nil, nil, nil)
	if !result.ESTruncated {
		t.Fatalf("expected ESTruncated=true when total (5000) exceeds returned records (2), got %+v", result)
	}
	if result.ESSightings != 5000 {
		t.Fatalf("expected the true total sightings to still be reported, got %d", result.ESSightings)
	}
}

// TestCorrelateHashDoesNotFlagTruncationWhenAllSightingsAreReturned (#887):
// the common case -- total fits within the record cap -- must not be
// flagged as truncated.
func TestCorrelateHashDoesNotFlagTruncationWhenAllSightingsAreReturned(t *testing.T) {
	es := httptest.NewServer(correlationSearchStub(t, new(string), hashCorrelationSample))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	result := s.correlateHash(shaA, "", nil, nil, nil)
	if result.ESTruncated {
		t.Fatalf("did not expect ESTruncated when total (2) matches returned records, got %+v", result)
	}
}

// TestPayloadAnalysisPageRendersSkeletonNotCorrelationDirectly (#1142):
// /payload-analysis/<hash> no longer renders SandboxRuns/GitHubAnalysis/
// Correlation synchronously -- even a binaryAnalysis with them fully
// populated (as if a caller tried the old direct-render path) must not
// leak that data into the page; only the skeleton placeholders and the
// hash/sha256 data attributes hp-payload-analysis.js hydrates from should
// appear. The real "known vs not seen elsewhere" content is covered by
// payloadAggregationFor's own tests instead, against the JSON it produces
// for that JS to render client-side.
func TestPayloadAnalysisPageRendersSkeletonNotCorrelationDirectly(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	known := binaryAnalysis{
		Hash: shaA, SHA256: shaA,
		Correlation: hashCorrelation{
			Known:       true,
			Ghidra:      &ghidraResult{ExitStatus: "ok", CompletedAt: "2026-08-02T10:00:00Z"},
			ESAvailable: true, ESSightings: 3, ESFirstSeen: "2026-08-01 09:00:00", ESLastSeen: "2026-08-02 12:00:00",
			ESSensors: []kv{{Key: "cowrie", Count: 2}},
		},
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "payload-analysis", &known); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()
	// "already analyzed" alone is too broad -- the card's own static note
	// ("...you know if this hash was already analyzed...") legitimately
	// contains that phrase regardless of Correlation; the badge markup is
	// what must be absent.
	for _, gone := range []string{`badge--green">already analyzed`, "3 event(s)", "not seen elsewhere"} {
		if strings.Contains(body, gone) {
			t.Fatalf("page must not render Correlation content directly anymore (found %q): %s", gone, body)
		}
	}
	for _, want := range []string{
		`data-hp-pl-hash="` + shaA + `"`, `data-hp-pl-sha256="` + shaA + `"`,
		"data-hp-pl-sandbox-runs", "data-hp-pl-github-analysis", "data-hp-pl-known-elsewhere",
		`id="hp-pl-known-elsewhere-heading"`, "/static/hp-payload-analysis.js",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("page is missing %q -- hp-payload-analysis.js needs this to hydrate", want)
		}
	}
}

// TestPayloadAggregationForReportsKnownVsNotSeenElsewhere (#354/#1142): the
// data payloadAggregationFor produces (what hp-payload-analysis.js renders
// as the Known-elsewhere card) must distinguish a hash with results
// somewhere from one with none -- moved here from the old template-level
// test now that this content renders client-side instead of server-side.
func TestPayloadAggregationForReportsKnownVsNotSeenElsewhere(t *testing.T) {
	esResultsClientFor(t, map[string][]map[string]any{
		"ghidra-analysis-v1": {
			{"ghidra": map[string]any{"version": 1, "sha256": shaA, "exit_status": "ok", "completed_at": "2026-08-02T10:00:00Z"}},
		},
	})
	es := httptest.NewServer(correlationSearchStub(t, new(string), hashCorrelationSample))
	defer es.Close()
	s := &store{es: newESClient(es.URL, "")}

	agg := s.payloadAggregationFor(shaA, "")
	if !agg.Correlation.Known {
		t.Fatal("expected Known=true when Ghidra has a result")
	}
	if agg.Correlation.Ghidra == nil || agg.Correlation.Ghidra.ExitStatus != "ok" {
		t.Fatalf("expected the Ghidra result to be surfaced, got %+v", agg.Correlation.Ghidra)
	}

	esResultsClientFor(t, map[string][]map[string]any{})
	esNone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer esNone.Close()
	s2 := &store{es: newESClient(esNone.URL, "")}
	agg2 := s2.payloadAggregationFor(shaB, "")
	if agg2.Correlation.Known {
		t.Fatalf("expected Known=false with no matches anywhere, got %+v", agg2.Correlation)
	}
}

// TestWorkbenchPageRendersKnownElsewhereSkeleton (#1472): correlation is an
// independent hydrated source. The identifier-aware shell must always reserve
// its visible card without synchronously embedding either stale results or a
// false "not known" state.
func TestWorkbenchPageRendersKnownElsewhereSkeleton(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	shell := workbenchPageData{SHA256: shaA}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "payload-workbench", &shell); err != nil {
		t.Fatalf("render shell: %v", err)
	}
	body := buf.String()
	for _, want := range []string{`id="wb-known-elsewhere"`, `data-wb-known aria-busy="true"`, `data-wb-classification aria-busy="true"`, `data-wb-model-status aria-busy="true"`, `data-wb-analyzers aria-busy="true"`, `data-wb-runs aria-live="polite" aria-busy="true"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("render-first workbench shell is missing %q", want)
		}
	}
	for _, synchronous := range []string{"Sandbox: 1 run(s)", "No prior native analysis", "identified type"} {
		if strings.Contains(body, synchronous) {
			t.Fatalf("shell synchronously rendered hydrated data %q", synchronous)
		}
	}
}
