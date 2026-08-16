package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGhidraVerdictReturnsFamilyGuessWhenPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ghidra-analysis-v1/_doc/ghidra:deadbeef" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"_source":{"ghidra":{"ai_triage":{"family_guess":"Mirai variant"}}}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	family, found := ghidraVerdict(es, "deadbeef")
	if !found || family != "Mirai variant" {
		t.Fatalf("family=%q found=%v", family, found)
	}
}

func TestGhidraVerdictNotFoundOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, found := ghidraVerdict(es, "deadbeef")
	if found {
		t.Fatal("expected found=false on a 404")
	}
}

func TestGhidraVerdictNotFoundOnEmptyFamilyGuess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"_source":{"ghidra":{"ai_triage":{"family_guess":""}}}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, found := ghidraVerdict(es, "deadbeef")
	if found {
		t.Fatal("an empty family_guess should not count as a found verdict")
	}
}

func TestSandboxVerdictReturnsHighestRiskAcrossRuns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sandbox-analysis-v1/_search" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"hits":{"hits":[
			{"_source":{"sandbox":{"risk_level":"low"}}},
			{"_source":{"sandbox":{"risk_level":"critical"}}},
			{"_source":{"sandbox":{"risk_level":"high"}}}
		]}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	label, found := sandboxVerdict(es, "deadbeef")
	if !found || label != "sandbox: critical risk" {
		t.Fatalf("label=%q found=%v", label, found)
	}
}

func TestSandboxVerdictIgnoresLowAndUnrated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"hits":{"hits":[
			{"_source":{"sandbox":{"risk_level":"low"}}},
			{"_source":{"sandbox":{"risk_level":"unrated"}}}
		]}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, found := sandboxVerdict(es, "deadbeef")
	if found {
		t.Fatal("low/unrated risk should not count as a found verdict")
	}
}

func TestGithubVerdictReturnsFamilyWhenPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/github-analysis-v1/_doc/github_analysis:deadbeef" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"_source":{"github_analysis":{"family":"Cobalt Strike"}}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	family, found := githubVerdict(es, "deadbeef")
	if !found || family != "Cobalt Strike" {
		t.Fatalf("family=%q found=%v", family, found)
	}
}

func TestRevdeckVerdictReturnsTruncatedAnswerOnlyWhenCompleted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/revdeck-analysis-v1/_doc/revdeck:deadbeef" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		long := ""
		for i := 0; i < 100; i++ {
			long += "x"
		}
		w.Write([]byte(`{"_source":{"revdeck":{"revdeck":{"status":"completed","answer":"` + long + `"}}}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	answer, found := revdeckVerdict(es, "deadbeef")
	if !found {
		t.Fatal("expected found=true for a completed run with an answer")
	}
	if len(answer) != len("revdeck: ")+revdeckAnswerLimit+len("…") {
		t.Fatalf("expected the answer to be truncated to %d chars, got %d: %q", revdeckAnswerLimit, len(answer), answer)
	}
}

func TestRevdeckVerdictIgnoresErrorRecords(t *testing.T) {
	// #1220: the exact live shape sampled on this deployment -- a run that
	// never completed because REVDECK_API_BASE isn't configured.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"_source":{"revdeck":{"error":"REVDECK_API_BASE is not configured on this worker","revdeck":null}}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, found := revdeckVerdict(es, "deadbeef")
	if found {
		t.Fatal("an error record with no completed revdeck payload should not count as a found verdict")
	}
}

func TestAttachVerdictsDedupsAndSortsLabels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"_source":{"ghidra":{"ai_triage":{"family_guess":"SomeFamily"}}}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	e := &entity{Payloads: []string{"abc123def456", "abc123def456"}}
	attachVerdicts(es, e)
	if len(e.Verdicts) != 1 {
		t.Fatalf("expected deduped verdicts, got %+v", e.Verdicts)
	}
}
