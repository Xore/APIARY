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
