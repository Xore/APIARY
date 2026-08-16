package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDocIndexSucceedsOn2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	if err := es.docIndex("campaigns-v1", "203.0.113.0/24", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
}

func TestDocIndexReturnsErrorOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	if err := es.docIndex("campaigns-v1", "id", []byte(`{}`)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestDeleteByQueryExceptSendsExplicitIDExclusions(t *testing.T) {
	var gotBody map[string]any
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	if err := deleteByQueryExcept(es, "campaigns-v1", []string{"203.0.113.0/24", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/campaigns-v1/_delete_by_query" {
		t.Fatalf("path = %q", gotPath)
	}
	mustNot, ok := gotBody["query"].(map[string]any)["bool"].(map[string]any)["must_not"].([]any)
	if !ok || len(mustNot) != 2 {
		t.Fatalf("expected 2 must_not clauses, got %+v", gotBody)
	}
}

func TestDeleteByQueryExceptTreats404AsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	if err := deleteByQueryExcept(es, "campaigns-v1", nil); err != nil {
		t.Fatalf("a missing index should not be an error: %v", err)
	}
}
