package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func decodeJSONBody(t *testing.T, r *http.Request, v any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatalf("decoding request body: %v", err)
	}
}

func TestDocGetReturnsNotFoundAsNoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, found, err := es.docGet("some-index", "some-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false on a 404")
	}
}

func TestDocGetParsesHitFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"_seq_no":3,"_primary_term":2,"_source":{"hash":"abc"}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	hit, found, err := es.docGet("some-index", "some-id")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if hit.SeqNo != 3 || hit.PrimaryTerm != 2 {
		t.Fatalf("hit = %+v, want seq_no=3 primary_term=2", hit)
	}
	if string(hit.Source) != `{"hash":"abc"}` {
		t.Fatalf("source = %s", hit.Source)
	}
}

func TestDocExistsUsesHEADNotGET(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	exists, err := es.docExists("some-index", "some-id")
	if err != nil || !exists {
		t.Fatalf("exists=%v err=%v", exists, err)
	}
	if gotMethod != http.MethodHead {
		t.Fatalf("method = %s, want HEAD (#1221 -- must not transfer _source just to check existence)", gotMethod)
	}
}

func TestDocExistsReturnsFalseOnNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	exists, err := es.docExists("some-index", "some-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Fatal("expected exists=false on a 404")
	}
}

func TestDocExistsReturnsErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	if _, err := es.docExists("some-index", "some-id"); err == nil {
		t.Fatal("expected an error on a 500 response")
	}
}

func TestDocIndexCreateUsesOpTypeCreate(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	if err := es.docIndex("idx", "id1", []byte(`{}`), true); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "op_type=create" {
		t.Fatalf("query = %q, want op_type=create", gotQuery)
	}
}

func TestDocIndexReturnsErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	if err := es.docIndex("idx", "id1", []byte(`{}`), false); err == nil {
		t.Fatal("expected an error on a 500 response")
	}
}
