package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchSuricataAlertCountsParsesBuckets(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"aggregations":{"by_ip":{"buckets":[
			{"key":"203.0.113.1","doc_count":5},
			{"key":"198.51.100.1","doc_count":2}
		]}}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	counts, ok := fetchSuricataAlertCounts(es, time.Now().Add(-time.Hour))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if gotPath != "/"+suricataAlertIndexPattern+"/_search" {
		t.Fatalf("path = %q", gotPath)
	}
	if counts["203.0.113.1"] != 5 || counts["198.51.100.1"] != 2 {
		t.Fatalf("got %+v", counts)
	}
}

func TestFetchSuricataAlertCountsTreats404AsEmptyNotFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	counts, ok := fetchSuricataAlertCounts(es, time.Now().Add(-time.Hour))
	if !ok {
		t.Fatal("a missing suricata-v2-alert-* index should not be a failure")
	}
	if len(counts) != 0 {
		t.Fatalf("expected an empty map, got %+v", counts)
	}
}

func TestFetchSuricataAlertCountsReturnsFalseOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, ok := fetchSuricataAlertCounts(es, time.Now().Add(-time.Hour))
	if ok {
		t.Fatal("a genuine 500 must not be conflated with a missing-index 404")
	}
}
