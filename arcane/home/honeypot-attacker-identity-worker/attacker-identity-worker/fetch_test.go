package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFetchRecentEventsFailsOnUnmarshalableSearchResponse covers #1344:
// fetchRecentEvents used to treat any json.Unmarshal error on a page as "no
// more results", discarding whatever hits it had already decoded and
// returning (out, true) -- a silently-truncated success. A single malformed
// document anywhere in honeypot-v2-* (many independent producers write to
// it) must instead fail the whole fetch loudly, not report a clean cycle
// with an artificially small event count.
func TestFetchRecentEventsFailsOnUnmarshalableSearchResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/honeypot-v2-*/_pit":
			w.Write([]byte(`{"id":"pit123"}`))
		case r.URL.Path == "/_search":
			w.Write([]byte(`not valid json`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, ok := fetchRecentEvents(es, time.Now().Add(-time.Hour))
	if ok {
		t.Fatal("an unparseable search response must fail fetchRecentEvents, not report a silently-truncated success")
	}
}

// TestFetchRecentEventsFailsOnSearchError covers the sibling silent-success
// path: a transport/query error from searchBody must also fail the fetch,
// not silently stop pagination and report whatever was collected so far as
// a complete, successful cycle.
func TestFetchRecentEventsFailsOnSearchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/honeypot-v2-*/_pit":
			w.Write([]byte(`{"id":"pit123"}`))
		case r.URL.Path == "/_search":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, ok := fetchRecentEvents(es, time.Now().Add(-time.Hour))
	if ok {
		t.Fatal("a search error must fail fetchRecentEvents")
	}
}

// TestFetchRecentEventsReturnsEvents is the control case, proving a clean
// single-page response still parses correctly and reports success.
func TestFetchRecentEventsReturnsEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/honeypot-v2-*/_pit":
			w.Write([]byte(`{"id":"pit123"}`))
		case r.URL.Path == "/_search":
			w.Write([]byte(`{"hits":{"hits":[{"sort":[1],"_source":{"@timestamp":"2026-08-14T00:00:00Z","source":{"ip":"198.51.100.7"},"event":{"sensor":"cowrie"}}}]}}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	events, ok := fetchRecentEvents(es, time.Now().Add(-time.Hour))
	if !ok {
		t.Fatal("expected success for a clean single-page response")
	}
	if len(events) != 1 || events[0].SrcIP != "198.51.100.7" {
		t.Fatalf("events = %+v, want one event from 198.51.100.7", events)
	}
}
