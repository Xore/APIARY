package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthzReportsUnavailableUntilReady proves #828's fix: /healthz
// answers immediately either way (never hangs/refuses -- that's #353's own
// fix, unchanged here), but its status code distinguishes "the listener is
// up" from "the first rebuild() actually populated real data", instead of
// an unconditional 200 the instant the process starts.
func TestHealthzReportsUnavailableUntilReady(t *testing.T) {
	s := &store{}
	handler := healthzHandler(s)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("before ready: status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	s.ready.Store(true)
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("after ready: status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("after ready: body = %q, want \"ok\"", rec.Body.String())
	}
}
