package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// seedPayloadCache populates s.payloadCache directly from a real disk scan,
// bypassing the async Elasticsearch round-trip refreshPayloadCacheAsync
// normally does -- the same test-only shortcut payloads_filter_test.go's
// own TestPayloadsDataFiltersBySensor already uses. payloadsData() itself
// reads only s.payloadCache (Elasticsearch-backed in production, per #403 --
// the dashboard never scans disk directly from a request handler), so this
// is what a test needs to seed, not the handler under test.
func seedPayloadCache(s *store) {
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()
}

// TestServeReportPayloadOptionsFindsRealCapturedPayload proves #653's
// picker endpoint actually surfaces a real captured payload -- the whole
// point of the issue was that Report Studio had no way to discover one at
// all, so this must find what's really on disk, not a synthetic fixture
// the endpoint itself fabricates.
func TestServeReportPayloadOptionsFindsRealCapturedPayload(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	hash := strings.Repeat("a", 64)
	s := newPayloadReportTestStore(t, hash, []byte("#!/bin/sh\necho hi\n"))
	seedPayloadCache(s)

	req := httptest.NewRequest(http.MethodGet, "/api/reports/payload-options?q="+hash[:12], nil)
	addIdentityTestCookie(req)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	s.serveReportPayloadOptions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Payloads []reportPayloadOption `json:"payloads"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Payloads) != 1 {
		t.Fatalf("payloads = %d, want 1: %+v", len(body.Payloads), body.Payloads)
	}
	if body.Payloads[0].Hash != hash {
		t.Fatalf("Hash = %q, want %q", body.Payloads[0].Hash, hash)
	}
}

// TestServeReportPayloadOptionsFiltersByQuery proves the ?q= substring
// filter actually narrows results rather than always returning everything.
func TestServeReportPayloadOptionsFiltersByQuery(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	hash := strings.Repeat("b", 64)
	s := newPayloadReportTestStore(t, hash, []byte("content"))
	seedPayloadCache(s)

	req := httptest.NewRequest(http.MethodGet, "/api/reports/payload-options?q="+strings.Repeat("z", 8), nil)
	addIdentityTestCookie(req)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	s.serveReportPayloadOptions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Payloads []reportPayloadOption `json:"payloads"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Payloads) != 0 {
		t.Fatalf("payloads = %d, want 0 for a non-matching query: %+v", len(body.Payloads), body.Payloads)
	}
}

// TestServeReportPayloadOptionsRequiresIdentity mirrors
// TestServeGeneratePayloadReportRequiresIdentity: an unauthenticated
// request must not reach the payload inventory at all.
func TestServeReportPayloadOptionsRequiresIdentity(t *testing.T) {
	hash := strings.Repeat("c", 64)
	s := newPayloadReportTestStore(t, hash, []byte("content"))

	req := httptest.NewRequest(http.MethodGet, "/api/reports/payload-options", nil)
	rec := httptest.NewRecorder()
	s.serveReportPayloadOptions(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("expected the request to be rejected without a configured identity service")
	}
}

func TestServeReportPayloadOptionsRejectsPOST(t *testing.T) {
	s := newPayloadReportTestStore(t, strings.Repeat("d", 64), []byte("x"))
	req := httptest.NewRequest(http.MethodPost, "/api/reports/payload-options", nil)
	rec := httptest.NewRecorder()
	s.serveReportPayloadOptions(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
