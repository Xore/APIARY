package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestPurgeDeadLettersRespectsCurrentQueryScope is #59's own rule applied to
// a destructive action instead of an export: the query actually sent to
// Elasticsearch must be exactly the one the operator had in the search box
// (mirrored via /api/dead-letters's own `q` param, the same one the read
// path already uses), never silently broadened.
func TestPurgeDeadLettersRespectsCurrentQueryScope(t *testing.T) {
	var gotMethod, gotPath string
	es := httptest.NewServer(deadLetterPurgeStub(t, &gotMethod, &gotPath, 7))
	defer es.Close()

	c := newESClient(es.URL, "")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/dead-letters?q=error.type:mapper_parsing_exception", nil)
	c.purgeDeadLetters(rec, req)

	if gotMethod != "POST" {
		t.Fatalf("expected Elasticsearch to receive POST for _delete_by_query, got %s", gotMethod)
	}
	if !strings.Contains(gotPath, "/dead-letter-honeypot*/_delete_by_query") {
		t.Fatalf("purge did not target the dead-letter index's _delete_by_query: %s", gotPath)
	}
	wantQ := url.QueryEscape("error.type:mapper_parsing_exception")
	if !strings.Contains(gotPath, "q="+wantQ) {
		t.Fatalf("purge request did not carry the operator's query scope: %s", gotPath)
	}
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"deleted":7`) {
		t.Fatalf("unexpected purge response: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestPurgeDeadLettersWithoutQueryPurgesEverythingExplicitly proves the
// empty-query case is handled as "no filter" (matching how the read path
// already treats an empty q), not silently rejected or silently scoped to
// something the UI never asked for.
func TestPurgeDeadLettersWithoutQueryPurgesEverythingExplicitly(t *testing.T) {
	var gotMethod, gotPath string
	es := httptest.NewServer(deadLetterPurgeStub(t, &gotMethod, &gotPath, 42))
	defer es.Close()

	c := newESClient(es.URL, "")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/dead-letters", nil)
	c.purgeDeadLetters(rec, req)

	if strings.Contains(gotPath, "q=") {
		t.Fatalf("unfiltered purge must not send a q= param at all: %s", gotPath)
	}
	if !strings.Contains(rec.Body.String(), `"deleted":42`) {
		t.Fatalf("unexpected purge response body: %s", rec.Body.String())
	}
}

// TestDeadLettersRouteBranchesOnMethod pins that /api/dead-letters routes
// DELETE to the purge path and everything else to the existing read-only
// search -- a regression here would either break search or, worse, make
// purge unreachable from the UI silently. #1323: this used to be one
// handler with an internal r.Method branch; it's now two separate
// method-scoped ServeMux registrations (routes.go) so an unsupported
// method gets net/http's own 405 instead of silently falling through to
// the GET-shaped read. The invariant this test protects is unchanged --
// only where the method decision is made.
func TestDeadLettersRouteBranchesOnMethod(t *testing.T) {
	b, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, `mux.HandleFunc("DELETE /api/dead-letters"`) || !strings.Contains(src, "s.es.purgeDeadLetters(w, r)") {
		t.Fatal("DELETE /api/dead-letters is not registered to purgeDeadLetters")
	}
	if !strings.Contains(src, `mux.HandleFunc("GET /api/dead-letters"`) || !strings.Contains(src, "s.es.deadLetters(w, r)") {
		t.Fatal("GET /api/dead-letters is not registered to the read-only search")
	}
}

// TestPurgeDeadLettersRequiresAdmin is a regression test for #1336:
// DELETE /api/dead-letters is a destructive bulk delete, but unlike every
// other mutating/destructive endpoint in the dashboard it never called
// requireAdmin. Under DASHBOARD_REQUIRE_ADMIN=true, a non-admin session
// must be rejected before the delete-by-query request ever reaches
// Elasticsearch, and a genuine admin session must still succeed.
func TestPurgeDeadLettersRequiresAdmin(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")

	t.Run("non-admin is rejected", func(t *testing.T) {
		configureIdentityTestBackend(t, "user")
		called := false
		es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"deleted":99}`)
		}))
		defer es.Close()

		c := newESClient(es.URL, "")
		req := httptest.NewRequest("DELETE", "/api/dead-letters", nil)
		addIdentityTestCookie(req)
		w := httptest.NewRecorder()
		c.purgeDeadLetters(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
		}
		if called {
			t.Fatal("purgeDeadLetters must not reach Elasticsearch for a non-admin session")
		}
	})

	t.Run("admin succeeds", func(t *testing.T) {
		configureIdentityTestBackend(t, "admin")
		var gotMethod, gotPath string
		es := httptest.NewServer(deadLetterPurgeStub(t, &gotMethod, &gotPath, 7))
		defer es.Close()

		c := newESClient(es.URL, "")
		req := httptest.NewRequest("DELETE", "/api/dead-letters", nil)
		addIdentityTestCookie(req)
		w := httptest.NewRecorder()
		c.purgeDeadLetters(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
		}
		if gotMethod != "POST" {
			t.Fatalf("expected Elasticsearch to receive POST for _delete_by_query, got %s", gotMethod)
		}
	})
}

func deadLetterPurgeStub(t *testing.T, gotMethod, gotPath *string, deleted int64) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		*gotMethod = r.Method
		*gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"deleted":%d}`, deleted)
	}
}
