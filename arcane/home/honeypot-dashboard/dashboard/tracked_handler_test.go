package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func stubOKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func newTestOIDCAuth() *oidcAuth {
	return &oidcAuth{sessions: &memorySessionStore{values: make(map[string][]byte)}, now: time.Now}
}

// TestTrackedHandlerDoesNotTouchActivityForAnUnauthenticatedRequest
// (#1312): touchActivity now runs AFTER the OIDC gate, not before it -- an
// unauthenticated request to an ordinary route never reaches mux at all
// (middleware() redirects or 401s first), so it must not keep the
// idle-rebuild loop alive the way it did when touchActivity ran
// unconditionally ahead of authentication.
func TestTrackedHandlerDoesNotTouchActivityForAnUnauthenticatedRequest(t *testing.T) {
	s := &store{}
	handler := trackedHandler(s, newTestOIDCAuth(), stubOKHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events", nil))

	if rec.Code == http.StatusOK {
		t.Fatalf("an unauthenticated request must not reach the stub handler (status = %d)", rec.Code)
	}
	if s.idleSince() != 0 {
		t.Fatal("touchActivity must not fire for a request the OIDC gate rejected")
	}
}

// TestTrackedHandlerDoesNotTouchActivityForHealthz (#486, preserved by
// #1312's reordering): Docker's own healthcheck (and any external uptime
// monitor) hits /healthz on a fixed interval regardless of whether an
// operator is looking -- touching activity for it would defeat idle
// detection entirely on an unattended host. /healthz is also allowlisted
// inside middleware() itself, so it reaches mux same as before; the
// exclusion has to be enforced here, not by the OIDC gate.
func TestTrackedHandlerDoesNotTouchActivityForHealthz(t *testing.T) {
	s := &store{}
	handler := trackedHandler(s, newTestOIDCAuth(), stubOKHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz must always reach the handler regardless of auth state, got status %d", rec.Code)
	}
	if s.idleSince() != 0 {
		t.Fatal("touchActivity must not fire for /healthz")
	}
}

// TestTrackedHandlerTouchesActivityForAnAllowlistedNonHealthzPath proves
// the positive case: any path that legitimately reaches mux (here,
// middleware()'s own /static/ allowlist, which needs no session) other
// than /healthz does touch activity.
func TestTrackedHandlerTouchesActivityForAnAllowlistedNonHealthzPath(t *testing.T) {
	s := &store{}
	handler := trackedHandler(s, newTestOIDCAuth(), stubOKHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/theme.css", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (static assets are allowlisted)", rec.Code)
	}
	if got := s.idleSince(); got < 0 || got > time.Second {
		t.Fatalf("idleSince() = %v, want ~0 -- touchActivity should have fired for a request that actually reached mux", got)
	}
}
