package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRetentionSweepExpiresOrphanedPreferences proves the Milestone F
// deletion behavior: once an auth account stops producing activity (deleted
// or disabled upstream), its dashboard projection and preferences expire
// through the retention sweep, with an audit record per removal.
func TestRetentionSweepExpiresOrphanedPreferences(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	s.serveWhoAmI(httptest.NewRecorder(), settingsRequest(t, http.MethodGet, "/api/whoami", false, ""))
	// Give the projection a non-default preference so the sweep visibly
	// removes stored state, then age it beyond the retention window.
	if _, err := s.settings.users.UpdatePreferences(
		authenticatedIdentity{Subject: "b65ab0dc-cc07-4b3d-9af0-b482dbb4b096", Username: "analyst", Role: "admin"},
		"", "", "", func(p *userPreferences) error { p.Theme = "light"; return nil }); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.settings.users.inner.Update("", func(doc *usersDocument) error {
		for i := range doc.Users {
			doc.Users[i].LastSeen = time.Now().UTC().Add(-100 * 24 * time.Hour)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	removed := s.settings.users.SweepRetention(time.Now().UTC(), 90*24*time.Hour)
	if removed != 1 {
		t.Fatalf("sweep removed %d projections, want 1", removed)
	}
	if _, _, found := s.settings.users.Preferences("b65ab0dc-cc07-4b3d-9af0-b482dbb4b096"); found {
		t.Fatal("orphaned preferences must expire with their projection")
	}
	events := s.settings.audit.read(10)
	if len(events) == 0 || events[0].Action != "users.retention" ||
		!containsString(events[0].Fields, "b65ab0dc-cc07-4b3d-9af0-b482dbb4b096") {
		t.Fatalf("retention must audit the removed subject: %#v", events)
	}

	// A second sweep over a fresh projection removes nothing and audits nothing.
	s.serveWhoAmI(httptest.NewRecorder(), settingsRequest(t, http.MethodGet, "/api/whoami", false, ""))
	before := len(s.settings.audit.read(50))
	if removed := s.settings.users.SweepRetention(time.Now().UTC(), 90*24*time.Hour); removed != 0 {
		t.Fatalf("fresh projections must survive the sweep, removed %d", removed)
	}
	if len(s.settings.audit.read(50)) != before {
		t.Fatal("an empty sweep must not write audit records")
	}
}

// TestRevokedOIDCSessionLosesAccessImmediately proves that deleting the
// server-side Keycloak session projection denies every settings API.
func TestRevokedOIDCSessionLosesAccessImmediately(t *testing.T) {
	previous := dashboardOIDC
	dashboardOIDC = &oidcAuth{sessions: &memorySessionStore{values: make(map[string][]byte)}, now: time.Now}
	t.Cleanup(func() { dashboardOIDC = previous })

	s := newSettingsAPITestStoreWithoutIdentity(t)
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/api/settings/me"},
		{http.MethodPatch, "/api/settings/me/preferences"},
		{http.MethodGet, "/api/settings/config"},
		{http.MethodGet, "/api/settings/users"},
		{http.MethodGet, "/api/settings/audit"},
	} {
		request := settingsRequest(t, tc.method, tc.target, true, `{}`)
		response := httptest.NewRecorder()
		switch tc.target {
		case "/api/settings/me":
			s.serveSettingsMe(response, request)
		case "/api/settings/me/preferences":
			s.servePreferencesPatch(response, request)
		case "/api/settings/config":
			s.serveSettingsConfig(response, request)
		case "/api/settings/users":
			s.serveSettingsUsers(response, request)
		case "/api/settings/audit":
			s.serveSettingsAudit(response, request)
		}
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s after introspection rejection: status = %d, want 401", tc.method, tc.target, response.Code)
		}
	}
}

// TestDashboardNeverProxiesCredentialActions pins the Keycloak credential
// boundary: the dashboard links out and never embeds or proxies credentials.
func TestDashboardNeverProxiesCredentialActions(t *testing.T) {
	sources := map[string]string{
		"static/hp-settings.js":   mustReadStatic(t, "static/hp-settings.js"),
		"static/hp-account.js":    mustReadStatic(t, "static/hp-account.js"),
		"partials/dashboard.html": mustReadUI("partials/dashboard.html"),
	}
	for name, src := range sources {
		for _, forbidden := range []string{"/_auth/", "xore-auth-app", "data-hp-settings-frame"} {
			if strings.Contains(src, forbidden) {
				t.Fatalf("%s retains legacy credential integration %q", name, forbidden)
			}
		}
	}
	js := sources["static/hp-settings.js"]
	for _, action := range []string{"actions.profile", "actions.security", "actions.sessions", "account_actions?.manage_users"} {
		if !strings.Contains(js, action) {
			t.Fatalf("Keycloak account action %s missing", action)
		}
	}
}

func mustReadStatic(t *testing.T, name string) string {
	t.Helper()
	data, err := staticAssets.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestAccountPaneRendersDeepLinks asserts the account pane carries server-
// supplied Keycloak action slots, hidden until identity resolves them.
func TestAccountPaneRendersDeepLinks(t *testing.T) {
	html := renderSettings(t, false)
	for _, pane := range []string{"account", "passkeys", "privacy", "sessions"} {
		if !strings.Contains(html, `data-hp-acct-deep="`+pane+`"`) {
			t.Fatalf("account pane missing deep link to auth pane %q", pane)
		}
	}
	admin := renderSettings(t, true)
	if !strings.Contains(admin, `data-hp-users-admin-link`) {
		t.Fatal("admin users pane must expose the server-supplied Keycloak users link")
	}
}

// newSettingsAPITestStoreWithoutIdentity builds a settings store against the
// currently configured (rejecting) introspection backend. Every caller of
// this helper only exercises auth-rejection paths (requests denied before
// ever reaching the settings store itself), so a nil Elasticsearch client
// is sufficient -- unlike newSettingsAPITestStore, which needs a real
// backing store for actual CRUD.
func newSettingsAPITestStoreWithoutIdentity(t *testing.T) *store {
	t.Helper()
	dir := t.TempDir()
	return &store{settings: newSettingsService(
		nil,
		filepath.Join(dir, "audit.jsonl"),
		filepath.Join(dir, "history.jsonl"),
	)}
}
