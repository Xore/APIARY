package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const testAuthCookie = "test-session"

type memorySessionStore struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (s *memorySessionStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[key]
	if !ok {
		return nil, errSessionNotFound
	}
	return append([]byte(nil), value...), nil
}

func (s *memorySessionStore) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = append([]byte(nil), value...)
	return nil
}

func (s *memorySessionStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	return nil
}

func configureIdentityTestBackend(t *testing.T, role string) {
	t.Helper()
	store := &memorySessionStore{values: make(map[string][]byte)}
	now := time.Now().UTC()
	auth := &oidcAuth{sessions: store, now: func() time.Time { return now }}
	session := oidcSession{
		Identity:    authenticatedIdentity{Subject: "b65ab0dc-cc07-4b3d-9af0-b482dbb4b096", Username: "analyst", DisplayName: "Analyst", Role: role},
		TokenExpiry: now.Add(time.Hour), CreatedAt: now, LastValidated: now,
	}
	if err := auth.putJSON(context.Background(), "oidc:session:"+testAuthCookie, session, time.Hour); err != nil {
		t.Fatal(err)
	}
	previous := dashboardOIDC
	dashboardOIDC = auth
	t.Cleanup(func() { dashboardOIDC = previous })
}

func addIdentityTestCookie(request *http.Request) {
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: testAuthCookie})
}

func TestRequireAdminUsesOIDCSessionAndIgnoresForgedRoleHeader(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "user")

	request := httptest.NewRequest(http.MethodGet, "/payload/hash", nil)
	request.Header.Set("X-Auth-Role", "admin")
	addIdentityTestCookie(request)
	denied := httptest.NewRecorder()
	if requireAdmin(denied, request) {
		t.Fatal("forged admin header overrode the authoritative user role")
	}
	if denied.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", denied.Code, http.StatusForbidden)
	}
}

func TestRequireAdminAcceptsCurrentOIDCRole(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	request := httptest.NewRequest(http.MethodGet, "/payload/hash", nil)
	request.Header.Set("X-Auth-Role", "user")
	addIdentityTestCookie(request)
	if !requireAdmin(httptest.NewRecorder(), request) {
		t.Fatal("current Keycloak administrator was denied")
	}
}

func TestRequireAdminFailsClosedWithoutIdentityService(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	previous := dashboardOIDC
	dashboardOIDC = nil
	t.Cleanup(func() { dashboardOIDC = previous })
	request := httptest.NewRequest(http.MethodGet, "/payload/hash", nil)
	request.Header.Set("X-Auth-Role", "admin")
	denied := httptest.NewRecorder()
	if requireAdmin(denied, request) {
		t.Fatal("unsigned admin header was accepted without identity service")
	}
	if denied.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", denied.Code, http.StatusServiceUnavailable)
	}
}

func TestWhoAmIReturnsStableSubjectAndCapabilities(t *testing.T) {
	configureIdentityTestBackend(t, "admin")
	request := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	addIdentityTestCookie(request)
	response := httptest.NewRecorder()
	(&store{}).serveWhoAmI(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var identity whoAmIResponse
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		t.Fatal(err)
	}
	if identity.Subject == "" || identity.Username != "analyst" || identity.Role != "admin" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if !containsString(identity.Capabilities, "configuration:write") {
		t.Fatalf("admin capabilities missing configuration write: %#v", identity.Capabilities)
	}
}

func TestValidatedAuthAccountURLAcceptsMatchingAuthOrigin(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "https://auth.honeypot.example/realms/apiary")
	t.Setenv("AUTH_ACCOUNT_URL", "https://auth.honeypot.example/realms/apiary/account/")
	if got := validatedAuthAccountURL(); got != "https://auth.honeypot.example/realms/apiary/account/" {
		t.Fatalf("validatedAuthAccountURL() = %q, want the configured URL unchanged", got)
	}
}

func TestValidatedAuthAccountURLEmptyWhenUnset(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "https://auth.honeypot.example/realms/apiary")
	t.Setenv("AUTH_ACCOUNT_URL", "")
	if got := validatedAuthAccountURL(); got != "" {
		t.Fatalf("validatedAuthAccountURL() = %q, want empty (unconfigured settings iframe)", got)
	}
}

// A malformed AUTH_ACCOUNT_URL must never reach the browser: it would open
// the settings modal onto a blank iframe with nothing but the browser
// console to explain why (issue #93). It must be rejected here instead.
func TestValidatedAuthAccountURLRejectsNonHTTPSScheme(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "https://auth.honeypot.example/realms/apiary")
	t.Setenv("AUTH_ACCOUNT_URL", "http://auth.honeypot.example/auth/app")
	if got := validatedAuthAccountURL(); got != "" {
		t.Fatalf("validatedAuthAccountURL() = %q, want empty for a non-HTTPS non-loopback URL", got)
	}
}

func TestValidatedAuthAccountURLRejectsUnparseableURL(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "https://auth.honeypot.example/realms/apiary")
	t.Setenv("AUTH_ACCOUNT_URL", "://not a url")
	if got := validatedAuthAccountURL(); got != "" {
		t.Fatalf("validatedAuthAccountURL() = %q, want empty for an unparseable URL", got)
	}
}

func TestValidatedAuthAccountURLRejectsHostMismatch(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "https://auth.honeypot.example/realms/apiary")
	t.Setenv("AUTH_ACCOUNT_URL", "https://attacker.example/auth/app")
	if got := validatedAuthAccountURL(); got != "" {
		t.Fatalf("validatedAuthAccountURL() = %q, want empty when the account URL host does not match the auth origin", got)
	}
}

func TestValidatedAuthAccountURLRejectsWithoutIntrospectionURL(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "")
	t.Setenv("AUTH_ACCOUNT_URL", "https://auth.honeypot.example/auth/app")
	if got := validatedAuthAccountURL(); got != "" {
		t.Fatalf("validatedAuthAccountURL() = %q, want empty when the auth origin cannot be confirmed", got)
	}
}

func TestWhoAmIExposesKeycloakActionsWithoutFraming(t *testing.T) {
	for _, role := range []string{"user", "admin"} {
		t.Run(role, func(t *testing.T) {
			configureIdentityTestBackend(t, role)
			t.Setenv("OIDC_ISSUER_URL", "https://auth.honeypot.example/realms/apiary")
			t.Setenv("AUTH_ACCOUNT_URL", "https://auth.honeypot.example/realms/apiary/account/")
			s := &store{authAccountURL: validatedAuthAccountURL(), authAdminURL: "https://auth.honeypot.example/admin/apiary/console/"}
			if s.authAccountURL == "" {
				t.Fatal("validatedAuthAccountURL rejected a well-formed, matching-origin URL")
			}

			request := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
			addIdentityTestCookie(request)
			response := httptest.NewRecorder()
			s.serveWhoAmI(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			var identity whoAmIResponse
			if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
				t.Fatal(err)
			}
			if identity.Role != role {
				t.Fatalf("role = %q, want %q", identity.Role, role)
			}
			if identity.AccountActions.ManageAccount == "" || identity.AccountActions.Logout != "/auth/logout" {
				t.Fatalf("whoami omitted Keycloak account actions for role %q: %#v", role, identity.AccountActions)
			}
			if (role == "admin") != (identity.AccountActions.ManageUsers != "") {
				t.Fatalf("manage_users role exposure mismatch for %q: %#v", role, identity.AccountActions)
			}
		})
	}
}

func TestAccountMenuUsesTopLevelKeycloakActions(t *testing.T) {
	data, err := staticAssets.ReadFile("static/hp-account.js")
	if err != nil {
		t.Fatal("static/hp-account.js must be embedded with the dashboard assets")
	}
	js := string(data)
	for _, want := range []string{"/api/whoami", "identity.account_actions", "actions.manage_account", `actions.logout || "/auth/logout"`} {
		if !strings.Contains(js, want) {
			t.Fatalf("hp-account.js missing postMessage contract behavior %q", want)
		}
	}
	for _, forbidden := range []string{"iframe", "xore-auth-app", "/_auth/logout", `addEventListener("message"`} {
		if strings.Contains(js, forbidden) {
			t.Fatalf("hp-account.js retains legacy embedded-auth contract %q", forbidden)
		}
	}
}

// #1015: this only asserts the legacy forward-auth middleware chain is gone
// (true today) -- it does NOT assert the router's service target, see
// TestDashboardTraefikRouteUsesNativeOIDCService below for that. The
// original name of this test claimed more than it checked; renamed to
// describe only what it verifies.
func TestDashboardTraefikRouteHasNoForwardAuthMiddleware(t *testing.T) {
	router := dashboardTraefikRouterBlock(t)
	if strings.Contains(router, "forward-auth") || strings.Contains(router, "strip-auth-identity") ||
		!strings.Contains(router, "middlewares: [security-headers]") {
		t.Fatalf("dashboard router still has legacy forward-auth middleware wired in:\n%s", router)
	}
}

// #1015 / #1026: production dashboard hostnames targeted the oidc-dashboard
// compatibility gateway until #1026's cutover flipped this router to the
// native-OIDC honeypot-dashboard service (both replicas verified live:
// direct unauthenticated access now redirects to /auth/login instead of
// serving full content). Asserts the new state so a future regression back
// to the compatibility gateway fails loudly here instead of silently.
func TestDashboardTraefikRouteUsesNativeOIDCService(t *testing.T) {
	router := dashboardTraefikRouterBlock(t)
	if !strings.Contains(router, "service: honeypot-dashboard") {
		t.Fatalf("dashboard router no longer targets the native-OIDC honeypot-dashboard service:\n%s", router)
	}
	if strings.Contains(router, "service: oidc-dashboard") {
		t.Fatalf("dashboard router still targets the retired oidc-dashboard compatibility gateway:\n%s", router)
	}
}

func dashboardTraefikRouterBlock(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../vps/traefik/dynamic.yml")
	if err != nil {
		t.Fatal(err)
	}
	config := string(raw)
	start := strings.Index(config, "    honeypot-dashboard:\n")
	if start < 0 {
		t.Fatal("dashboard router missing")
	}
	end := strings.Index(config[start+1:], "\n    honeypot-kibana:")
	if end < 0 {
		t.Fatal("dashboard router boundary missing")
	}
	return config[start : start+1+end]
}
