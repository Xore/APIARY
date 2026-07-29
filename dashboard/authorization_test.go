package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const testAuthCookie = "test-session"

func configureIdentityTestBackend(t *testing.T, role string) {
	t.Helper()
	token := strings.Repeat("t", 32)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("xore_sso")
		if r.Method != http.MethodPost ||
			r.Header.Get("Authorization") != "Bearer "+token ||
			err != nil || cookie.Value != testAuthCookie {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request identityRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.TargetHost != "honeypot.example" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authenticatedIdentity{
			Subject:  "b65ab0dc-cc07-4b3d-9af0-b482dbb4b096",
			Username: "analyst", DisplayName: "Analyst", Role: role, Generation: 3,
		})
	}))
	t.Cleanup(backend.Close)
	t.Setenv("AUTH_INTROSPECTION_URL", backend.URL)
	t.Setenv("AUTH_INTROSPECTION_TOKEN", token)
	t.Setenv("AUTH_TARGET_HOST", "honeypot.example")
	t.Setenv("AUTH_SESSION_COOKIE_NAME", "xore_sso")
}

func addIdentityTestCookie(request *http.Request) {
	request.AddCookie(&http.Cookie{Name: "xore_sso", Value: testAuthCookie})
}

func TestRequireAdminUsesIntrospectionAndIgnoresForgedRoleHeader(t *testing.T) {
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

func TestRequireAdminAcceptsCurrentBackendRole(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	request := httptest.NewRequest(http.MethodGet, "/payload/hash", nil)
	request.Header.Set("X-Auth-Role", "user")
	addIdentityTestCookie(request)
	if !requireAdmin(httptest.NewRecorder(), request) {
		t.Fatal("current auth-backend administrator was denied")
	}
}

func TestRequireAdminFailsClosedWithoutIdentityService(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	t.Setenv("AUTH_INTROSPECTION_URL", "")
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

func TestTraefikStripsClientIdentityHeadersAndDoesNotForwardRole(t *testing.T) {
	raw, err := os.ReadFile("../vps/traefik/dynamic.yml")
	if err != nil {
		t.Fatal(err)
	}
	config := string(raw)
	if !strings.Contains(config, "middlewares: [security-headers, strip-auth-identity, forward-auth]") ||
		!strings.Contains(config, "X-Auth-Role: \"\"") {
		t.Fatal("protected proxy routes do not strip client-supplied identity headers")
	}
	start := strings.Index(config, "authResponseHeaders:")
	if start < 0 {
		t.Fatal("forward-auth response-header configuration is missing")
	}
	responseHeaders := config[start:]
	if strings.Contains(responseHeaders, "- X-Auth-Role") {
		t.Fatal("Traefik still forwards X-Auth-Role as an upstream authorization hint")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
