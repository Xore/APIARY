package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	errIdentityUnavailable  = errors.New("identity service unavailable")
	errIdentityUnauthorized = errors.New("authenticated identity required")
)

type authenticatedIdentity struct {
	Subject     string `json:"subject"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	Generation  int    `json:"generation"`
}

type whoAmIResponse struct {
	authenticatedIdentity
	Capabilities   []string `json:"capabilities"`
	AuthAccountURL string   `json:"auth_account_url,omitempty"`
}

type identityRequest struct {
	TargetHost string `json:"target_host"`
}

// requireAdmin protects evidence-changing and raw-evidence operations. It
// deliberately ignores X-Auth-Role: callers can reach the dashboard on its
// internal WireGuard listener and could forge that header. The current browser
// session is re-validated by auth-backend on every privileged request.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("DASHBOARD_REQUIRE_ADMIN")), "true") {
		return true
	}
	identity, err := resolveIdentity(r)
	if err != nil {
		if errors.Is(err, errIdentityUnavailable) {
			http.Error(w, "authorization service unavailable", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "administrator role required", http.StatusForbidden)
		}
		return false
	}
	if identity.Role == "admin" {
		return true
	}
	http.Error(w, "administrator role required", http.StatusForbidden)
	return false
}

// capabilitiesFor maps a trusted role to dashboard capabilities. Capability
// lists are computed server-side only; client code never derives permission
// from a badge or a hidden control (roadmap §2).
func capabilitiesFor(role string) []string {
	capabilities := []string{"preferences:write", "evidence:read"}
	if role == "admin" {
		capabilities = append(capabilities, "configuration:write", "evidence:admin")
	}
	return capabilities
}

// requireIdentity is the identity middleware for the settings APIs added in
// Milestones C and E: it resolves the current session through live
// introspection and writes the error response on failure. Authorization
// beyond "any authenticated subject" (admin-only endpoints) additionally
// checks identity.Role at the call site.
func requireIdentity(w http.ResponseWriter, r *http.Request) (authenticatedIdentity, bool) {
	identity, err := resolveIdentity(r)
	if err != nil {
		if errors.Is(err, errIdentityUnavailable) {
			http.Error(w, "identity service unavailable", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "authentication required", http.StatusUnauthorized)
		}
		return authenticatedIdentity{}, false
	}
	return identity, true
}

// serveWhoAmI answers the current identity and refreshes the dashboard-owned
// user projection as a side effect. The projection is diagnostic and
// best-effort; a projection write failure must never break the identity
// response itself.
func (s *store) serveWhoAmI(w http.ResponseWriter, r *http.Request) {
	identity, err := resolveIdentity(r)
	if err != nil {
		if errors.Is(err, errIdentityUnavailable) {
			http.Error(w, "identity service unavailable", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "authentication required", http.StatusUnauthorized)
		}
		return
	}
	if s != nil && s.settings != nil {
		s.settings.users.Upsert(identity)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(whoAmIResponse{
		authenticatedIdentity: identity,
		Capabilities:          capabilitiesFor(identity.Role),
		AuthAccountURL:        s.authAccountURL,
	})
}

// validatedAuthAccountURL resolves and validates AUTH_ACCOUNT_URL once at
// startup. An unset value just leaves the settings menu item hidden
// (hp-account.js). A set-but-malformed one is worse: it reaches the browser
// as an opaque src, and the only symptom is a blank iframe inside the
// settings modal with nothing but the browser console to explain it — so a
// bad value is rejected here, loudly, before the server takes any traffic,
// instead of failing silently in front of whichever user opens Settings
// first (issue #93).
func validatedAuthAccountURL() string {
	raw := strings.TrimSpace(os.Getenv("AUTH_ACCOUNT_URL"))
	if raw == "" {
		return ""
	}
	accountURL, err := url.Parse(raw)
	if err != nil || accountURL.User != nil || accountURL.Fragment != "" || accountURL.Hostname() == "" ||
		(accountURL.Scheme != "https" && !(accountURL.Scheme == "http" && isLoopbackHost(accountURL.Hostname()))) {
		fmt.Fprintf(os.Stderr, "dashboard: AUTH_ACCOUNT_URL %q is not a valid HTTPS URL; the settings menu item will stay hidden\n", raw)
		return ""
	}
	introspection := strings.TrimSpace(os.Getenv("AUTH_INTROSPECTION_URL"))
	authOrigin, err := url.Parse(introspection)
	if introspection == "" || err != nil || authOrigin.Hostname() == "" {
		fmt.Fprintf(os.Stderr, "dashboard: AUTH_ACCOUNT_URL is set but AUTH_INTROSPECTION_URL is not a usable URL, so the auth origin cannot be confirmed; the settings menu item will stay hidden\n")
		return ""
	}
	if !strings.EqualFold(accountURL.Hostname(), authOrigin.Hostname()) {
		fmt.Fprintf(os.Stderr, "dashboard: AUTH_ACCOUNT_URL host %q does not match the AUTH_INTROSPECTION_URL auth origin %q; the settings menu item will stay hidden\n", accountURL.Hostname(), authOrigin.Hostname())
		return ""
	}
	return raw
}

func resolveIdentity(r *http.Request) (authenticatedIdentity, error) {
	endpoint := strings.TrimSpace(os.Getenv("AUTH_INTROSPECTION_URL"))
	token, err := secretFromEnvironment("AUTH_INTROSPECTION_TOKEN")
	targetHost := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_TARGET_HOST")))
	cookieName := strings.TrimSpace(os.Getenv("AUTH_SESSION_COOKIE_NAME"))
	if cookieName == "" {
		cookieName = "xore_sso"
	}
	if err != nil || endpoint == "" || len(token) < 32 || targetHost == "" {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()))) {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	sessionCookie, err := r.Cookie(cookieName)
	if err != nil || sessionCookie.Value == "" {
		return authenticatedIdentity{}, errIdentityUnauthorized
	}
	body, err := json.Marshal(identityRequest{TargetHost: targetHost})
	if err != nil {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", r.UserAgent())
	request.AddCookie(&http.Cookie{Name: cookieName, Value: sessionCookie.Value})
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return authenticatedIdentity{}, errIdentityUnauthorized
	}
	if response.StatusCode != http.StatusOK {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	if !strings.HasPrefix(contentType, "application/json") {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 8192))
	decoder.DisallowUnknownFields()
	var identity authenticatedIdentity
	if err := decoder.Decode(&identity); err != nil {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	if !validSubject(identity.Subject) || identity.Username == "" || identity.Generation < 1 ||
		(identity.Role != "admin" && identity.Role != "user") {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	return identity, nil
}

func secretFromEnvironment(name string) (string, error) {
	if path := strings.TrimSpace(os.Getenv(name + "_FILE")); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	return strings.TrimSpace(os.Getenv(name)), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validSubject(subject string) bool {
	if len(subject) < 16 || len(subject) > 128 {
		return false
	}
	for _, char := range subject {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}
