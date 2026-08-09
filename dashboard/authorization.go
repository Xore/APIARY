package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	errIdentityUnavailable  = errors.New("identity service unavailable")
	errIdentityUnauthorized = errors.New("authenticated identity required")
	dashboardOIDC           *oidcAuth
)

type identityContextKey struct{}

type authenticatedIdentity struct {
	Subject     string `json:"subject"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	Generation  int    `json:"generation"`
}

type whoAmIResponse struct {
	authenticatedIdentity
	Capabilities   []string       `json:"capabilities"`
	AccountActions accountActions `json:"account_actions"`
}

type accountActions struct {
	ManageAccount string `json:"manage_account,omitempty"`
	Profile       string `json:"profile,omitempty"`
	Security      string `json:"security,omitempty"`
	Sessions      string `json:"sessions,omitempty"`
	Logout        string `json:"logout"`
	ManageUsers   string `json:"manage_users,omitempty"`
}

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

func capabilitiesFor(role string) []string {
	capabilities := []string{"preferences:write", "evidence:read"}
	if role == "admin" {
		capabilities = append(capabilities, "configuration:write", "evidence:admin")
	}
	return capabilities
}

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
		config, _ := s.settings.config.Get()
		s.settings.users.Upsert(identity, config.Behavior.DefaultTimezone)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(whoAmIResponse{
		authenticatedIdentity: identity,
		Capabilities:          capabilitiesFor(identity.Role),
		AccountActions:        keycloakAccountActions(s.authAccountURL, identity.Role, s.authAdminURL),
	})
}

func keycloakAccountActions(accountURL, role, adminURL string) accountActions {
	actions := accountActions{Logout: "/auth/logout"}
	if accountURL == "" {
		return actions
	}
	base := strings.TrimSuffix(accountURL, "/") + "/"
	actions.ManageAccount = base
	actions.Profile = base + "#/personal-info"
	actions.Security = base + "#/security/signingin"
	actions.Sessions = base + "#/security/device-activity"
	if role == "admin" && adminURL != "" {
		actions.ManageUsers = strings.TrimSuffix(adminURL, "/") + "/#/apiary/users"
	}
	return actions
}

func validatedExternalURL(name string) string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return ""
	}
	if err := validateHTTPSURL(raw); err != nil {
		fmt.Fprintf(os.Stderr, "dashboard: %s is not a valid HTTPS URL; the related account action will stay hidden\n", name)
		return ""
	}
	return raw
}

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
	issuer, err := url.Parse(strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")))
	if err != nil || issuer.Hostname() == "" {
		fmt.Fprintln(os.Stderr, "dashboard: AUTH_ACCOUNT_URL is set but OIDC_ISSUER_URL is unusable; the settings menu item will stay hidden")
		return ""
	}
	if !strings.EqualFold(accountURL.Hostname(), issuer.Hostname()) {
		fmt.Fprintf(os.Stderr, "dashboard: AUTH_ACCOUNT_URL host %q does not match OIDC issuer host %q; the settings menu item will stay hidden\n", accountURL.Hostname(), issuer.Hostname())
		return ""
	}
	return raw
}

func resolveIdentity(r *http.Request) (authenticatedIdentity, error) {
	if identity, ok := r.Context().Value(identityContextKey{}).(authenticatedIdentity); ok {
		return identity, nil
	}
	if dashboardOIDC == nil {
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	return dashboardOIDC.identityFromRequest(r)
}

func withIdentity(r *http.Request, identity authenticatedIdentity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityContextKey{}, identity))
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
