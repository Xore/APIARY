package main

import (
	"bytes"
	"encoding/json"
	"errors"
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

func serveWhoAmI(w http.ResponseWriter, r *http.Request) {
	identity, err := resolveIdentity(r)
	if err != nil {
		if errors.Is(err, errIdentityUnavailable) {
			http.Error(w, "identity service unavailable", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "authentication required", http.StatusUnauthorized)
		}
		return
	}
	capabilities := []string{"preferences:write", "evidence:read"}
	if identity.Role == "admin" {
		capabilities = append(capabilities, "configuration:write", "evidence:admin")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(whoAmIResponse{
		authenticatedIdentity: identity,
		Capabilities:          capabilities,
		AuthAccountURL:        strings.TrimSpace(os.Getenv("AUTH_ACCOUNT_URL")),
	})
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
