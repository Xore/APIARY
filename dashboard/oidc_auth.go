package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

const (
	oidcSessionCookie = "__Host-apiary_session"
	oidcStateCookie   = "__Host-apiary_oidc"
	oidcClientID      = "apiary-dashboard"
	oidcSessionMaxAge = 12 * time.Hour
	oidcStateMaxAge   = 10 * time.Minute
)

var errSessionNotFound = errors.New("OIDC session not found")

type sessionStore interface {
	Get(context.Context, string) ([]byte, error)
	Set(context.Context, string, []byte, time.Duration) error
	Delete(context.Context, string) error
}

type redisSessionStore struct{ client *redis.Client }

func (s redisSessionStore) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, errSessionNotFound
	}
	return value, err
}

func (s redisSessionStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl).Err()
}

func (s redisSessionStore) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

type oidcAuth struct {
	provider              *oidc.Provider
	verifier              *oidc.IDTokenVerifier
	oauth2                oauth2.Config
	sessions              sessionStore
	introspectionEndpoint string
	endSessionEndpoint    string
	externalURL           string
	clientSecret          string
	httpClient            *http.Client
	now                   func() time.Time
}

type oidcSession struct {
	Identity      authenticatedIdentity `json:"identity"`
	AccessToken   string                `json:"access_token"`
	RefreshToken  string                `json:"refresh_token"`
	TokenType     string                `json:"token_type"`
	IDToken       string                `json:"id_token"`
	TokenExpiry   time.Time             `json:"token_expiry"`
	CreatedAt     time.Time             `json:"created_at"`
	LastValidated time.Time             `json:"last_validated"`
}

type oidcAttempt struct {
	Binding      string    `json:"binding"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	ReturnTo     string    `json:"return_to"`
	CreatedAt    time.Time `json:"created_at"`
}

type keycloakClaims struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Nonce             string `json:"nonce"`
	AuthorizedParty   string `json:"azp"`
	ResourceAccess    map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

type providerMetadata struct {
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func newOIDCAuth(ctx context.Context) (*oidcAuth, error) {
	issuer := strings.TrimRight(strings.TrimSpace(envRequired("OIDC_ISSUER_URL")), "/")
	externalURL := strings.TrimRight(strings.TrimSpace(envRequired("OIDC_EXTERNAL_URL")), "/")
	clientSecret, err := secretFromEnvironment("OIDC_CLIENT_SECRET")
	if err != nil || len(clientSecret) < 32 {
		return nil, errors.New("OIDC_CLIENT_SECRET(_FILE) must contain at least 32 characters")
	}
	redisURL := strings.TrimSpace(envRequired("OIDC_SESSION_REDIS_URL"))
	if issuer == "" || externalURL == "" || redisURL == "" {
		return nil, errors.New("OIDC_ISSUER_URL, OIDC_EXTERNAL_URL, and OIDC_SESSION_REDIS_URL are required")
	}
	if err := validateHTTPSURL(issuer); err != nil {
		return nil, fmt.Errorf("OIDC_ISSUER_URL: %w", err)
	}
	if err := validateHTTPSURL(externalURL); err != nil {
		return nil, fmt.Errorf("OIDC_EXTERNAL_URL: %w", err)
	}
	redisOptions, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC_SESSION_REDIS_URL: %w", err)
	}
	redisClient := redis.NewClient(redisOptions)
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		return nil, fmt.Errorf("OIDC session store unavailable: %w", err)
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	providerCtx := oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(providerCtx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	var metadata providerMetadata
	if err := provider.Claims(&metadata); err != nil || metadata.IntrospectionEndpoint == "" || metadata.EndSessionEndpoint == "" {
		return nil, errors.New("OIDC discovery lacks introspection or end-session endpoint")
	}
	auth := &oidcAuth{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: oidcClientID}),
		oauth2: oauth2.Config{
			ClientID:     oidcClientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  externalURL + "/auth/callback",
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},
		},
		sessions:              redisSessionStore{client: redisClient},
		introspectionEndpoint: metadata.IntrospectionEndpoint,
		endSessionEndpoint:    metadata.EndSessionEndpoint,
		externalURL:           externalURL,
		clientSecret:          clientSecret,
		httpClient:            httpClient,
		now:                   time.Now,
	}
	return auth, nil
}

func envRequired(name string) string { return strings.TrimSpace(getenv(name, "")) }

func validateHTTPSURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" {
		return errors.New("invalid URL")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return errors.New("HTTPS is required")
	}
	return nil
}

func (a *oidcAuth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/auth/login", "/auth/callback", "/auth/logout":
			next.ServeHTTP(w, r)
			return
		}
		identity, err := a.identityFromRequest(r)
		if err == nil {
			next.ServeHTTP(w, withIdentity(r, identity))
			return
		}
		if errors.Is(err, errIdentityUnavailable) {
			http.Error(w, "identity service unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			returnTo := r.URL.RequestURI()
			http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(returnTo), http.StatusSeeOther)
			return
		}
		http.Error(w, "authentication required", http.StatusUnauthorized)
	})
}

func (a *oidcAuth) serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "login unavailable", http.StatusServiceUnavailable)
		return
	}
	binding, _ := randomToken(32)
	nonce, _ := randomToken(32)
	verifier, _ := randomToken(32)
	attempt := oidcAttempt{Binding: binding, Nonce: nonce, CodeVerifier: verifier, ReturnTo: safeReturnTo(r.URL.Query().Get("return_to")), CreatedAt: a.now().UTC()}
	if err := a.putJSON(r.Context(), "oidc:state:"+state, attempt, oidcStateMaxAge); err != nil {
		http.Error(w, "login unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, secureCookie(oidcStateCookie, binding, oidcStateMaxAge))
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	destination := a.oauth2.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.S256ChallengeOption(challenge))
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

func (a *oidcAuth) serveCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Query().Get("code") == "" || r.URL.Query().Get("state") == "" {
		http.Error(w, "invalid OIDC callback", http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	var attempt oidcAttempt
	if err := a.getJSON(r.Context(), "oidc:state:"+state, &attempt); err != nil {
		http.Error(w, "expired or invalid OIDC state", http.StatusBadRequest)
		return
	}
	_ = a.sessions.Delete(r.Context(), "oidc:state:"+state)
	binding, err := r.Cookie(oidcStateCookie)
	clearCookie(w, oidcStateCookie)
	if err != nil || binding.Value == "" || binding.Value != attempt.Binding || a.now().Sub(attempt.CreatedAt) > oidcStateMaxAge {
		http.Error(w, "invalid OIDC browser binding", http.StatusBadRequest)
		return
	}
	token, err := a.oauth2.Exchange(oidc.ClientContext(r.Context(), a.httpClient), r.URL.Query().Get("code"), oauth2.VerifierOption(attempt.CodeVerifier))
	if err != nil {
		http.Error(w, "OIDC code exchange failed", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "OIDC response omitted ID token", http.StatusUnauthorized)
		return
	}
	identity, idToken, err := a.verifyIDToken(r.Context(), rawIDToken, attempt.Nonce)
	if err != nil {
		http.Error(w, "invalid OIDC identity", http.StatusUnauthorized)
		return
	}
	sessionID, _ := randomToken(32)
	now := a.now().UTC()
	session := oidcSession{Identity: identity, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, TokenType: token.TokenType, IDToken: rawIDToken, TokenExpiry: idToken.Expiry, CreatedAt: now, LastValidated: now}
	if err := a.putJSON(r.Context(), "oidc:session:"+sessionID, session, oidcSessionMaxAge); err != nil {
		http.Error(w, "session store unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, secureCookie(oidcSessionCookie, sessionID, oidcSessionMaxAge))
	http.Redirect(w, r, attempt.ReturnTo, http.StatusSeeOther)
}

func (a *oidcAuth) serveLogout(w http.ResponseWriter, r *http.Request) {
	var idToken string
	if cookie, err := r.Cookie(oidcSessionCookie); err == nil && cookie.Value != "" {
		var session oidcSession
		if a.getJSON(r.Context(), "oidc:session:"+cookie.Value, &session) == nil {
			idToken = session.IDToken
		}
		_ = a.sessions.Delete(r.Context(), "oidc:session:"+cookie.Value)
	}
	clearCookie(w, oidcSessionCookie)
	query := url.Values{"post_logout_redirect_uri": {a.externalURL + "/"}, "client_id": {oidcClientID}}
	if idToken != "" {
		query.Set("id_token_hint", idToken)
	}
	http.Redirect(w, r, a.endSessionEndpoint+"?"+query.Encode(), http.StatusSeeOther)
}

func (a *oidcAuth) identityFromRequest(r *http.Request) (authenticatedIdentity, error) {
	cookie, err := r.Cookie(oidcSessionCookie)
	if err != nil || cookie.Value == "" {
		return authenticatedIdentity{}, errIdentityUnauthorized
	}
	var session oidcSession
	if err := a.getJSON(r.Context(), "oidc:session:"+cookie.Value, &session); err != nil {
		if errors.Is(err, errSessionNotFound) {
			return authenticatedIdentity{}, errIdentityUnauthorized
		}
		return authenticatedIdentity{}, errIdentityUnavailable
	}
	now := a.now().UTC()
	if now.Sub(session.CreatedAt) > oidcSessionMaxAge || !validSubject(session.Identity.Subject) {
		_ = a.sessions.Delete(r.Context(), "oidc:session:"+cookie.Value)
		return authenticatedIdentity{}, errIdentityUnauthorized
	}
	changed := false
	if now.Add(time.Minute).After(session.TokenExpiry) {
		if err := a.refreshSession(r.Context(), &session); err != nil {
			_ = a.sessions.Delete(r.Context(), "oidc:session:"+cookie.Value)
			return authenticatedIdentity{}, errIdentityUnauthorized
		}
		changed = true
	}
	if now.Sub(session.LastValidated) >= 30*time.Second {
		if err := a.introspect(r.Context(), session.AccessToken, session.Identity.Subject); err != nil {
			if errors.Is(err, errIdentityUnauthorized) {
				_ = a.sessions.Delete(r.Context(), "oidc:session:"+cookie.Value)
			}
			return authenticatedIdentity{}, err
		}
		session.LastValidated = now
		changed = true
	}
	if changed {
		remaining := oidcSessionMaxAge - now.Sub(session.CreatedAt)
		if err := a.putJSON(r.Context(), "oidc:session:"+cookie.Value, session, remaining); err != nil {
			return authenticatedIdentity{}, errIdentityUnavailable
		}
	}
	return session.Identity, nil
}

func (a *oidcAuth) verifyIDToken(ctx context.Context, raw, nonce string) (authenticatedIdentity, *oidc.IDToken, error) {
	idToken, err := a.verifier.Verify(oidc.ClientContext(ctx, a.httpClient), raw)
	if err != nil {
		return authenticatedIdentity{}, nil, err
	}
	var claims keycloakClaims
	if err := idToken.Claims(&claims); err != nil || claims.Nonce != nonce || (claims.AuthorizedParty != "" && claims.AuthorizedParty != oidcClientID) {
		return authenticatedIdentity{}, nil, errors.New("invalid OIDC claims")
	}
	if !validSubject(claims.Subject) || strings.TrimSpace(claims.PreferredUsername) == "" {
		return authenticatedIdentity{}, nil, errors.New("missing stable identity")
	}
	roles := claims.ResourceAccess[oidcClientID].Roles
	if !containsString(roles, "access") {
		return authenticatedIdentity{}, nil, errors.New("dashboard access role missing")
	}
	role := "user"
	if containsString(roles, "admin") {
		role = "admin"
	}
	return authenticatedIdentity{Subject: claims.Subject, Username: claims.PreferredUsername, DisplayName: claims.Name, Role: role}, idToken, nil
}

func (a *oidcAuth) refreshSession(ctx context.Context, session *oidcSession) error {
	old := &oauth2.Token{AccessToken: session.AccessToken, RefreshToken: session.RefreshToken, TokenType: session.TokenType, Expiry: session.TokenExpiry}
	token, err := a.oauth2.TokenSource(oidc.ClientContext(ctx, a.httpClient), old).Token()
	if err != nil {
		return err
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return errors.New("refresh response omitted ID token")
	}
	identity, idToken, err := a.verifyIDToken(ctx, rawIDToken, "")
	if err != nil {
		// Refreshed ID tokens normally omit nonce. Verify again through the same
		// verifier and validate the remaining claims explicitly.
		verified, verifyErr := a.verifier.Verify(oidc.ClientContext(ctx, a.httpClient), rawIDToken)
		if verifyErr != nil {
			return err
		}
		var claims keycloakClaims
		if verified.Claims(&claims) != nil || claims.Subject != session.Identity.Subject ||
			(claims.AuthorizedParty != "" && claims.AuthorizedParty != oidcClientID) || !containsString(claims.ResourceAccess[oidcClientID].Roles, "access") {
			return errors.New("invalid refreshed identity")
		}
		role := "user"
		if containsString(claims.ResourceAccess[oidcClientID].Roles, "admin") {
			role = "admin"
		}
		identity = authenticatedIdentity{Subject: claims.Subject, Username: claims.PreferredUsername, DisplayName: claims.Name, Role: role}
		idToken = verified
	}
	session.Identity = identity
	session.AccessToken = token.AccessToken
	session.RefreshToken = token.RefreshToken
	session.TokenType = token.TokenType
	session.IDToken = rawIDToken
	session.TokenExpiry = idToken.Expiry
	return nil
}

func (a *oidcAuth) introspect(ctx context.Context, accessToken, subject string) error {
	form := url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.introspectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errIdentityUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(oidcClientID, a.clientSecret)
	response, err := a.httpClient.Do(request)
	if err != nil {
		return errIdentityUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errIdentityUnavailable
	}
	var result struct {
		Active   bool   `json:"active"`
		Subject  string `json:"sub"`
		ClientID string `json:"client_id"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 8192))
	if err := decoder.Decode(&result); err != nil {
		return errIdentityUnavailable
	}
	if !result.Active || result.Subject != subject || result.ClientID != oidcClientID {
		return errIdentityUnauthorized
	}
	return nil
}

func (a *oidcAuth) getJSON(ctx context.Context, key string, target any) error {
	raw, err := a.sessions.Get(ctx, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

func (a *oidcAuth) putJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return a.sessions.Set(ctx, key, raw, ttl)
}

func randomToken(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func safeReturnTo(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || parsed.IsAbs() || parsed.Host != "" {
		return "/"
	}
	return parsed.RequestURI()
}

func secureCookie(name, value string, age time.Duration) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(age.Seconds())}
}

func clearCookie(w http.ResponseWriter, name string) {
	cookie := secureCookie(name, "", -time.Hour)
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
