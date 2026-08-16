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

	// #1127: the refresh-token exchange below is serialized per session
	// with a short-lived lock, since Keycloak's refresh tokens here are
	// single-use (realm config: revokeRefreshToken=true,
	// refreshTokenMaxReuse=0). oidcRefreshLockTTL bounds how long a crashed
	// or hung lock-holder can block everyone else. oidcRefreshWaitTimeout
	// is how long a request that lost the race waits for the winner to
	// finish before giving up (transient 503, not a forced logout) --
	// generous enough for one real Keycloak round trip, short enough not
	// to stall a page load noticeably.
	oidcRefreshLockTTL = 15 * time.Second
)

// oidcRefreshWaitTimeout/oidcRefreshPollInterval are vars, not consts, so
// tests can shrink them -- the wait loop paces itself against real
// wall-clock time (below), deliberately not the mockable a.now() the rest
// of this file uses for session-expiry logic, since this is genuinely
// about how long to wait for another goroutine, not simulated session age.
var (
	oidcRefreshWaitTimeout  = 5 * time.Second
	oidcRefreshPollInterval = 100 * time.Millisecond
)

var (
	errSessionNotFound     = errors.New("OIDC session not found")
	errRefreshLockTimedOut = errors.New("timed out waiting for a concurrent token refresh to finish")
)

type sessionStore interface {
	Get(context.Context, string) ([]byte, error)
	Set(context.Context, string, []byte, time.Duration) error
	Delete(context.Context, string) error
	// TryLock atomically acquires a short-lived lock at key, returning
	// true only if this call acquired it (false if another holder already
	// has it -- not an error). Unlock releases it early; the TTL is the
	// backstop if a holder never calls Unlock (crash, context cancellation).
	TryLock(ctx context.Context, key string, ttl time.Duration) (bool, error)
	Unlock(ctx context.Context, key string) error
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

func (s redisSessionStore) TryLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return s.client.SetNX(ctx, key, "1", ttl).Result()
}

func (s redisSessionStore) Unlock(ctx context.Context, key string) error {
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
	endpoint := provider.Endpoint()
	// Left at the zero value (AuthStyleAutoDetect), golang.org/x/oauth2
	// probes which client-auth style the token endpoint wants: it tries
	// AuthStyleInHeader first, and on ANY failure blindly retries with
	// AuthStyleInParams using the same authorization code
	// (golang.org/x/oauth2/internal/token.go's RetrieveToken). Keycloak's
	// codes are single-use, so if the first attempt fails for any reason
	// at all, the "corrective" retry is guaranteed to fail too --
	// "invalid_grant: Code not valid" -- even though that second auth
	// style is the one Keycloak actually wants. Caught live: every real
	// login failed with exactly that error despite the client secret,
	// redirect_uri, and PKCE verifier all independently verified correct.
	// Pinning AuthStyleInParams (client_secret in the POST body, verified
	// working directly against this realm's token endpoint) skips the
	// probe entirely.
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	auth := &oidcAuth{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: oidcClientID}),
		oauth2: oauth2.Config{
			ClientID:     oidcClientID,
			ClientSecret: clientSecret,
			Endpoint:     endpoint,
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
		// #1255: static assets (CSS/JS/images/site.webmanifest) carry no
		// identity-bearing data, so there is no reason to gate them on
		// session validity at all -- doing so used to mean a session that
		// expired mid-page-view turned the browser's own background
		// manifest fetch into a redirect toward Keycloak's authorization
		// endpoint, which manifest-src/default-src then correctly blocked
		// as a cross-origin CSP violation instead of anything the user
		// could act on.
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		identity, err := a.identityFromRequest(r)
		if err == nil {
			// #1323: centralized here rather than per-handler -- every
			// authenticated response carries attacker/session data scoped
			// to this operator's own request, and the dashboard sits
			// behind Traefik and (per real deployments) shared browsers/
			// proxies where a cached copy could otherwise leak across
			// sessions or survive a logout. /healthz, /static/, and the
			// /auth/* flow above never reach this branch (no identity to
			// scope the response to), so genuinely cacheable static assets
			// are unaffected.
			w.Header().Set("Cache-Control", "private, no-store")
			next.ServeHTTP(w, withIdentity(r, identity))
			return
		}
		if errors.Is(err, errIdentityUnavailable) {
			http.Error(w, "identity service unavailable", http.StatusServiceUnavailable)
			return
		}
		// #1255: /api/* is exclusively fetched by page JS (fetch/XHR/
		// EventSource), never a top-level browser navigation, so redirecting
		// an unauthenticated call there toward Keycloak has the same
		// problem as the /static/ case above -- the caller's fetch()
		// follows the redirect and connect-src blocks the cross-origin
		// target, surfacing as a bare "Failed to fetch" instead of a real
		// response the frontend's existing 401/403 handling (several
		// dashboard/static/*.js api() helpers already check response.status)
		// can act on.
		// #1237: same problem again, this time for the "view report"-style
		// iframes (ghidra.html's report viewer, and every other inline PDF/
		// report proxy that follows the same pattern) rather than an /api/
		// fetch() call -- a session that expired mid-view turns the
		// iframe's GET into a redirect toward Keycloak, and frame-src
		// 'self' then blocks that cross-origin target, surfacing as a
		// browser-level "refused to connect" inside the frame instead of
		// anything the page can react to. Sec-Fetch-Dest (Fetch Metadata,
		// broadly supported) reliably distinguishes an iframe/nested-frame
		// load from a real top-level navigation regardless of path, unlike
		// the /api/ and /static/ checks above which only cover specific
		// prefixes.
		// #1394: same problem a third time -- overview.html's own in-place
		// live refresh (its 60s timer / SSE "update" handler) does a plain
		// fetch(location.pathname), i.e. fetch("/"), which is neither under
		// /api/ nor a frame load, so it fell straight through to the
		// redirect-to-Keycloak branch below and connect-src blocked the
		// resulting cross-origin hop exactly like the two cases above.
		// Rather than special-case yet another path, isProgrammaticFetch
		// covers the general case Sec-Fetch-Dest already distinguishes:
		// "empty" is what a browser sends for any script-initiated fetch()/
		// XMLHttpRequest that is not a navigation and not a frame load --
		// this subsumes the /api/ prefix check for modern browsers too, but
		// that check stays as-is for the older, pre-Fetch-Metadata browsers
		// isProgrammaticFetch's own comment already carves out.
		if strings.HasPrefix(r.URL.Path, "/api/") || isProgrammaticFetch(r) {
			http.Error(w, "authentication required", http.StatusUnauthorized)
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

// isProgrammaticFetch reports whether r is the browser loading this response
// via script (fetch()/XMLHttpRequest, "empty") or into an <iframe>/nested
// browsing context ("iframe" for same-origin, "frame" for the unused-here
// cross-origin case), per the Sec-Fetch-Dest Fetch Metadata header --
// "document" is what a real top-level navigation carries instead. Missing
// entirely on older browsers without Fetch Metadata support; those fall
// through to the normal redirect-to-login path exactly as before this
// existed.
func isProgrammaticFetch(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "empty", "iframe", "frame":
		return true
	}
	return false
}

// oidcBindingCookieName (#1235 item 5) gives each login attempt its own,
// distinctly-named binding cookie instead of every attempt sharing one
// fixed cookie name. state is safe to fold into the name unencrypted --
// it's already public (visible in the redirect to Keycloak and in the
// callback URL itself); only the cookie's *value* (binding) is the secret
// half of this check. base64.RawURLEncoding's alphabet (randomToken's own
// encoding) is a valid RFC 6265 cookie-name token as-is, so no further
// escaping is needed.
//
// Without this, two tabs in the same browser starting a login flow in
// close succession raced on ONE shared "__Host-apiary_oidc" cookie: the
// second /auth/login's Set-Cookie silently overwrote the first tab's
// binding value before its own round trip back from Keycloak completed,
// so the first tab's callback compared its state's stored Binding against
// the SECOND tab's cookie value and failed with "invalid OIDC browser
// binding" -- confirmed live and reported as #1235 item 5's own
// self-resolving-on-retry symptom (a fresh, no-longer-racing /auth/login
// from the same tab works). A per-state cookie name means concurrent
// flows never share a name, so a browser holds one cookie per in-flight
// attempt (RFC 6265 allows arbitrarily many same-origin cookies with
// distinct names) and each callback reads back exactly its own.
func oidcBindingCookieName(state string) string {
	return oidcStateCookie + "." + state
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
	http.SetCookie(w, secureCookie(oidcBindingCookieName(state), binding, oidcStateMaxAge))
	// S256ChallengeOption takes the *verifier* and hashes it internally to
	// produce the code_challenge -- it does not take an already-computed
	// challenge. Passing a pre-hashed value here double-hashes it, so the
	// challenge sent at authorization time never matches SHA256(verifier)
	// as computed by VerifierOption at exchange time. Caught live: every
	// login failed with Keycloak's own "PKCE verification failed: Code
	// mismatch", confirmed by reproducing the exact double hash by hand.
	destination := a.oauth2.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.S256ChallengeOption(verifier))
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
	binding, err := r.Cookie(oidcBindingCookieName(state))
	clearCookie(w, oidcBindingCookieName(state))
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
	// #1235: an SSE connection is authenticated once, when the stream is
	// opened; it is not re-authorized when its access token expires later.
	// Refreshing a still-valid token in the proactive one-minute window buys
	// the stream no additional security, but it can make EventSource lose the
	// per-session refresh race and wait behind the winning page request for up
	// to oidcRefreshWaitTimeout before the response headers are even flushed.
	// That was the live indicator's long "Reconnecting..." stall. Let ordinary
	// short-lived API requests perform the proactive refresh and let the stream
	// use its still-valid cached identity; an already-expired stream request
	// still refreshes normally and therefore never fails open.
	needsRefresh := !now.Before(session.TokenExpiry)
	if r.URL.Path != "/api/stream" {
		needsRefresh = now.Add(time.Minute).After(session.TokenExpiry)
	}
	if needsRefresh {
		remaining := oidcSessionMaxAge - now.Sub(session.CreatedAt)
		if err := a.refreshSessionLocked(r.Context(), cookie.Value, &session, remaining); err != nil {
			if isTransientOAuthError(err) {
				// Keycloak unreachable/overloaded right as this session's
				// token needed refreshing -- the same "fail closed, but
				// don't destroy a session over a transient outage" contract
				// introspect() already gives the 30s re-check path. Without
				// this, a Keycloak blip landing in this exact one-minute
				// window would silently and permanently log the user out
				// even though nothing about their own session was actually
				// invalid. errRefreshLockTimedOut and a lock-store error
				// both fall through isTransientOAuthError's own default
				// (errors.As fails to match *oauth2.RetrieveError -> true),
				// so they land here too, same as a real Keycloak outage.
				return authenticatedIdentity{}, errIdentityUnavailable
			}
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

// refreshSessionLocked serializes refreshSession per session ID (#1127).
//
// Keycloak's refresh tokens here are single-use (revokeRefreshToken=true,
// refreshTokenMaxReuse=0 in the realm config) -- reusing one gets a real
// invalid_grant rejection, indistinguishable at the HTTP level from a
// genuinely revoked session. Without this lock, two concurrent requests for
// the same session both arriving after its access token entered the
// "needs refresh" window (the last minute of its 300s lifespan) both read
// the same still-valid refresh token from Redis and both race to spend it:
// whichever's exchange Keycloak processes first succeeds and overwrites
// the session with new tokens; the loser's exchange, using the
// now-already-consumed token, gets invalid_grant -- a real rejection by
// isTransientOAuthError's own classification -- and identityFromRequest
// deleted the session it named, discarding the winner's still-good
// refresh a moment earlier. Reproduces exactly as reported in #1127: a
// burst of near-simultaneous requests after idle time (the common case
// once the access token has been sitting in its last minute), self-healing
// once enough wall-clock time passes for the race to resolve on its own,
// which is why a full reload "fixes" it but an instant same-page retry
// usually lands in the same window and fails again.
//
// remaining is the session's own remaining TTL (identityFromRequest's own
// oidcSessionMaxAge - age calculation) -- the refreshed session is
// persisted here, still under the lock, not left to identityFromRequest's
// later shared "if changed" write: a losing racer that acquires this lock
// immediately after release must see the already-persisted refreshed
// session, not the stale one that would let it back into refreshSession()
// with an already-spent refresh token.
func (a *oidcAuth) refreshSessionLocked(ctx context.Context, sessionID string, session *oidcSession, remaining time.Duration) error {
	lockKey := "oidc:refreshlock:" + sessionID
	acquired, err := a.sessions.TryLock(ctx, lockKey, oidcRefreshLockTTL)
	if err != nil {
		return err
	}
	if !acquired {
		return a.waitForConcurrentRefresh(ctx, sessionID, session, remaining)
	}
	defer func() { _ = a.sessions.Unlock(ctx, lockKey) }()

	// Someone may have refreshed and released the lock between our own
	// session read (by the caller, before acquiring this lock) and here --
	// re-read rather than assume we're first.
	var fresh oidcSession
	if err := a.getJSON(ctx, "oidc:session:"+sessionID, &fresh); err == nil && fresh.TokenExpiry.After(session.TokenExpiry) {
		*session = fresh
		return nil
	}
	if err := a.refreshSession(ctx, session); err != nil {
		return err
	}
	return a.putJSON(ctx, "oidc:session:"+sessionID, *session, remaining)
}

// waitForConcurrentRefresh is the losing side of refreshSessionLocked's
// race: rather than attempting a second exchange with an already-spent
// refresh token, it polls for the lock-holder's write. If the holder never
// finishes (crashed, or its own request context was cancelled) the lock
// self-expires (oidcRefreshLockTTL) and this takes over the refresh
// itself, rather than waiting out the full timeout for nothing.
func (a *oidcAuth) waitForConcurrentRefresh(ctx context.Context, sessionID string, session *oidcSession, remaining time.Duration) error {
	lockKey := "oidc:refreshlock:" + sessionID
	staleExpiry := session.TokenExpiry
	deadline := time.Now().Add(oidcRefreshWaitTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(oidcRefreshPollInterval):
		}
		var fresh oidcSession
		if err := a.getJSON(ctx, "oidc:session:"+sessionID, &fresh); err == nil && fresh.TokenExpiry.After(staleExpiry) {
			*session = fresh
			return nil
		}
		if acquired, err := a.sessions.TryLock(ctx, lockKey, oidcRefreshLockTTL); err == nil && acquired {
			defer func() { _ = a.sessions.Unlock(ctx, lockKey) }()
			if err := a.refreshSession(ctx, session); err != nil {
				return err
			}
			return a.putJSON(ctx, "oidc:session:"+sessionID, *session, remaining)
		}
	}
	return errRefreshLockTimedOut
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

// isTransientOAuthError reports whether a refresh-token exchange failure
// reflects Keycloak being unreachable or overloaded (retry later, keep the
// session) rather than the refresh token itself being genuinely invalid or
// revoked (a real logout). A request that never got an HTTP response at
// all -- dial failure, timeout -- never populates *oauth2.RetrieveError;
// that's unambiguously transient. A RetrieveError with a 5xx status means
// Keycloak itself responded but couldn't process the request (mid-restart,
// its own DB unreachable, etc.), also transient. Anything else -- a 4xx
// like invalid_grant for a refresh token that's actually been revoked or
// expired -- is a real rejection.
func isTransientOAuthError(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) {
		return true
	}
	return retrieveErr.Response != nil && retrieveErr.Response.StatusCode >= 500
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
