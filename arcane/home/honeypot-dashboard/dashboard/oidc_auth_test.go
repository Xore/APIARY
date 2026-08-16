package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

func TestSafeReturnToRejectsExternalAndProtocolRelativeURLs(t *testing.T) {
	for _, raw := range []string{"https://attacker.example/", "//attacker.example/", "javascript:alert(1)", ""} {
		if got := safeReturnTo(raw); got != "/" {
			t.Fatalf("safeReturnTo(%q) = %q, want /", raw, got)
		}
	}
	if got := safeReturnTo("/events?page=2"); got != "/events?page=2" {
		t.Fatalf("safe local return path changed: %q", got)
	}
}

func TestOIDCSessionCookieIsHostOnlySecureAndHTTPOnly(t *testing.T) {
	cookie := secureCookie(oidcSessionCookie, "opaque", time.Hour)
	if cookie.Domain != "" || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe OIDC cookie: %#v", cookie)
	}
}

func TestOIDCBindingCookieNameIsDistinctPerState(t *testing.T) {
	a := oidcBindingCookieName("state-a")
	b := oidcBindingCookieName("state-b")
	if a == b {
		t.Fatalf("two different states produced the same cookie name %q", a)
	}
	if a[:len(oidcStateCookie)] != oidcStateCookie {
		t.Fatalf("cookie name %q lost the __Host- prefix oidcStateCookie carries", a)
	}
}

// loginRedirectState pulls the "state" query parameter back out of
// serveLogin's own redirect Location -- the same value Keycloak would echo
// back on /auth/callback.
func loginRedirectState(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	loc, err := url.Parse(rec.Result().Header.Get("Location"))
	if err != nil {
		t.Fatalf("serveLogin redirect Location did not parse: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("serveLogin redirect is missing its own state param")
	}
	return state
}

// TestServeLoginBindingCookiesDoNotCollideAcrossConcurrentFlows is #1235
// item 5's own regression guard: two tabs in the same browser starting a
// login flow in close succession used to share ONE fixed-name binding
// cookie ("__Host-apiary_oidc") -- the second /auth/login's Set-Cookie
// silently overwrote the first tab's binding value before its own round
// trip back from Keycloak completed, so the first tab's callback compared
// its state's stored Binding against the wrong cookie and failed with
// "invalid OIDC browser binding" (confirmed live, self-resolving on a
// fresh, no-longer-racing retry -- see #1235's own investigation
// comment). oidcBindingCookieName gives each flow its own cookie name;
// this proves a browser holding BOTH concurrent flows' cookies still lets
// the FIRST flow's callback find and validate its own.
func TestServeLoginBindingCookiesDoNotCollideAcrossConcurrentFlows(t *testing.T) {
	// serveCallback's token exchange step runs after the binding check
	// this test cares about -- pointed at a real (but failing) endpoint so
	// Exchange fails fast and deterministically rather than the test
	// depending on network access or hanging on an unroutable URL.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer tokenServer.Close()

	store := &memorySessionStore{values: make(map[string][]byte)}
	auth := &oidcAuth{
		sessions:   store,
		now:        time.Now,
		httpClient: tokenServer.Client(),
		oauth2: oauth2.Config{
			ClientID: oidcClientID,
			Endpoint: oauth2.Endpoint{AuthURL: tokenServer.URL + "/auth", TokenURL: tokenServer.URL + "/token"},
		},
	}

	// Tab A starts a login flow.
	recA := httptest.NewRecorder()
	auth.serveLogin(recA, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	stateA := loginRedirectState(t, recA)
	cookiesA := recA.Result().Cookies()
	if len(cookiesA) != 1 {
		t.Fatalf("serveLogin set %d cookies, want 1: %+v", len(cookiesA), cookiesA)
	}

	// Tab B starts a SECOND login flow in the same browser before tab A's
	// own round trip completes -- the exact race #1235 item 5 reported.
	recB := httptest.NewRecorder()
	auth.serveLogin(recB, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	cookiesB := recB.Result().Cookies()
	if len(cookiesB) != 1 {
		t.Fatalf("serveLogin set %d cookies, want 1: %+v", len(cookiesB), cookiesB)
	}

	if cookiesA[0].Name == cookiesB[0].Name {
		t.Fatalf("two concurrent login flows must not share one binding cookie name, both got %q", cookiesA[0].Name)
	}

	// Tab A's callback arrives. A real browser holds BOTH cookies at this
	// point (they have different names) -- attach both, the way an actual
	// browser's cookie jar would.
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+stateA+"&code=fake-code", nil)
	req.AddCookie(cookiesA[0])
	req.AddCookie(cookiesB[0])
	rec := httptest.NewRecorder()
	auth.serveCallback(rec, req)

	if strings.Contains(rec.Body.String(), "invalid OIDC browser binding") {
		t.Fatalf("tab A's callback was confused by tab B's concurrent flow: %s", rec.Body.String())
	}
	// Getting to (and failing at) the token exchange step confirms the
	// binding check itself passed -- the exchange failure is expected and
	// unrelated, tokenServer above deliberately rejects it.
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "OIDC code exchange failed") {
		t.Fatalf("expected to reach (and fail at) the token exchange step, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestVerifyIDTokenEnforcesIssuerAudienceNoncePartyAndRole(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
				"token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	provider, err := oidc.NewProvider(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	auth := &oidcAuth{verifier: provider.Verifier(&oidc.Config{ClientID: oidcClientID}), httpClient: server.Client()}

	base := map[string]any{
		"iss": server.URL, "sub": "b65ab0dc-cc07-4b3d-9af0-b482dbb4b096",
		"aud": oidcClientID, "azp": oidcClientID, "exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(), "nonce": "expected-nonce",
		"preferred_username": "analyst", "name": "Analyst",
		"resource_access": map[string]any{oidcClientID: map[string]any{"roles": []string{"access", "admin"}}},
	}
	sign := func(claims map[string]any, signingKey *rsa.PrivateKey) string {
		signer, signErr := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
		if signErr != nil {
			t.Fatal(signErr)
		}
		raw, signErr := jwt.Signed(signer).Claims(claims).Serialize()
		if signErr != nil {
			t.Fatal(signErr)
		}
		return raw
	}
	clone := func() map[string]any {
		copy := make(map[string]any, len(base))
		for key, value := range base {
			copy[key] = value
		}
		return copy
	}

	identity, _, err := auth.verifyIDToken(context.Background(), sign(clone(), key), "expected-nonce")
	if err != nil || identity.Role != "admin" || identity.Subject == "" {
		t.Fatalf("valid administrator token rejected: identity=%#v err=%v", identity, err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://wrong.example" }},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other-client" }},
		{"wrong authorized party", func(c map[string]any) { c["azp"] = "other-client" }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{"wrong nonce", func(c map[string]any) { c["nonce"] = "attacker-nonce" }},
		{"missing role", func(c map[string]any) {
			c["resource_access"] = map[string]any{oidcClientID: map[string]any{"roles": []string{"admin"}}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := clone()
			test.mutate(claims)
			if _, _, err := auth.verifyIDToken(context.Background(), sign(claims, key), "expected-nonce"); err == nil {
				t.Fatal("invalid token was accepted")
			}
		})
	}

	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, _, err := auth.verifyIDToken(context.Background(), sign(clone(), wrongKey), "expected-nonce"); err == nil {
		t.Fatal("token with an untrusted signature was accepted")
	}
}

// #978: identityFromRequest() is dashboard/oidc_auth.go's single
// authoritative session check -- every one of #978's acceptance-criteria
// cases (anonymous, expired, revoked) route through it, but nothing
// exercised it directly before this: authorization_test.go's requireAdmin
// tests all construct a session with LastValidated == now, so they never
// hit the 30s introspection re-check or the 12h max-age expiry at all.
func TestIdentityFromRequestSessionLifecycle(t *testing.T) {
	const subject = "b65ab0dc-cc07-4b3d-9af0-b482dbb4b096"

	newStore := func() *memorySessionStore { return &memorySessionStore{values: make(map[string][]byte)} }

	t.Run("anonymous request with no cookie is rejected", func(t *testing.T) {
		auth := &oidcAuth{sessions: newStore(), now: time.Now}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		if _, err := auth.identityFromRequest(request); err != errIdentityUnauthorized {
			t.Fatalf("err = %v, want errIdentityUnauthorized", err)
		}
	})

	t.Run("cookie pointing at a session that was never created is rejected", func(t *testing.T) {
		auth := &oidcAuth{sessions: newStore(), now: time.Now}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "unknown-session-id"})
		if _, err := auth.identityFromRequest(request); err != errIdentityUnauthorized {
			t.Fatalf("err = %v, want errIdentityUnauthorized", err)
		}
	})

	t.Run("session older than the 12h max age is rejected and deleted", func(t *testing.T) {
		store := newStore()
		created := time.Now().UTC()
		nowFn := func() time.Time { return created.Add(oidcSessionMaxAge + time.Minute) }
		auth := &oidcAuth{sessions: store, now: nowFn}
		session := oidcSession{
			Identity: authenticatedIdentity{Subject: subject, Username: "analyst", Role: "user"},
			// Far in the future so the refresh path is never reached --
			// this test is specifically about the CreatedAt/max-age check.
			TokenExpiry: created.Add(1000 * time.Hour), CreatedAt: created, LastValidated: created,
		}
		if err := auth.putJSON(context.Background(), "oidc:session:expired-session", session, time.Hour); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "expired-session"})
		if _, err := auth.identityFromRequest(request); err != errIdentityUnauthorized {
			t.Fatalf("err = %v, want errIdentityUnauthorized", err)
		}
		if _, getErr := store.Get(context.Background(), "oidc:session:expired-session"); getErr != errSessionNotFound {
			t.Fatalf("expired session was not deleted: %v", getErr)
		}
	})

	t.Run("session revoked at the identity provider is rejected and deleted on next check", func(t *testing.T) {
		introspection := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
		}))
		defer introspection.Close()

		store := newStore()
		created := time.Now().UTC()
		// LastValidated 31s in the past forces identityFromRequest() past
		// the 30s re-check threshold into a real introspection call, the
		// same as a real session that's simply been sitting idle.
		nowFn := func() time.Time { return created.Add(31 * time.Second) }
		auth := &oidcAuth{
			sessions: store, now: nowFn, httpClient: introspection.Client(),
			introspectionEndpoint: introspection.URL, clientSecret: "unused-in-this-test",
		}
		session := oidcSession{
			Identity:    authenticatedIdentity{Subject: subject, Username: "analyst", Role: "user"},
			TokenExpiry: created.Add(time.Hour), CreatedAt: created, LastValidated: created,
			AccessToken: "revoked-access-token",
		}
		if err := auth.putJSON(context.Background(), "oidc:session:revoked-session", session, time.Hour); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "revoked-session"})
		if _, err := auth.identityFromRequest(request); err != errIdentityUnauthorized {
			t.Fatalf("err = %v, want errIdentityUnauthorized (session was revoked at the identity provider)", err)
		}
		if _, getErr := store.Get(context.Background(), "oidc:session:revoked-session"); getErr != errSessionNotFound {
			t.Fatalf("revoked session was not deleted: %v", getErr)
		}
	})

	t.Run("still-active session survives its 30s introspection re-check", func(t *testing.T) {
		introspection := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": subject, "client_id": oidcClientID})
		}))
		defer introspection.Close()

		store := newStore()
		created := time.Now().UTC()
		nowFn := func() time.Time { return created.Add(31 * time.Second) }
		auth := &oidcAuth{
			sessions: store, now: nowFn, httpClient: introspection.Client(),
			introspectionEndpoint: introspection.URL, clientSecret: "unused-in-this-test",
		}
		session := oidcSession{
			Identity:    authenticatedIdentity{Subject: subject, Username: "analyst", Role: "admin"},
			TokenExpiry: created.Add(time.Hour), CreatedAt: created, LastValidated: created,
			AccessToken: subject,
		}
		if err := auth.putJSON(context.Background(), "oidc:session:live-session", session, time.Hour); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "live-session"})
		identity, err := auth.identityFromRequest(request)
		if err != nil || identity.Role != "admin" || identity.Subject != subject {
			t.Fatalf("still-active session was rejected: identity=%#v err=%v", identity, err)
		}
	})

	// #978: "Keycloak/JWKS failure is fail closed" -- distinct from
	// TestRequireAdminFailsClosedWithoutIdentityService (dashboardOIDC ==
	// nil, no identity service configured at all). This is the case that
	// matters operationally: a real, previously-valid session mid-life
	// whose next 30s introspection re-check can't reach Keycloak at all.
	// A bug here would silently keep granting access on stale
	// LastValidated forever during an outage, exactly what "fail closed"
	// exists to prevent.
	t.Run("session survives past a broken introspection endpoint by denying, not granting", func(t *testing.T) {
		store := newStore()
		created := time.Now().UTC()
		nowFn := func() time.Time { return created.Add(31 * time.Second) }
		auth := &oidcAuth{
			sessions: store, now: nowFn, httpClient: &http.Client{Timeout: time.Second},
			// No server listening on this port: simulates Keycloak/network
			// being unreachable during the introspection re-check.
			introspectionEndpoint: "http://127.0.0.1:1/introspect", clientSecret: "unused-in-this-test",
		}
		session := oidcSession{
			Identity:    authenticatedIdentity{Subject: subject, Username: "analyst", Role: "admin"},
			TokenExpiry: created.Add(time.Hour), CreatedAt: created, LastValidated: created,
			AccessToken: subject,
		}
		if err := auth.putJSON(context.Background(), "oidc:session:outage-session", session, time.Hour); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "outage-session"})
		if _, err := auth.identityFromRequest(request); err != errIdentityUnavailable {
			t.Fatalf("err = %v, want errIdentityUnavailable (fail closed on identity-provider outage)", err)
		}
	})

	// Found live via a real chaos test (scripts/test-dashboard-oidc-chaos.sh):
	// a Keycloak outage landing in the one-minute window before a session's
	// access token expiry routes through refreshSession(), not introspect().
	// Unlike introspect()'s already-tested outage handling above, every
	// refreshSession() failure -- transient or not -- used to be treated as
	// a genuine rejection and delete the session outright, permanently
	// logging the user out over what was really just Keycloak being
	// mid-restart.
	t.Run("session survives a transient refresh failure by denying, not destroying the session", func(t *testing.T) {
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "keycloak still starting", http.StatusServiceUnavailable)
		}))
		defer tokenEndpoint.Close()

		store := newStore()
		created := time.Now().UTC()
		nowFn := func() time.Time { return created.Add(time.Hour) }
		auth := &oidcAuth{
			sessions: store, now: nowFn, httpClient: tokenEndpoint.Client(),
			oauth2: oauth2.Config{ClientID: oidcClientID, Endpoint: oauth2.Endpoint{TokenURL: tokenEndpoint.URL}},
		}
		session := oidcSession{
			Identity: authenticatedIdentity{Subject: subject, Username: "analyst", Role: "admin"},
			// Already past expiry -- forces the refresh path on this request
			// rather than waiting a further 30s for introspection to matter.
			TokenExpiry: created.Add(-time.Hour), CreatedAt: created, LastValidated: created,
			AccessToken: subject, RefreshToken: "refresh-token-still-valid",
		}
		if err := auth.putJSON(context.Background(), "oidc:session:refresh-outage-session", session, time.Hour); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "refresh-outage-session"})
		if _, err := auth.identityFromRequest(request); err != errIdentityUnavailable {
			t.Fatalf("err = %v, want errIdentityUnavailable (fail closed, not logged out, on a transient refresh failure)", err)
		}
		if _, getErr := store.Get(context.Background(), "oidc:session:refresh-outage-session"); getErr != nil {
			t.Fatalf("session was deleted over a transient refresh failure: %v", getErr)
		}
	})

	t.Run("session with a genuinely revoked refresh token is rejected and deleted", func(t *testing.T) {
		tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Refresh token expired"}`))
		}))
		defer tokenEndpoint.Close()

		store := newStore()
		created := time.Now().UTC()
		nowFn := func() time.Time { return created.Add(time.Hour) }
		auth := &oidcAuth{
			sessions: store, now: nowFn, httpClient: tokenEndpoint.Client(),
			oauth2: oauth2.Config{ClientID: oidcClientID, Endpoint: oauth2.Endpoint{TokenURL: tokenEndpoint.URL}},
		}
		session := oidcSession{
			Identity:    authenticatedIdentity{Subject: subject, Username: "analyst", Role: "admin"},
			TokenExpiry: created.Add(-time.Hour), CreatedAt: created, LastValidated: created,
			AccessToken: subject, RefreshToken: "refresh-token-actually-revoked",
		}
		if err := auth.putJSON(context.Background(), "oidc:session:revoked-refresh-session", session, time.Hour); err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "revoked-refresh-session"})
		if _, err := auth.identityFromRequest(request); err != errIdentityUnauthorized {
			t.Fatalf("err = %v, want errIdentityUnauthorized (refresh token was genuinely revoked)", err)
		}
		if _, getErr := store.Get(context.Background(), "oidc:session:revoked-refresh-session"); getErr != errSessionNotFound {
			t.Fatalf("session with a genuinely revoked refresh token was not deleted: %v", getErr)
		}
	})

	// #1235: /api/stream is authenticated once before its long-lived response
	// begins. If another page request already owns the refresh lock while the
	// access token is still valid (inside the normal one-minute proactive
	// refresh window), EventSource must not wait behind it before receiving
	// the SSE headers. The still-held lock after this call proves this request
	// neither waited for nor took over the refresh.
	t.Run("SSE does not wait for a proactive concurrent refresh while its token is valid", func(t *testing.T) {
		store := newStore()
		now := time.Now().UTC()
		auth := &oidcAuth{sessions: store, now: func() time.Time { return now }}
		const sessionID = "near-expiry-stream-session"
		session := oidcSession{
			Identity: authenticatedIdentity{Subject: subject, Username: "analyst", Role: "admin"},
			// Inside the ordinary request path's proactive refresh window, but
			// not expired -- exactly the concurrent page-load race from #1235.
			TokenExpiry: now.Add(30 * time.Second), CreatedAt: now, LastValidated: now,
		}
		if err := auth.putJSON(context.Background(), "oidc:session:"+sessionID, session, time.Hour); err != nil {
			t.Fatal(err)
		}
		lockKey := "oidc:refreshlock:" + sessionID
		acquired, err := store.TryLock(context.Background(), lockKey, oidcRefreshLockTTL)
		if err != nil || !acquired {
			t.Fatalf("pre-acquire refresh lock: acquired=%v err=%v", acquired, err)
		}

		request := httptest.NewRequest(http.MethodGet, "/api/stream", nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: sessionID})
		identity, err := auth.identityFromRequest(request)
		if err != nil {
			t.Fatalf("identityFromRequest() = %v, want immediate cached identity", err)
		}
		if identity.Subject != subject {
			t.Fatalf("identity subject = %q, want %q", identity.Subject, subject)
		}
		if !store.locks[lockKey] {
			t.Fatal("SSE unexpectedly acquired/released the refresh lock for a still-valid token")
		}
	})

	// #1127: reproduces the actual production bug. Keycloak's refresh
	// tokens here are single-use (revokeRefreshToken=true,
	// refreshTokenMaxReuse=0, keycloak/realm/apiary-realm.json) -- two
	// concurrent requests for the same session, both arriving after its
	// access token entered the last-minute refresh window, both read the
	// same still-valid refresh token and race to spend it. Before the
	// #1127 fix, the loser's exchange got a real invalid_grant (Keycloak
	// telling the truth: that exact token was already used), which
	// identityFromRequest treated as a genuine revocation -- deleting the
	// session the winner had just legitimately refreshed a moment earlier.
	// The fake token endpoint below plays Keycloak's actual behavior: the
	// first exchange succeeds, every one after it (reusing the same
	// spent refresh token) gets invalid_grant.
	t.Run("concurrent requests racing to refresh the same session do not delete it", func(t *testing.T) {
		originalTimeout, originalPoll := oidcRefreshWaitTimeout, oidcRefreshPollInterval
		oidcRefreshWaitTimeout, oidcRefreshPollInterval = 2*time.Second, 5*time.Millisecond
		t.Cleanup(func() { oidcRefreshWaitTimeout, oidcRefreshPollInterval = originalTimeout, originalPoll })

		// The winning exchange must actually succeed end to end -- unlike
		// the transient/revoked-refresh tests above, which only need the
		// token endpoint to fail, this one needs refreshSession() to reach
		// a valid identity, which means a real signed ID token verified
		// against a real JWKS (verifyIDToken does real signature checking,
		// same setup as TestVerifyIDTokenEnforcesIssuerAudienceNoncePartyAndRole).
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		var server *httptest.Server
		var mu sync.Mutex
		exchanges := 0
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
					"token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/jwks",
					"id_token_signing_alg_values_supported": []string{"RS256"},
				})
			case "/jwks":
				_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
			case "/token":
				mu.Lock()
				exchanges++
				first := exchanges == 1
				mu.Unlock()
				if !first {
					// Keycloak's real response to a refresh token already
					// spent by the winning concurrent request.
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Token reuse detected"}`))
					return
				}
				signer, signErr := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
				if signErr != nil {
					t.Fatal(signErr)
				}
				idToken, signErr := jwt.Signed(signer).Claims(map[string]any{
					"iss": server.URL, "sub": subject, "aud": oidcClientID, "azp": oidcClientID,
					"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
					"preferred_username": "analyst", "name": "Analyst",
					"resource_access": map[string]any{oidcClientID: map[string]any{"roles": []string{"access", "admin"}}},
				}).Serialize()
				if signErr != nil {
					t.Fatal(signErr)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "new-access-token", "refresh_token": "new-refresh-token",
					"token_type": "Bearer", "expires_in": 300, "id_token": idToken,
				})
			case "/introspect":
				// now() is 1h past LastValidated in this test, so every
				// request also crosses the 30s introspection re-check --
				// this needs to succeed for the request to reach a clean
				// identity, same as the refresh above.
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": subject, "client_id": oidcClientID})
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		provider, err := oidc.NewProvider(context.Background(), server.URL)
		if err != nil {
			t.Fatal(err)
		}

		store := newStore()
		created := time.Now().UTC()
		nowFn := func() time.Time { return created.Add(time.Hour) }
		auth := &oidcAuth{
			sessions: store, now: nowFn, httpClient: server.Client(),
			verifier:              provider.Verifier(&oidc.Config{ClientID: oidcClientID}),
			oauth2:                oauth2.Config{ClientID: oidcClientID, Endpoint: provider.Endpoint()},
			introspectionEndpoint: server.URL + "/introspect",
			clientSecret:          "unused-in-this-test",
		}
		session := oidcSession{
			Identity:    authenticatedIdentity{Subject: subject, Username: "analyst", Role: "admin"},
			TokenExpiry: created.Add(-time.Hour), CreatedAt: created, LastValidated: created,
			AccessToken: subject, RefreshToken: "refresh-token-still-valid",
		}
		if err := auth.putJSON(context.Background(), "oidc:session:racing-session", session, time.Hour); err != nil {
			t.Fatal(err)
		}

		const concurrency = 8
		results := make([]error, concurrency)
		var wg sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				request := httptest.NewRequest(http.MethodGet, "/", nil)
				request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "racing-session"})
				_, results[i] = auth.identityFromRequest(request)
			}(i)
		}
		wg.Wait()

		for i, err := range results {
			if err != nil {
				t.Errorf("request %d: identityFromRequest() = %v, want nil (a losing racer must wait for the winner, not force a logout)", i, err)
			}
		}
		if _, getErr := store.Get(context.Background(), "oidc:session:racing-session"); getErr != nil {
			t.Fatalf("session was deleted by a losing racer's spent refresh token: %v", getErr)
		}
		mu.Lock()
		defer mu.Unlock()
		if exchanges != 1 {
			t.Errorf("token endpoint hit %d times, want exactly 1 -- the lock should have serialized every concurrent request onto one real exchange", exchanges)
		}
	})
}

// #978: "logout terminates dashboard access predictably" -- serveLogout()
// itself had no direct test either.
func TestServeLogoutDeletesSessionAndEndsAtKeycloak(t *testing.T) {
	const subject = "b65ab0dc-cc07-4b3d-9af0-b482dbb4b096"
	store := &memorySessionStore{values: make(map[string][]byte)}
	now := time.Now().UTC()
	auth := &oidcAuth{
		sessions: store, now: func() time.Time { return now },
		endSessionEndpoint: "https://keycloak.example/realms/apiary/protocol/openid-connect/logout",
		externalURL:        "https://dashboard.example",
	}
	session := oidcSession{
		Identity: authenticatedIdentity{Subject: subject, Role: "user"},
		IDToken:  "opaque-id-token", TokenExpiry: now.Add(time.Hour), CreatedAt: now, LastValidated: now,
	}
	if err := auth.putJSON(context.Background(), "oidc:session:logout-me", session, time.Hour); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "logout-me"})
	recorder := httptest.NewRecorder()
	auth.serveLogout(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	location := recorder.Header().Get("Location")
	if !strings.HasPrefix(location, auth.endSessionEndpoint+"?") || !strings.Contains(location, "id_token_hint=opaque-id-token") {
		t.Fatalf("Location = %q, want a redirect to Keycloak's end_session_endpoint with the ID token hint", location)
	}

	if _, err := store.Get(context.Background(), "oidc:session:logout-me"); err != errSessionNotFound {
		t.Fatalf("session survived logout: %v", err)
	}
	postLogout := httptest.NewRequest(http.MethodGet, "/", nil)
	postLogout.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "logout-me"})
	if _, err := auth.identityFromRequest(postLogout); err != errIdentityUnauthorized {
		t.Fatalf("logged-out session cookie still authenticated: err=%v", err)
	}
}

// #978: nothing exercised the global middleware's anonymous-access
// behavior directly -- this is the one function every protected route
// (everything except /healthz, /auth/login, /auth/callback, /auth/logout)
// actually runs through.
func TestMiddlewareRejectsAnonymousRequests(t *testing.T) {
	auth := &oidcAuth{sessions: &memorySessionStore{values: make(map[string][]byte)}, now: time.Now}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	handler := auth.middleware(next)

	t.Run("anonymous GET is redirected to login, not served", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/alerts", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
		}
		if location := recorder.Header().Get("Location"); !strings.HasPrefix(location, "/auth/login?") {
			t.Fatalf("Location = %q, want a redirect to /auth/login", location)
		}
	})

	t.Run("anonymous POST is denied outright, not redirected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/api/settings", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
		}
	})

	t.Run("exempt paths are served without identity", func(t *testing.T) {
		for _, path := range []string{"/healthz", "/auth/login", "/auth/callback", "/auth/logout"} {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusTeapot {
				t.Fatalf("%s: status = %d, want the handler to run unauthenticated (%d)", path, recorder.Code, http.StatusTeapot)
			}
		}
	})

	// #1255: static assets carry no identity-bearing data, so an anonymous
	// request for one should never gate on session validity at all.
	t.Run("static assets are served without identity", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/static/site.webmanifest", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusTeapot {
			t.Fatalf("status = %d, want the handler to run unauthenticated (%d)", recorder.Code, http.StatusTeapot)
		}
	})

	// #1255: /api/* is only ever called by page JS (fetch/XHR/EventSource),
	// so an anonymous GET there must fail with a real status the caller can
	// branch on -- redirecting it toward Keycloak instead sends fetch()
	// chasing a cross-origin URL that connect-src then blocks, surfacing as
	// an opaque network error rather than a 401 the frontend can handle.
	t.Run("anonymous API GET is denied outright, not redirected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
		}
	})

	// #1237: an <iframe> (ghidra.html's "view report" viewer, any similar
	// inline proxy) loading a page whose session just expired must also get
	// a real 401, not a redirect toward Keycloak that frame-src then blocks.
	t.Run("anonymous iframe GET is denied outright, not redirected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/export/ghidra/deadbeef", nil)
		request.Header.Set("Sec-Fetch-Dest", "iframe")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
		}
	})

	// #1394: overview.html's own in-place live refresh does a plain
	// fetch(location.pathname) -- fetch("/") for the overview page itself --
	// which is neither under /api/ nor a frame load, so an expired session
	// must still get a real 401 there too, not a redirect toward Keycloak
	// that connect-src then blocks the same way #1255/#1237 already fixed
	// for /api/ and iframe loads.
	t.Run("anonymous script-initiated GET to a non-API path is denied outright, not redirected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Sec-Fetch-Dest", "empty")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
		}
	})

	// A real top-level navigation to the same kind of path (no Sec-Fetch-Dest,
	// or "document") must keep redirecting to login -- e.g. clicking a
	// download link while logged out should still land the user at sign-in
	// and back, not a bare 401 with no path forward.
	t.Run("anonymous top-level GET to a non-API path still redirects", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/export/ghidra/deadbeef", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
		}
	})
}

// TestMiddlewareCacheControl (#1323): every authenticated response now
// carries Cache-Control: private, no-store, set centrally in middleware()
// itself rather than left to each handler to remember -- attacker/session
// data scoped to one operator's own request must never be served from a
// shared cache. /healthz and /static/ never reach the identity-resolved
// branch (no per-operator data to scope), so they must be unaffected.
func TestMiddlewareCacheControl(t *testing.T) {
	const subject = "b65ab0dc-cc07-4b3d-9af0-b482dbb4b096"
	store := &memorySessionStore{values: make(map[string][]byte)}
	created := time.Now().UTC()
	// now == created: zero elapsed time since LastValidated, so
	// identityFromRequest() stays under the 30s re-check threshold and
	// never needs a real introspection endpoint for this test.
	auth := &oidcAuth{sessions: store, now: func() time.Time { return created }}
	session := oidcSession{
		Identity:    authenticatedIdentity{Subject: subject, Username: "analyst", Role: "user"},
		TokenExpiry: created.Add(time.Hour), CreatedAt: created, LastValidated: created,
	}
	if err := auth.putJSON(context.Background(), "oidc:session:cache-control-test", session, time.Hour); err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := auth.middleware(next)

	t.Run("an authenticated request gets private, no-store", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/alerts", nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "cache-control-test"})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (a valid session should reach the handler)", recorder.Code)
		}
		if got := recorder.Header().Get("Cache-Control"); got != "private, no-store" {
			t.Fatalf("Cache-Control = %q, want %q", got, "private, no-store")
		}
	})

	t.Run("/healthz gets no Cache-Control from the middleware", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if got := recorder.Header().Get("Cache-Control"); got != "" {
			t.Fatalf("Cache-Control = %q, want unset -- /healthz never reaches the identity-resolved branch", got)
		}
	})

	t.Run("static assets get no Cache-Control from the middleware", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/static/site.webmanifest", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if got := recorder.Header().Get("Cache-Control"); got != "" {
			t.Fatalf("Cache-Control = %q, want unset -- static assets never reach the identity-resolved branch", got)
		}
	})
}
