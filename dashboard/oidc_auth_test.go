package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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
