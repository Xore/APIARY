package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func newTestHandler() *handler {
	return &handler{log: newLogger(""), port: 443}
}

func TestGETRootServesLoginPage(t *testing.T) {
	for _, p := range []string{"/", "/vpn/"} {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		newTestHandler().ServeHTTP(w, req)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Citrix Login") {
			t.Fatalf("path %q: expected login page, got %d %q", p, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Server"); got != "Apache" {
			t.Fatalf("path %q: Server header = %q, want Apache", p, got)
		}
	}
}

func TestUnhandledMethodIsLoggedAndReturnsEmpty200(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	req := httptest.NewRequest("OPTIONS", "/foo", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Server"); got != "Apache" {
		t.Fatalf("Server header = %q, want Apache", got)
	}
	if !strings.Contains(buf.String(), `"event":"method_options"`) {
		t.Fatalf("expected method_options event logged, got %q", buf.String())
	}
}

func TestGETPlainPathWithoutTraversalReturnsEmpty200(t *testing.T) {
	req := httptest.NewRequest("GET", "/some/random/path", nil)
	w := httptest.NewRecorder()
	newTestHandler().ServeHTTP(w, req)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", w.Code, w.Body.String())
	}
}

func TestGETType1ScanReturns403WithURLSubstituted(t *testing.T) {
	req := httptest.NewRequest("GET", "/vpn/../vpns/", nil)
	w := httptest.NewRecorder()
	newTestHandler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("code = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/vpns") {
		t.Fatalf("body should echo the collapsed path: %q", w.Body.String())
	}
}

func TestGETCVECompletionReturnsEmpty200(t *testing.T) {
	req := httptest.NewRequest("GET", "/vpn/../vpns/portal/anything", nil)
	w := httptest.NewRecorder()
	newTestHandler().ServeHTTP(w, req)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", w.Code, w.Body.String())
	}
}

func TestGETSMBConfScanReturnsSmbConf(t *testing.T) {
	req := httptest.NewRequest("GET", "/vpn/../vpns/cfg/smb.conf", nil)
	w := httptest.NewRecorder()
	newTestHandler().ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "encrypt passwords") {
		t.Fatalf("got %d %q, want smb.conf content", w.Code, w.Body.String())
	}
}

// TestCitrixForbiddenBodyEscapesReflectedPath guards against reflected XSS
// (CodeQL caught this as a real finding during development): the value
// substituted into the 403 page is fundamentally attacker-influenced (it's
// derived from the request path), so it must be HTML-escaped rather than
// substituted verbatim -- upstream's own Python does this substitution
// unescaped, but that's not a behavior worth reproducing. Exercised
// directly against the helper rather than through a full request: the
// current caller only ever passes the fixed literal "/vpns" (the routing
// above forces that), so no crafted HTTP request can reach this code path
// with a different value today -- this test defends the escaping itself,
// not current reachability, in case that constraint ever loosens.
func TestCitrixForbiddenBodyEscapesReflectedPath(t *testing.T) {
	body := citrixForbiddenBody(`/vpns/<script>alert(1)</script>`)
	if strings.Contains(body, "<script>") {
		t.Fatalf("unescaped script tag in body: %q", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("expected the payload to be HTML-escaped, got: %q", body)
	}
}

func TestGETUnhandledVpnsTraversalReturnsEmpty200(t *testing.T) {
	req := httptest.NewRequest("GET", "/vpn/../vpns/something/else", nil)
	w := httptest.NewRecorder()
	newTestHandler().ServeHTTP(w, req)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", w.Code, w.Body.String())
	}
}

func TestGETTraversalOutsideVpnsReturnsEmpty200(t *testing.T) {
	// literal "/../" present, but the collapsed path's first segment isn't
	// "vpns" -- upstream's outer `if url_path[0] == 'vpns'` guard never
	// fires, so this falls all the way through to the default empty 200.
	req := httptest.NewRequest("GET", "/foo/../bar/baz", nil)
	w := httptest.NewRecorder()
	newTestHandler().ServeHTTP(w, req)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", w.Code, w.Body.String())
	}
}

func TestPOSTNewbmCapturesTitlePayload(t *testing.T) {
	body := "title=" + "id%3B%20cat%20%2Fetc%2Fpasswd"
	req := httptest.NewRequest("POST", "/vpns/portal/scripts/newbm.pl", strings.NewReader(body))
	w := httptest.NewRecorder()

	l := newLogger("")
	h := &handler{log: l, port: 443}
	h.ServeHTTP(w, req)

	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", w.Code, w.Body.String())
	}
}

func TestGETQueryStringIsCapturedInLoggedEvent(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	req := httptest.NewRequest("GET", "/oauth/idp/.well-known/openid-configuration?SAMLRequest=fZ1LmZvbw", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if !strings.Contains(buf.String(), `"query":"SAMLRequest=fZ1LmZvbw"`) {
		t.Fatalf("expected query string in logged event, got %q", buf.String())
	}
}

func TestGETWithoutQueryStringOmitsQueryField(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	req := httptest.NewRequest("GET", "/some/random/path", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if strings.Contains(buf.String(), `"query"`) {
		t.Fatalf("expected no query field for a request without one, got %q", buf.String())
	}
}

func TestPOSTOtherPathReturnsEmpty200(t *testing.T) {
	req := httptest.NewRequest("POST", "/whatever", strings.NewReader("data"))
	w := httptest.NewRecorder()
	newTestHandler().ServeHTTP(w, req)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", w.Code, w.Body.String())
	}
}

func TestSelfSignedCertIsGeneratedFresh(t *testing.T) {
	c1, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if string(c1.Certificate[0]) == string(c2.Certificate[0]) {
		t.Fatal("two calls produced the identical certificate -- not fresh per instance")
	}
}

// #2977: probes of the NetScaler AAA / SAML / OAuth authentication surface
// get their own event kind. The literals come from ET signatures loaded on
// this fleet's Suricata (see authSurfaceEvent's comment), so this is a
// confirmed-shape classifier, not a guessed one.
func TestAuthSurfaceProbesAreClassified(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/saml/login", "netscaler_saml_surface_probe"},
		{"/cgi/samlauth", "netscaler_saml_surface_probe"},
		{"/wsfed/passive", "netscaler_saml_surface_probe"},
		{"/cgi/logout", "netscaler_saml_surface_probe"},
		{"/SAML/Login/", "netscaler_saml_surface_probe"},
		{"/oauth/idp/.well-known/openid-configuration", "netscaler_oauth_surface_probe"},
		{"/oauth/rp/.well-known/openid-configuration", "netscaler_oauth_surface_probe"},
		{"/p/u/doAuthentication.do", "netscaler_aaa_surface_probe"},
		{"/", ""},
		{"/vpn", ""},
		{"/vpn/../vpns/", ""},
		{"/some/random/path", ""},
		{"/oauth", ""},
	}
	for _, c := range cases {
		if got := authSurfaceEvent(c.path); got != c.want {
			t.Errorf("authSurfaceEvent(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// #3032: classification alone is no longer the whole story -- these paths
// now also get an AAA/SAML-shaped response instead of an empty 200, so a
// scanner fingerprinting for the surface finds something. The event log
// behavior from #2977 is unchanged.
func TestAuthSurfaceProbeServesSAMLShapedResponseAndIsLogged(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	req := httptest.NewRequest("GET", "/saml/login", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if rec.Code != 200 || rec.Body.Len() == 0 {
		t.Fatalf("got %d %q, want a non-empty SAML-shaped 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Fatalf("expected a SAML bounce form in the body, got %q", rec.Body.String())
	}
	if got := rec.Header().Get("Server"); got != "Apache" {
		t.Fatalf("Server header = %q, want Apache", got)
	}
	out := buf.String()
	if !strings.Contains(out, `"event":"get"`) {
		t.Fatalf("the unconditional get event must still be emitted, got %q", out)
	}
	if !strings.Contains(out, `"event":"netscaler_saml_surface_probe"`) {
		t.Fatalf("expected the auth-surface event alongside it, got %q", out)
	}
}

func TestOAuthDiscoveryPathsServeOIDCDocument(t *testing.T) {
	for _, tc := range []struct {
		path string
		role string
	}{
		{"/oauth/idp/.well-known/openid-configuration", "idp"},
		{"/oauth/rp/.well-known/openid-configuration", "rp"},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		req.Host = "citrixgw01.example.test"
		rec := httptest.NewRecorder()
		newTestHandler().ServeHTTP(rec, req)

		if rec.Code != 200 {
			t.Fatalf("%s: code = %d, want 200", tc.path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("%s: Content-Type = %q, want application/json", tc.path, got)
		}
		var doc oidcDiscovery
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: invalid JSON body %q: %v", tc.path, rec.Body.String(), err)
		}
		wantIssuer := "https://citrixgw01.example.test/oauth/" + tc.role
		if doc.Issuer != wantIssuer {
			t.Fatalf("%s: issuer = %q, want %q", tc.path, doc.Issuer, wantIssuer)
		}
	}
}

func TestAAALoginEndpointServesDistinctPage(t *testing.T) {
	req := httptest.NewRequest("GET", "/p/u/doAuthentication.do", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "vpnForm") {
		t.Fatalf("got %d %q, want the AAA login page", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Citrix Login") {
		t.Fatalf("AAA login page should be distinct from the Gateway login page, got %q", rec.Body.String())
	}
}

func TestWSFedPassiveReflectsEscapedWctx(t *testing.T) {
	req := httptest.NewRequest("GET", "/wsfed/passive?wctx=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("wctx must be HTML-escaped, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "&lt;script&gt;") {
		t.Fatalf("expected the escaped wctx reflected back, got %q", rec.Body.String())
	}
}

func TestLoginPageAdvertisesSAMLSSO(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), `href="/saml/login"`) {
		t.Fatalf("expected a SAML SSO link on the login page, got %q", rec.Body.String())
	}
}

// POST classifies too, and carries the body -- the CVE-2026-3055 M1 shape is
// a POST to /saml/login whose SAMLRequest= parameter is in the body.
func TestAuthSurfacePOSTCarriesTheBody(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	req := httptest.NewRequest("POST", "/saml/login", strings.NewReader("SAMLRequest=PHNhbWxw"))
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	out := buf.String()
	if !strings.Contains(out, `"event":"netscaler_saml_surface_probe"`) {
		t.Fatalf("expected the auth-surface event on POST, got %q", out)
	}
	if !strings.Contains(out, "SAMLRequest=PHNhbWxw") {
		t.Fatalf("expected the POST body captured on the classified event, got %q", out)
	}
}
