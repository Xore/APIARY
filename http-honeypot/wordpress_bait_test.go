package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #238: wp-login.php alone only let classify() label a request "wordpress"
// after the fact -- these deepen the bait so a real WordPress-specific CVE
// attempt (version fingerprinting via readme.html, xmlrpc.php pingback/
// multicall probes, per-plugin readme.txt fingerprinting) gets more signal
// than a generic 404.

func newTestServer() (*server, *bytes.Buffer) {
	var output bytes.Buffer
	return &server{log: &logger{out: &output}, sensor: "http-honeypot", serverHdr: "nginx"}, &output
}

func TestWordPressReadmeExposesVersionString(t *testing.T) {
	s, _ := newTestServer()
	r := httptest.NewRequest(http.MethodGet, "http://example/readme.html", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Version 5.8.1") {
		t.Fatalf("expected a version-bearing readme.html, got %d %s", w.Code, w.Body.String())
	}
}

func TestXMLRPCRejectsGETAndFaultsOnPOST(t *testing.T) {
	s, output := newTestServer()

	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example/xmlrpc.php", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "POST requests only") {
		t.Fatalf("GET xmlrpc.php: got %d %s", w.Code, w.Body.String())
	}

	output.Reset()
	body := `<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName></methodCall>`
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://example/xmlrpc.php", strings.NewReader(body)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<fault>") {
		t.Fatalf("POST xmlrpc.php: got %d %s", w.Code, w.Body.String())
	}
	// The attempted multicall/pingback payload must actually be captured,
	// not just answered -- that's the whole point of presenting the
	// endpoint at all.
	if !strings.Contains(output.String(), "system.multicall") {
		t.Fatalf("xmlrpc.php POST body not logged: %s", output.String())
	}
}

func TestVulnerablePluginReadmesExposeVersionStrings(t *testing.T) {
	cases := []struct {
		path    string
		version string
	}{
		{"/wp-content/plugins/duplicator/readme.txt", "1.3.26"},
		{"/wp-content/plugins/wp-file-manager/readme.txt", "6.0"},
	}
	for _, tc := range cases {
		s, _ := newTestServer()
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example"+tc.path, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Stable tag: "+tc.version) {
			t.Fatalf("%s: expected version %s, got %d %s", tc.path, tc.version, w.Code, w.Body.String())
		}
	}
}

func TestUnknownWPContentPathIs404(t *testing.T) {
	s, _ := newTestServer()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example/wp-content/uploads/2024/malware.php", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unmodeled wp-content path, got %d", w.Code)
	}
}

func TestWordPressPathsClassifiedAsWordPress(t *testing.T) {
	for _, p := range []string{"/readme.html", "/xmlrpc.php", "/wp-content/plugins/duplicator/readme.txt"} {
		if got := classify(p); got != "wordpress" {
			t.Errorf("classify(%q) = %q, want \"wordpress\"", p, got)
		}
	}
}
