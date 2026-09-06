package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #2973: #2919 shipped only the classify() half of the CVE-2026-9586
// (Sangoma Switchvox) bait, so /pa was labelled correctly and then answered
// with the generic nginx 404 -- which ends the exchange instead of drawing
// the exploitation request. These cover the dedicated response body.

func TestSwitchvoxPAServesAnXMLFaultNotThe404(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		s, _ := newTestServer()
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(method, "http://example/pa", nil))

		if w.Code != http.StatusOK {
			t.Fatalf("%s /pa: got %d, want 200", method, w.Code)
		}
		body := w.Body.String()
		if strings.Contains(body, "404 Not Found") {
			t.Fatalf("%s /pa: still falling through to the generic 404: %s", method, body)
		}
		if !strings.Contains(body, "<errors>") || !strings.Contains(body, "could not be parsed") {
			t.Fatalf("%s /pa: expected a Switchvox XML error envelope, got %s", method, body)
		}
		if ct := w.Header().Get("Content-Type"); ct != "text/xml; charset=UTF-8" {
			t.Fatalf("%s /pa: Content-Type = %q, want text/xml; charset=UTF-8", method, ct)
		}
	}
}

// The whole point of answering at all is capturing what comes next, so the
// injected PhoneIP field must still reach the log.
func TestSwitchvoxPACapturesTheInjectedBody(t *testing.T) {
	s, output := newTestServer()
	payload := `<request><PhoneIP>1.2.3.4' UNION SELECT 1,2,3-- -</PhoneIP></request>`
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://example/pa", strings.NewReader(payload)))

	if !strings.Contains(output.String(), "UNION SELECT") {
		t.Fatalf("/pa POST body not logged: %s", output.String())
	}
	if !strings.Contains(output.String(), "switchvox-cve-2026-9586") {
		t.Fatalf("/pa not classified as the Switchvox campaign: %s", output.String())
	}
}

// Nothing in the response may identify the decoy. A Go error string, an
// internal path or a build identifier leaking here would undo the bait.
func TestSwitchvoxPAResponseLeaksNothingAboutTheHoneypot(t *testing.T) {
	s, _ := newTestServer()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://example/pa", strings.NewReader("junk")))

	body := strings.ToLower(w.Body.String())
	for _, leak := range []string{
		"honeypot", "apiary", "goroutine", "panic:", "/usr/local/go",
		"main.go", "net/http", "http-honeypot", "nexusai",
	} {
		if strings.Contains(body, leak) {
			t.Fatalf("/pa response leaks %q: %s", leak, w.Body.String())
		}
	}
	// The header set must stay the persona's -- a /pa that advertised a
	// different server than / is itself a tell.
	if got := w.Header().Get("Server"); got != "nginx" {
		t.Fatalf("/pa Server header = %q, want the persona's %q", got, "nginx")
	}
}

// #2973 must not disturb the paths that were already right: /pma still
// belongs to the phpMyAdmin bait, and a near-miss path still 404s.
func TestSwitchvoxPAExactMatchDoesNotSwallowNeighbouringPaths(t *testing.T) {
	cases := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{"/pma", http.StatusOK, "phpMyAdmin"},
		{"/pa/", http.StatusNotFound, "404 Not Found"},
		{"/path", http.StatusNotFound, "404 Not Found"},
	}
	for _, tc := range cases {
		s, _ := newTestServer()
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example"+tc.path, nil))
		if w.Code != tc.wantStatus || !strings.Contains(w.Body.String(), tc.wantBody) {
			t.Fatalf("%s: got %d %s, want %d containing %q",
				tc.path, w.Code, w.Body.String(), tc.wantStatus, tc.wantBody)
		}
	}
}

// The sibling WordPress XML-RPC bait declared text/xml at the call site and
// then handed the body to writeHTML, which overwrote it with text/html --
// found while wiring /pa (#2973). Both XML baits now go through writeXML.
func TestXMLRPCFaultIsServedAsXML(t *testing.T) {
	s, _ := newTestServer()
	w := httptest.NewRecorder()
	body := `<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName></methodCall>`
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://example/xmlrpc.php", strings.NewReader(body)))

	if ct := w.Header().Get("Content-Type"); ct != "text/xml; charset=UTF-8" {
		t.Fatalf("xmlrpc.php Content-Type = %q, want text/xml; charset=UTF-8", ct)
	}
}
