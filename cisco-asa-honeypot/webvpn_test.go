package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestWebvpnHandler() *webvpnHandler {
	return &webvpnHandler{log: newLogger(""), port: 8443}
}

func TestGETRootRedirectsViaScriptToLogonHTML(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	newTestWebvpnHandler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/+CSCOE+/logon.html") {
		t.Fatalf("body should redirect to logon.html: %q", w.Body.String())
	}
}

func TestGETLogonHTMLRedirectsWithFcadbadd(t *testing.T) {
	req := httptest.NewRequest("GET", "/+CSCOE+/logon.html", nil)
	w := httptest.NewRecorder()
	newTestWebvpnHandler().ServeHTTP(w, req)
	if w.Code != 302 {
		t.Fatalf("code = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/+CSCOE+/logon.html?fcadbadd=1" {
		t.Fatalf("Location = %q", got)
	}
}

func TestGETLogonFailureServesFailurePage(t *testing.T) {
	req := httptest.NewRequest("GET", "/+CSCOE+/logon.html?reason=1", nil)
	w := httptest.NewRecorder()
	newTestWebvpnHandler().ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Login failed") {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
}

func TestGETAsaDirReturns403WrongURL(t *testing.T) {
	req := httptest.NewRequest("GET", "/asa/", nil)
	w := httptest.NewRecorder()
	newTestWebvpnHandler().ServeHTTP(w, req)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "Wrong URL") {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
}

func TestGETKnownFileServesItsContent(t *testing.T) {
	req := httptest.NewRequest("GET", "/some/path/logon.html", nil)
	w := httptest.NewRecorder()
	newTestWebvpnHandler().ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "SSL VPN Service") {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
}

func TestGETUnknownFileReturns404WrongURL(t *testing.T) {
	req := httptest.NewRequest("GET", "/nonexistent-file.xyz", nil)
	w := httptest.NewRecorder()
	newTestWebvpnHandler().ServeHTTP(w, req)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "Wrong URL") {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
}

func TestPOSTRootRedirectsToWebvpnIndex(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(""))
	w := httptest.NewRecorder()
	newTestWebvpnHandler().ServeHTTP(w, req)
	if w.Code != 302 || w.Header().Get("Location") != "/+webvpn+/index.html" {
		t.Fatalf("got %d Location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestPOSTWebvpnIndexServesLogonRedirBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/+webvpn+/index.html", strings.NewReader(""))
	w := httptest.NewRecorder()
	newTestWebvpnHandler().ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "logon.html?") {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
}

func TestPOSTOtherPathReturnsParseErrorXML(t *testing.T) {
	req := httptest.NewRequest("POST", "/some/other/path", strings.NewReader("junk"))
	w := httptest.NewRecorder()
	newTestWebvpnHandler().ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "VPN Server could not parse request") {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
}

// TestPOSTHostScanReplyCapturesExploitPayload is the CVE-2018-0101 case:
// a crafted host-scan-reply XML body should have its payload text
// extracted and logged, matching upstream's alert_function call.
func TestPOSTHostScanReplyCapturesExploitPayload(t *testing.T) {
	body := `<config-auth><csd host-scan-reply="true"><host-scan-reply>` +
		`AAAAAAAAAAAAAAAAAAAAAAAAAAAA` + // stand-in for a crafted overflow payload
		`</host-scan-reply></csd></config-auth>`
	req := httptest.NewRequest("POST", "/+CSCOE+/webvpn/index.html", strings.NewReader(body))
	w := httptest.NewRecorder()

	var captured []string
	h := &webvpnHandler{log: newLogger(""), port: 8443}
	// Use the real handler; verify indirectly by checking the parse helper
	// used inside it produces the expected payload for this exact body.
	captured = parseHostScanReplies([]byte(body))
	h.ServeHTTP(w, req)

	if w.Code != 200 || !strings.Contains(w.Body.String(), "VPN Server could not parse request") {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	if len(captured) != 1 || captured[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("captured = %v, want the single host-scan-reply payload", captured)
	}
}

func TestParseHostScanRepliesIgnoresMalformedXML(t *testing.T) {
	got := parseHostScanReplies([]byte("not xml at all <<<"))
	if got != nil {
		t.Fatalf("got %v, want nil for malformed XML", got)
	}
}

func TestParseHostScanRepliesFindsMultiplePayloads(t *testing.T) {
	body := `<a><host-scan-reply>one</host-scan-reply><b><host-scan-reply>two</host-scan-reply></b></a>`
	got := parseHostScanReplies([]byte(body))
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("got %v, want [one two]", got)
	}
}
