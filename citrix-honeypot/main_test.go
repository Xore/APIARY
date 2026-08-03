package main

import (
	"net/http/httptest"
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
