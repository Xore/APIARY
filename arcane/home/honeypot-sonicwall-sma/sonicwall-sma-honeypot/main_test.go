package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestHandler(relayURL string) *handler {
	return &handler{
		log:       newLogger(""),
		port:      8443,
		relayURL:  relayURL,
		relayHTTP: &http.Client{Timeout: 2 * time.Second},
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	fn()
	os.Stdout = orig
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestGETRootServesWorkPlaceLoginPage(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	newTestHandler("http://127.0.0.1:1").ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Work Place") {
		t.Fatalf("got %d %q, want Work Place login page", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Server"); got != "Apache" {
		t.Fatalf("Server header = %q, want Apache", got)
	}
}

func TestGETOtherPathAlsoServesLoginPage(t *testing.T) {
	req := httptest.NewRequest("GET", "/some/random/path", nil)
	w := httptest.NewRecorder()
	newTestHandler("http://127.0.0.1:1").ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Work Place") {
		t.Fatalf("got %d %q, want Work Place login page", w.Code, w.Body.String())
	}
}

func TestSSRFProbeClassifiedAndServesAMCHopPage(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer relay.Close()

	req := httptest.NewRequest("GET", "/cgi-bin/welcome/welcome.cgi", nil)
	w := httptest.NewRecorder()

	out := captureStdout(t, func() {
		newTestHandler(relay.URL).ServeHTTP(w, req)
	})

	if w.Code != 200 || !strings.Contains(w.Body.String(), "Appliance Management Console") {
		t.Fatalf("got %d %q, want AMC hop page", w.Code, w.Body.String())
	}
	if !strings.Contains(out, `"event":"cve_2026_83548_ssrf_probe"`) {
		t.Fatalf("expected ssrf_probe event logged, got %q", out)
	}
	if !strings.Contains(out, `"event":"cve_2026_83548_ssrf_relay"`) || !strings.Contains(out, "status=200") {
		t.Fatalf("expected successful relay event logged, got %q", out)
	}
}

func TestSSRFRelayFailureIsLogged(t *testing.T) {
	req := httptest.NewRequest("GET", "/cgi-bin/welcome/welcome.cgi", nil)
	w := httptest.NewRecorder()

	out := captureStdout(t, func() {
		newTestHandler("http://127.0.0.1:1").ServeHTTP(w, req)
	})

	if w.Code != 200 || !strings.Contains(w.Body.String(), "Appliance Management Console") {
		t.Fatalf("got %d %q, want AMC hop page even on relay failure", w.Code, w.Body.String())
	}
	if !strings.Contains(out, `"event":"cve_2026_83548_ssrf_relay"`) || !strings.Contains(out, "relay failed") {
		t.Fatalf("expected failed relay event logged, got %q", out)
	}
}

func TestAMCActionPathClassifiesStageTwoWithBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/cgi-bin/amc/rollbackConfirm.action", strings.NewReader("hotfix=../../etc/passwd"))
	w := httptest.NewRecorder()

	out := captureStdout(t, func() {
		newTestHandler("http://127.0.0.1:1").ServeHTTP(w, req)
	})

	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", w.Code, w.Body.String())
	}
	if !strings.Contains(out, `"event":"cve_2026_83549_amc_command_injection_probe"`) {
		t.Fatalf("expected amc_command_injection_probe event logged, got %q", out)
	}
	if !strings.Contains(out, "hotfix=../../etc/passwd") {
		t.Fatalf("expected POST body logged, got %q", out)
	}
}

func TestUnhandledMethodIsLoggedAndReturnsEmpty200(t *testing.T) {
	req := httptest.NewRequest("OPTIONS", "/foo", nil)
	w := httptest.NewRecorder()

	out := captureStdout(t, func() {
		newTestHandler("http://127.0.0.1:1").ServeHTTP(w, req)
	})

	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", w.Code, w.Body.String())
	}
	if !strings.Contains(out, `"event":"method_options"`) {
		t.Fatalf("expected method_options event logged, got %q", out)
	}
}
