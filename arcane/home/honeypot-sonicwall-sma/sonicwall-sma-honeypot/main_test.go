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
		relayed:   make(map[string]struct{}),
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

func TestPOSTToLoginFormOwnTargetIsNotClassifiedAsSSRF(t *testing.T) {
	req := httptest.NewRequest("POST", "/cgi-bin/welcome/welcome.cgi", strings.NewReader("username=admin&password=admin"))
	w := httptest.NewRecorder()

	out := captureStdout(t, func() {
		newTestHandler("http://127.0.0.1:1").ServeHTTP(w, req)
	})

	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("got %d %q, want empty 200", w.Code, w.Body.String())
	}
	if strings.Contains(out, `"event":"cve_2026_83548_ssrf_probe"`) {
		t.Fatalf("login form submission must not classify as SSRF probe, got %q", out)
	}
}

func TestGETToLoginFormOwnTargetStillClassifiesAsSSRF(t *testing.T) {
	req := httptest.NewRequest("GET", "/cgi-bin/welcome/welcome.cgi", nil)
	w := httptest.NewRecorder()

	out := captureStdout(t, func() {
		newTestHandler("http://127.0.0.1:1").ServeHTTP(w, req)
	})

	if !strings.Contains(out, `"event":"cve_2026_83548_ssrf_probe"`) {
		t.Fatalf("GET scanning the relay path must still classify as SSRF probe, got %q", out)
	}
}

func TestRelayIsRateLimitedToOneHopPerSourceIP(t *testing.T) {
	var hits int
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	}))
	defer relay.Close()

	h := newTestHandler(relay.URL)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/cgi-bin/x", nil)
		w := httptest.NewRecorder()
		captureStdout(t, func() {
			h.ServeHTTP(w, req)
		})
	}

	if hits != 1 {
		t.Fatalf("relay hit %d times, want exactly 1 (rate-limited to one hop per source IP)", hits)
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
