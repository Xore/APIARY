package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestHandler(t *testing.T, upstream *httptest.Server, maxBody int) http.Handler {
	t.Helper()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := upstream.Client()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !allowedPaths[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, int64(maxBody))
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		req, err := http.NewRequest(http.MethodPost, targetURL.String()+r.URL.Path, strings.NewReader(string(body)))
		if err != nil {
			http.Error(w, "bad upstream request", http.StatusInternalServerError)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	return mux
}

func TestAllowedPathIsForwarded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("upstream got path %q, want /api/chat", r.URL.Path)
		}
		w.Write([]byte(`{"message":"ok"}`))
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream, 65536)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(`{"model":"qwen3:8b"}`))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != `{"message":"ok"}` {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestDisallowedPathIs404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should never be called for a disallowed path")
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream, 65536)
	for _, path := range []string{"/api/embeddings", "/api/pull", "/api/tags", "/"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("path %q: status = %d, want 404", path, rr.Code)
		}
	}
}

func TestGetIsRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should never be called for GET")
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream, 65536)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/chat", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should never be called for an oversized body")
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream, 16)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/generate", strings.NewReader(strings.Repeat("a", 1000)))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
}

func TestEnvIntOrParsesOrFallsBack(t *testing.T) {
	if got := envIntOr("GALAH_BROKER_TEST_UNSET_VAR", 8); got != 8 {
		t.Fatalf("envIntOr fallback = %d, want 8", got)
	}
	t.Setenv("GALAH_BROKER_TEST_SET_VAR", "42")
	if got := envIntOr("GALAH_BROKER_TEST_SET_VAR", 8); got != 42 {
		t.Fatalf("envIntOr set = %d, want 42", got)
	}
	t.Setenv("GALAH_BROKER_TEST_BAD_VAR", "not-a-number")
	if got := envIntOr("GALAH_BROKER_TEST_BAD_VAR", 8); got != 8 {
		t.Fatalf("envIntOr bad-value fallback = %d, want 8", got)
	}
}

func TestUpstreamTimeoutSurfacesAsBadGateway(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("too slow"))
	}))
	defer upstream.Close()

	targetURL, _ := url.Parse(upstream.URL)
	client := &http.Client{Timeout: 5 * time.Millisecond}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(http.MethodPost, targetURL.String()+r.URL.Path, nil)
		if _, err := client.Do(req); err != nil {
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/generate", nil)
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 on upstream timeout", rr.Code)
	}
}
