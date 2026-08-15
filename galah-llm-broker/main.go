// galah-llm-broker is the sole bridge between the attacker-facing galah
// sensor and the shared Ollama instance on the honeypot-llm network (see
// analysis/ghidra/docker-compose.ghidra.yml's own "sensors must never be
// able to submit prompts or observe model traffic" invariant -- galah's
// container is deliberately never attached to that network itself).
//
// It proxies exactly the two Ollama routes langchaingo's ollama client
// calls (confirmed against the vendored client source, not assumed):
// /api/generate and /api/chat. Everything else 404s. Request bodies are
// capped and upstream calls are time-bounded so an attacker-controlled
// HTTP request (which becomes the entire LLM prompt verbatim -- galah's
// own llm.CreateMessageContent dumps the raw request into the prompt with
// no size limit of its own) can't turn into unbounded prompt size or a
// stuck request against the shared GPU backend.
package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

var allowedPaths = map[string]bool{
	"/api/generate": true,
	"/api/chat":     true,
}

func main() {
	target := envOr("OLLAMA_URL", "http://ollama:11434")
	listen := envOr("LISTEN_ADDR", ":11434")
	maxBody := envIntOr("MAX_BODY_BYTES", 65536)
	upstreamTimeout := time.Duration(envIntOr("UPSTREAM_TIMEOUT_SECONDS", 8)) * time.Second

	targetURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("galah-llm-broker: invalid OLLAMA_URL %q: %s", target, err)
	}

	client := &http.Client{Timeout: upstreamTimeout}

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

		ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
		defer cancel()

		upstreamURL := *targetURL
		upstreamURL.Path = r.URL.Path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL.String(), bytes.NewReader(body))
		if err != nil {
			http.Error(w, "bad upstream request", http.StatusInternalServerError)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			req.Header.Set("Content-Type", ct)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("galah-llm-broker: upstream error: %s", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	log.Printf("galah-llm-broker: listening on %s, forwarding to %s (max body %d bytes, upstream timeout %s)", listen, target, maxBody, upstreamTimeout)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
