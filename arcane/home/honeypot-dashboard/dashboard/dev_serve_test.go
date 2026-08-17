package main

// dev_serve_test.go — local design-review harness, NOT for CI.
//
// Boots the complete real dashboard (templates, routes, trackedHandler)
// against a real Elasticsearch (ELASTICSEARCH_URL, e.g. an SSH tunnel to the
// homeserver) with the OIDC layer stubbed out the same way
// configureIdentityTestBackend does in authorization_test.go: an in-memory
// session store holding one admin session with a frozen clock, injected into
// every request server-side, so no Keycloak/Redis is needed.
//
// Run:
//   DEV_SERVE=1 LISTEN_ADDR=127.0.0.1:19201 \
//   ELASTICSEARCH_URL=http://127.0.0.1:19200 LOG_DIR=/path/to/skeleton \
//   go test -run TestDevServe -timeout 0 -count 1 .
//
// Guarded by DEV_SERVE so a plain `go test ./...` skips it instantly.

import (
	"context"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDevServe(t *testing.T) {
	if os.Getenv("DEV_SERVE") != "1" {
		t.Skip("dev harness; set DEV_SERVE=1 to serve")
	}

	// --- OIDC stub: one eternal admin session, frozen clock -------------
	sessions := &memorySessionStore{values: make(map[string][]byte)}
	now := time.Now().UTC()
	auth := &oidcAuth{sessions: sessions, now: func() time.Time { return now }}
	session := oidcSession{
		Identity: authenticatedIdentity{
			Subject:     "b65ab0dc-cc07-4b3d-9af0-b482dbb4b096",
			Username:    "xore",
			DisplayName: "Xore (design lab)",
			Role:        "admin",
		},
		TokenExpiry:   now.Add(oidcSessionMaxAge),
		CreatedAt:     now,
		LastValidated: now,
	}
	if err := auth.putJSON(context.Background(), "oidc:session:"+testAuthCookie, session, oidcSessionMaxAge); err != nil {
		t.Fatal(err)
	}
	dashboardOIDC = auth

	// --- store, mirroring main()'s nil-when-unconfigured posture --------
	state := t.TempDir()
	s := &store{dir: getenv("LOG_DIR", state)}
	if esURL := os.Getenv("ELASTICSEARCH_URL"); esURL != "" {
		s.es = newESClient(esURL, os.Getenv("FILEBEAT_URL"))
		esResultsClient = s.es
		s.mlAnomalies = &mlAnomalyStore{}
		s.llmAnalysis = &llmAnalysisStore{}
		s.agentCampaigns = &agentCampaignStore{}
		s.authEvents = &authEventStore{}
		s.es.refresh()
		s.refreshMLAnomalies()
		s.refreshLLMAnalysis()
		s.refreshAgentCampaigns()
		s.refreshAuthEvents()
	}
	// Write-capable services get NO ES client: the tunnel points at the real
	// production Elasticsearch and this lab must stay read-only. Each of
	// these treats nil-ES as "degraded/read-only, compiled defaults" per
	// main.go's own comments, so the pages still render.
	s.alerts = newAlertManager(nil, 6*time.Hour)
	s.ipBlocks = newIPBlockManager(nil)
	s.canarytokensHistory = newCanarytokensManager(s.es) // read-only history
	s.mlAnomalyAcks = newMLAnomalyAckManager(nil)
	s.intelligence = &intelligenceStore{path: filepath.Join(state, "intelligence.json"), es: s.es}
	s.settings = newSettingsService(
		nil,
		filepath.Join(state, "dashboard-audit.jsonl"),
		filepath.Join(state, "dashboard-config-history.jsonl"),
	)
	s.reports = newReportStore(s.es) // read: report library/PDF viewing; generation stays untested here
	s.workbench = newWorkbenchService(nil)

	go func() {
		s.rebuild()
		s.ready.Store(true)
		for range time.Tick(30 * time.Second) {
			s.es.refresh()
			s.rebuild()
		}
	}()

	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	handler := trackedHandler(s, dashboardOIDC, s.routes(tmpl))

	// STATIC_DIR: serve /static/* from disk instead of the embedded copy so
	// CSS/JS design variants iterate without recompiling.
	var static http.Handler
	if dir := os.Getenv("STATIC_DIR"); dir != "" {
		static = http.StripPrefix("/static/", http.FileServer(http.Dir(dir)))
	}

	// Inject the stub session cookie server-side so the browser needs no
	// __Host- cookie gymnastics on plain http://localhost.
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if static != nil && len(r.URL.Path) > 8 && r.URL.Path[:8] == "/static/" {
			w.Header().Set("Cache-Control", "no-store")
			static.ServeHTTP(w, r)
			return
		}
		r.Header.Add("Cookie", oidcSessionCookie+"="+testAuthCookie)
		// The playground's split-compare embeds pages in iframes; the app's
		// own anti-framing headers would block that, so drop them here
		// (design lab only, loopback only).
		handler.ServeHTTP(&frameableWriter{ResponseWriter: w}, r)
	})

	addr := getenv("LISTEN_ADDR", "127.0.0.1:19201")
	t.Logf("design-lab dashboard on http://%s (ES=%s)", addr, os.Getenv("ELASTICSEARCH_URL"))
	if err := http.ListenAndServe(addr, wrapped); err != nil {
		t.Fatal(err)
	}
}

// frameableWriter strips anti-framing response headers just before they are
// flushed, so the design-lab compare page can iframe the dashboard. Write is
// overridden too: without it, a handler that never calls WriteHeader
// explicitly flushes headers through the inner writer's implicit 200 and the
// strip never runs.
type frameableWriter struct {
	http.ResponseWriter
	wrote bool
}

func (f *frameableWriter) WriteHeader(code int) {
	if f.wrote {
		return
	}
	f.wrote = true
	h := f.Header()
	h.Del("X-Frame-Options")
	if csp := h.Get("Content-Security-Policy"); csp != "" {
		h.Set("Content-Security-Policy", stripFrameAncestors(csp))
	}
	f.ResponseWriter.WriteHeader(code)
}

func (f *frameableWriter) Write(b []byte) (int, error) {
	if !f.wrote {
		f.WriteHeader(http.StatusOK)
	}
	return f.ResponseWriter.Write(b)
}

// Flush keeps /api/stream's SSE working through the wrapper.
func (f *frameableWriter) Flush() {
	if fl, ok := f.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func stripFrameAncestors(csp string) string {
	parts := strings.Split(csp, ";")
	kept := parts[:0]
	for _, p := range parts {
		if !strings.Contains(strings.ToLower(p), "frame-ancestors") {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ";")
}
