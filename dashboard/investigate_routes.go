package main

import (
	"html/template"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// registerInvestigateRoutes wires up every path-parameter drill-down route
// that #1312 found decoding its own path segment twice: url.PathUnescape
// called on a substring of r.URL.Path, which net/http has already decoded
// exactly once by the time a handler sees it. A second decode pass makes
// %252F become / and corrupts otherwise-literal percent-escape-looking
// identifiers. Extracted into its own function (main() previously built
// these as inline closures) purely so it's callable against a throwaway
// http.NewServeMux() in tests -- Go's ServeMux only populates
// r.PathValue() for a request actually routed through ServeHTTP, so
// exercising the double-decode fix at all requires a real mux, not just
// calling a handler function directly the way most of this codebase's
// other handler tests do.
//
// Go 1.22+ ServeMux wildcards ({name}) match exactly one non-empty path
// segment and can't cross a literal "/" -- fine for every ID here (IPs,
// session IDs, and hex hashes never contain one), except CIDR notation
// itself, which always does ("203.0.113.0/24"). /investigate/cidr/{cidr...}
// uses the "rest of path" wildcard form specifically for that reason.
func (s *store) registerInvestigateRoutes(mux *http.ServeMux, tmpl *template.Template) {
	mux.HandleFunc("GET /investigate/ip/{ip}", func(w http.ResponseWriter, r *http.Request) {
		data, ok := s.attackerData(r.PathValue("ip"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "attacker", &data)
	})
	mux.HandleFunc("GET /investigate/ip/{ip}/fragment", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimSpace(r.PathValue("ip"))
		if _, err := netip.ParseAddr(ip); err != nil {
			http.NotFound(w, r)
			return
		}
		if s.es == nil {
			http.Error(w, "correlation backend unavailable", http.StatusServiceUnavailable)
			return
		}
		data := attackerPage{Generated: time.Now(), IP: ip, Correlation: s.es.correlateIP(ip, 100)}
		if !data.Correlation.Available {
			http.Error(w, "correlation backend unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "attacker-correlation-body", &data)
	})
	mux.HandleFunc("GET /investigate/ip/{ip}/state-fragment", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimSpace(r.PathValue("ip"))
		if _, err := netip.ParseAddr(ip); err != nil {
			http.NotFound(w, r)
			return
		}
		data := attackerPage{Generated: time.Now(), IP: ip}
		if s.ipBlocks != nil {
			data.Block = s.ipBlocks.get(ip)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "attacker-block-body", &data)
	})
	mux.HandleFunc("GET /investigate/cidr/{cidr...}", func(w http.ResponseWriter, r *http.Request) {
		data, ok := cidrCorrelationShell(r.PathValue("cidr"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "cidr-correlation", &data)
	})
	mux.HandleFunc("GET /investigate/cidr-fragment", func(w http.ResponseWriter, r *http.Request) {
		data, ok := s.cidrCorrelationData(r.URL.Query().Get("cidr"))
		if !ok {
			http.Error(w, "correlation backend unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "cidr-correlation-body", &data)
	})
	// #1312 confirmed bug: kind/value used to be packed into one
	// url.PathUnescape'd path segment, joined by \x00 (#354's own
	// clustersData grouping-key separator). The matching link
	// (ui/intel.html) escaped that joined string with the template's
	// urlquery func -- query-style escaping, which represents a space as
	// "+" -- but url.PathUnescape (path-style decoding) never translates
	// "+" back to a space. Any kind/value containing a literal space
	// ("Autonomous system", "Provider class", or any cluster value with
	// one) round-tripped as "Autonomous+system", the exact clusterIPs
	// lookup always missed, and the drill-down 404'd for every real
	// cluster. Separate query parameters use exactly one escaping
	// convention end to end and remove the \x00 separator from the URL
	// entirely.
	mux.HandleFunc("GET /investigate/cluster", func(w http.ResponseWriter, r *http.Request) {
		kind, value := r.URL.Query().Get("kind"), r.URL.Query().Get("value")
		data, _, ok := s.clusterCorrelationShell(kind, value)
		if !ok {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "cluster-correlation", &data)
	})
	mux.HandleFunc("GET /investigate/cluster/fragment", func(w http.ResponseWriter, r *http.Request) {
		data, ok := s.clusterCorrelationData(r.URL.Query().Get("kind"), r.URL.Query().Get("value"))
		if !ok {
			http.Error(w, "correlation backend unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "cluster-correlation-body", &data)
	})
	// #1327/#1328 shell+hydrate: this used to call s.sessionData(), a
	// synchronous O(n) scan of every cached event, before writing any
	// response bytes. sessionShell needs nothing but the URL's own id --
	// the real content is fetched client-side from the fragment route
	// just below (see sessionShell's own comment in intelligence.go). A
	// session id that doesn't resolve to any events now gets a 200 shell
	// instead of a 404 here; the fragment fetch 404s instead, and
	// hp-session-detail.js surfaces that as an in-page error state rather
	// than a browser-level not-found (same tradeoff the ghidra shell
	// above already accepts for the same reason).
	mux.HandleFunc("GET /sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.PathValue("id"))
		if id == "" || len(id) > 256 {
			http.NotFound(w, r)
			return
		}
		data := sessionShell(id)
		renderPage(w, tmpl, "session", &data)
	})
	mux.HandleFunc("GET /sessions/{id}/fragment", func(w http.ResponseWriter, r *http.Request) {
		data, ok := s.sessionData(r.PathValue("id"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "session-body", &data)
	})
	// #1288/#1285/#1286 shell+hydrate: this used to call s.ghidraData(),
	// a synchronous Elasticsearch round trip, before writing any response
	// bytes. ghidraDetailShell needs nothing but the URL's own hash --
	// the real content is fetched client-side from the fragment route
	// just below (see ghidraDetailShell's own comment in ghidra.go). A
	// hash that doesn't resolve to a real analysis now gets a 200 shell
	// instead of a 404 here; the fragment fetch 404s instead, and
	// hp-ghidra-report.js surfaces that as an in-page error state rather
	// than a browser-level not-found (same tradeoff tty_replay.go's own
	// viewer shell already accepts for the same reason).
	mux.HandleFunc("GET /ghidra/{sha}", func(w http.ResponseWriter, r *http.Request) {
		sha := r.PathValue("sha")
		if !hashName.MatchString(sha) {
			http.NotFound(w, r)
			return
		}
		data := ghidraDetailShell(strings.ToLower(sha))
		data.Analysis = r.URL.Query().Get("analysis")
		renderPage(w, tmpl, "ghidra", &data)
	})
	mux.HandleFunc("GET /ghidra/{sha}/fragment", func(w http.ResponseWriter, r *http.Request) {
		sha := r.PathValue("sha")
		if !hashName.MatchString(sha) {
			http.NotFound(w, r)
			return
		}
		data, err := s.ghidraData(strings.ToLower(sha), "")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "ghidra-detail-body", &data)
	})
	// Sandbox detail follows the same shell/fragment split as Ghidra above.
	// The shell validates only the URL job name and writes immediately; the
	// fragment performs the single document lookup after first paint. The
	// exact GET /sandbox/vnc route registered in routes.go remains the more
	// specific match for that literal path.
	mux.HandleFunc("GET /sandbox/{job}", func(w http.ResponseWriter, r *http.Request) {
		job := r.PathValue("job")
		if !sandboxJobName.MatchString(job) {
			http.NotFound(w, r)
			return
		}
		data := sandboxDetailShell(job)
		data.Analysis = r.URL.Query().Get("analysis")
		renderPage(w, tmpl, "sandbox", &data)
	})
	mux.HandleFunc("GET /sandbox/{job}/fragment", func(w http.ResponseWriter, r *http.Request) {
		job := r.PathValue("job")
		if !sandboxJobName.MatchString(job) {
			http.NotFound(w, r)
			return
		}
		data, err := s.sandboxData(job, "")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data.StaticYARA = s.yaraForSHA(data.Detail.SHA256).Matches
		_, captureErr := s.payloadPath(data.Detail.SHA256)
		data.Detail.CaptureAvailable = captureErr == nil
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		logTemplateErr("sandbox-detail-body", tmpl.ExecuteTemplate(w, "sandbox-detail-body", &data))
	})
	mux.HandleFunc("GET /revdeck/{sha}", func(w http.ResponseWriter, r *http.Request) {
		sha := r.PathValue("sha")
		if !hashName.MatchString(sha) {
			http.NotFound(w, r)
			return
		}
		data, err := revdeckData(sha)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "revdeck", &data)
	})
	mux.HandleFunc("GET /cape/{sha}", func(w http.ResponseWriter, r *http.Request) {
		sha := r.PathValue("sha")
		if !hashName.MatchString(sha) {
			http.NotFound(w, r)
			return
		}
		data := capeDetailShell(strings.ToLower(sha))
		renderPage(w, tmpl, "cape", &data)
	})
	mux.HandleFunc("GET /cape/{sha}/fragment", func(w http.ResponseWriter, r *http.Request) {
		sha := r.PathValue("sha")
		if !hashName.MatchString(sha) {
			http.NotFound(w, r)
			return
		}
		data, err := capeData(strings.ToLower(sha))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "cape-detail-body", &data)
	})
	mux.HandleFunc("GET /github-analysis/{sha}", func(w http.ResponseWriter, r *http.Request) {
		sha := r.PathValue("sha")
		if !hashName.MatchString(sha) {
			http.NotFound(w, r)
			return
		}
		data, err := s.githubAnalysisData(strings.ToLower(sha), "")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data.Analysis = r.URL.Query().Get("analysis")
		renderPage(w, tmpl, "github-analysis", &data)
	})
}
