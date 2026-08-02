// dashboard — a tiny live view over the honeypot log volume.
//
// It walks /logs recursively every 15 seconds, parses every JSON-lines log the
// sensors export (cowrie, multipot, http-honeypot, dionaea, conpot, tanner —
// including rotated files like cowrie.json.2026-07-18), aggregates them into a
// snapshot and serves an auto-refreshing HTML page plus /api/stats.
//
// It exposes attacker data, so it has NO auth of its own — put it behind the
// auth-gateway or a Traefik basicAuth middleware (see the stack README).
package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		addr := getenv("LISTEN_ADDR", ":8080")
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		c := http.Client{Timeout: 3 * time.Second}
		if r, err := c.Get("http://" + addr + "/healthz"); err != nil || r.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	authAccountURL := validatedAuthAccountURL()
	setAuthFrameOrigin(authAccountURL)
	s := &store{
		dir:            getenv("LOG_DIR", "/logs"),
		yaraFile:       os.Getenv("YARA_RESULTS_FILE"),
		authAccountURL: authAccountURL,
	}
	for _, name := range strings.Split(os.Getenv("EXPECTED_SENSORS"), ",") {
		if name = strings.TrimSpace(name); name != "" && name != "portbridge" {
			s.expected = append(s.expected, name)
		}
	}
	// Multiple capture sources are supported: Dionaea malware, Cowrie uploads/
	// downloads and the dashboard's own inert copies of inline script commands.
	dirs := os.Getenv("PAYLOAD_DIRS")
	if dirs == "" {
		dirs = os.Getenv("BINARIES_DIR") // backwards compatibility
	}
	if d := getenv("SCRIPT_PAYLOAD_DIR", "/state/script-payloads"); d != "" {
		if err := os.MkdirAll(d, 0700); err == nil {
			s.scriptDir = d
			if dirs != "" {
				dirs += ","
			}
			dirs += d
		} else {
			fmt.Fprintf(os.Stderr, "dashboard: script payload directory %s: %v\n", d, err)
		}
	}
	seenPayloadDir := map[string]bool{}
	for _, d := range strings.Split(dirs, ",") {
		d = strings.TrimSpace(d)
		if d == "" || seenPayloadDir[d] {
			continue
		}
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			s.payloadDirs = append(s.payloadDirs, d)
			seenPayloadDir[d] = true
			fmt.Fprintf(os.Stderr, "dashboard: payload source enabled: %s\n", d)
		} else {
			fmt.Fprintf(os.Stderr, "dashboard: payload source %s unavailable\n", d)
		}
	}
	go s.payloadInventoryLoop()
	// Optional GeoIP: a CSV of "start_ip,end_ip,country" (DB-IP lite or a
	// GeoLite2 country CSV export). Absent/unreadable → enrichment stays off.
	// Prefer native GeoLite2 City/ASN MMDB. The CSV loader remains a fallback.
	if city, asn := os.Getenv("GEOIP_CITY_MMDB"), os.Getenv("GEOIP_ASN_MMDB"); city != "" || asn != "" {
		if g, err := loadGeoMMDB(city, asn, os.Getenv("THREAT_CIDRS_FILE")); err != nil {
			fmt.Fprintf(os.Stderr, "dashboard: MMDB GeoIP: %v (trying CSV fallback)\n", err)
		} else {
			s.geo = g
			fmt.Fprintf(os.Stderr, "dashboard: GeoLite2 City/ASN loaded (intel prefixes: %d)\n", len(g.intel))
		}
	}
	if p := os.Getenv("GEOIP_CSV"); s.geo == nil && p != "" {
		if g, err := loadGeoCSV(p); err != nil {
			fmt.Fprintf(os.Stderr, "dashboard: GEOIP_CSV %s: %v (geo off)\n", p, err)
		} else {
			s.geo = g
			fmt.Fprintf(os.Stderr, "dashboard: geoip loaded, %d ranges\n", len(g.ranges))
		}
	}
	if esURL := os.Getenv("ELASTICSEARCH_URL"); esURL != "" {
		s.es = newESClient(esURL, os.Getenv("FILEBEAT_URL"))
		s.mlAnomalies = &mlAnomalyStore{}
		s.es.refresh()
		s.refreshMLAnomalies()
		go func() {
			for range time.Tick(time.Minute) {
				s.es.refresh()
				s.refreshMLAnomalies()
			}
		}()
	}
	cooldown, err := time.ParseDuration(getenv("ALERT_COOLDOWN", "6h"))
	if err != nil || cooldown < 5*time.Minute {
		cooldown = 6 * time.Hour
	}
	s.alerts = newAlertManager(getenv("ALERT_STATE_FILE", "/state/alerts.json"), cooldown)
	s.intelligence = &intelligenceStore{path: getenv("INTELLIGENCE_STATE_FILE", "/state/intelligence.json")}
	s.settings = newSettingsService(
		getenv("DASHBOARD_CONFIG_FILE", "/state/dashboard-config.json"),
		getenv("DASHBOARD_USERS_FILE", "/state/dashboard-users.json"),
		getenv("DASHBOARD_AUDIT_FILE", "/state/dashboard-audit.jsonl"),
		getenv("DASHBOARD_CONFIG_HISTORY_FILE", "/state/dashboard-config-history.jsonl"),
	)
	s.reports = newReportStore(
		getenv("DASHBOARD_REPORTS_FILE", "/state/reports.json"),
		getenv("DASHBOARD_REPORTS_DIR", "/state/reports"),
	)
	s.workbench = newWorkbenchService(getenv("ANALYSIS_WORKBENCH_DIR", "/state/analysis-workbench"))
	s.rebuild()
	go s.notifyLoop(os.Getenv("ALERT_WEBHOOK_URL"))
	go s.reportScheduleLoop()
	go func() {
		for range time.Tick(15 * time.Second) {
			s.rebuild()
		}
	}()

	// Orphan-preference retention (Milestone F): accounts deleted or disabled
	// in auth-backend stop producing activity immediately — live introspection
	// already revokes their access on the very next request — and this sweep
	// expires their stored dashboard preferences after the retention window.
	retentionDays := 90
	if raw := strings.TrimSpace(os.Getenv("DASHBOARD_USER_RETENTION_DAYS")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			retentionDays = parsed
		}
	}
	go func() {
		maxAge := time.Duration(retentionDays) * 24 * time.Hour
		for {
			if removed := s.settings.users.SweepRetention(time.Now().UTC(), maxAge); removed > 0 {
				s.settings.retentionRemoved.Add(uint64(removed))
				fmt.Printf("dashboard: settings retention removed %d orphaned user projection(s)\n", removed)
			}
			time.Sleep(24 * time.Hour)
		}
	}()

	// `dict` lets the template pass named args into the reusable "tbl" block.
	// The presentation funcs wire the admin-configurable shell copy (Milestone
	// E) into every page at render time.
	funcs := templateFuncs(s, template.HTML(worldMapSVG))
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))

	html := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.get())
	})
	http.HandleFunc("/api/runtime", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(currentRuntime())
	})
	// Current identity is resolved live through auth-backend. Caller-supplied
	// X-Auth-* headers are intentionally ignored.
	http.HandleFunc("/api/whoami", s.serveWhoAmI)
	http.HandleFunc("/api/settings/me", s.serveSettingsMe)
	http.HandleFunc("/api/settings/me/preferences", s.servePreferencesPatch)
	http.HandleFunc("/api/settings/me/preferences/reset", s.servePreferencesReset)
	http.HandleFunc("/api/settings/config", s.serveSettingsConfig)
	http.HandleFunc("/api/settings/config/validate", s.serveSettingsConfigValidate)
	http.HandleFunc("/api/settings/config/rollback", s.serveSettingsConfigRollback)
	http.HandleFunc("/api/settings/config/history", s.serveSettingsConfigHistory)
	http.HandleFunc("/api/settings/users", s.serveSettingsUsers)
	http.HandleFunc("/api/settings/services", s.serveSettingsServices)
	http.HandleFunc("/api/settings/services/", s.serveSettingsServiceItem)
	http.HandleFunc("/api/settings/audit", s.serveSettingsAudit)
	http.HandleFunc("/api/map-points", s.serveMapPoints)
	http.HandleFunc("/api/quick-search", s.serveQuickSearch)
	http.HandleFunc("/api/stream", s.serveEventsSSE)
	http.HandleFunc("/api/alerts", s.serveAlertsAPI)
	http.HandleFunc("/api/ml/anomalies", s.serveMLAnomaliesAPI)
	http.HandleFunc("/api/ml/stats", s.serveMLStatsAPI)
	http.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.eventsData(r))
	})
	http.HandleFunc("/api/event-rows", func(w http.ResponseWriter, r *http.Request) {
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if offset < 0 {
			offset = 0
		}
		clone := r.Clone(r.Context())
		urlCopy := *r.URL
		query := r.URL.Query()
		query.Set("page", strconv.Itoa(offset/25+1))
		query.Set("per_page", "25")
		urlCopy.RawQuery = query.Encode()
		clone.URL = &urlCopy
		data := s.eventsData(clone)
		if offset >= data.Total {
			data.Events = nil
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "eventrows", data)
	})
	http.HandleFunc("/api/ip-rows", func(w http.ResponseWriter, r *http.Request) {
		data := s.ipsData(r)
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if offset < 0 {
			offset = 0
		}
		if offset >= len(data.Rows) {
			data.Rows = nil
		} else {
			data.Rows = data.Rows[offset:min(offset+25, len(data.Rows))]
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "iprows", data)
	})
	http.HandleFunc("/api/campaigns", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.get().Campaigns)
	})
	http.HandleFunc("/api/intelligence/archive", func(w http.ResponseWriter, r *http.Request) { s.intelligence.serveArchive(w, r) })
	http.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		if s.es == nil {
			http.Error(w, "Elasticsearch integration disabled", http.StatusServiceUnavailable)
			return
		}
		s.es.history(w, r, false)
	})
	http.HandleFunc("/api/dead-letters", func(w http.ResponseWriter, r *http.Request) {
		if s.es == nil {
			http.Error(w, "Elasticsearch integration disabled", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodDelete {
			s.es.purgeDeadLetters(w, r)
			return
		}
		s.es.deadLetters(w, r)
	})
	http.HandleFunc("/api/sandbox", serveSandboxAPI)
	http.HandleFunc("/api/sandbox/", serveSandboxAPI)
	http.HandleFunc("/export/sandbox/", serveSandboxExport)
	http.HandleFunc("/api/ghidra", serveGhidraAPI)
	http.HandleFunc("/api/ghidra/", serveGhidraAPI)
	http.HandleFunc("/export/ghidra/", serveGhidraExport)
	http.HandleFunc("/api/revdeck/", serveRevdeckAPI)
	http.HandleFunc("/api/github-analysis", s.serveGitHubAnalysisAPI)
	http.HandleFunc("/api/github-analysis/", s.serveGitHubAnalysisAPI)
	http.HandleFunc("/export/github-analysis/", s.serveGitHubAnalysisExport)
	http.HandleFunc("/api/payload-workbench/registry/", s.serveWorkbenchRegistry)
	http.HandleFunc("/api/payload-workbench/recipes", s.serveWorkbenchRecipes)
	http.HandleFunc("/api/payload-workbench/runs", s.serveWorkbenchRuns)
	http.HandleFunc("/api/payload-workbench/runs/", s.serveWorkbenchRuns)
	http.HandleFunc("/metrics", s.serveMetrics)
	http.HandleFunc("/export/history.json", func(w http.ResponseWriter, r *http.Request) {
		if s.es == nil {
			http.Error(w, "Elasticsearch integration disabled", http.StatusServiceUnavailable)
			return
		}
		s.es.history(w, r, true)
	})
	// Reports studio (R2): the single surface that designs, schedules, and
	// produces PDFs. The legacy /export/report.pdf endpoint and the per-page
	// PDF buttons were removed; dashboard pages link here instead.
	http.HandleFunc("/api/reports/templates", s.serveReportTemplates)
	http.HandleFunc("/api/reports/definitions", s.serveReportDefinitions)
	http.HandleFunc("/api/reports/definitions/", s.serveReportDefinitionByID)
	http.HandleFunc("/api/reports/generated", s.serveReportsGenerated)
	http.HandleFunc("/api/reports/generated/", s.serveReportGeneratedByID)
	// Settings modal fragment: the shell fetches this once per session and
	// opens it as a centered overlay; there is no standalone /settings page.
	// Admin panes render only for a live-introspected admin; any identity
	// failure degrades to the personal panes, never to an error page.
	http.HandleFunc("/api/settings/modal", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/settings/modal" {
			http.NotFound(w, r)
			return
		}
		html(w)
		data := settingsPageData{}
		if identity, err := resolveIdentity(r); err == nil && identity.Role == "admin" {
			data.Admin = true
		}
		tmpl.ExecuteTemplate(w, "settingsModal", data)
	})
	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		data := s.eventsData(r)
		renderPage(w, tmpl, "events", &data)
	})
	// The investigation command dock submits here. Resolution is server-side so
	// a query that names nothing lands on grouped results instead of a 404.
	http.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		s.serveSearch(w, r, tmpl)
	})
	http.HandleFunc("/ips", func(w http.ResponseWriter, r *http.Request) {
		data := s.ipsData(r)
		if len(data.Rows) > 25 {
			data.Rows = data.Rows[:25]
		}
		renderPage(w, tmpl, "ips", &data)
	})
	http.HandleFunc("/investigate/ip/", func(w http.ResponseWriter, r *http.Request) {
		ip, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/investigate/ip/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data, ok := s.attackerData(ip)
		if !ok {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "attacker", &data)
	})
	http.HandleFunc("/sessions/", func(w http.ResponseWriter, r *http.Request) {
		id, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/sessions/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data, ok := s.sessionData(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "session", &data)
	})
	http.HandleFunc("/clusters", func(w http.ResponseWriter, r *http.Request) {
		data := s.clustersData(parseFilter(r))
		renderPage(w, tmpl, "clusters", &data)
	})
	http.HandleFunc("/campaigns", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "campaigns", &data)
	})
	http.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "history", &data)
	})
	http.HandleFunc("/dead-letters", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "dead-letters", &data)
	})
	http.HandleFunc("/source-health", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "source-health", &data)
	})
	http.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "alerts", &data)
	})
	http.HandleFunc("/ml-anomalies", func(w http.ResponseWriter, r *http.Request) {
		if !s.mlPanelsEnabled() {
			http.NotFound(w, r)
			return
		}
		data := s.mlAnomaliesData()
		renderPage(w, tmpl, "ml-anomalies", &data)
	})
	http.HandleFunc("/reports", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "reports", &data)
	})
	http.HandleFunc("/payloads", func(w http.ResponseWriter, r *http.Request) {
		data := s.payloadsData(r.URL.Query().Get("source"))
		if r.URL.Query().Get("analysis") == "queued" && hashName.MatchString(r.URL.Query().Get("hash")) {
			guest := "isolated"
			switch sandboxTarget(r.URL.Query().Get("target")) {
			case targetWindows:
				guest = "Windows"
			case targetLinux:
				guest = "Linux"
			}
			data.Notice = "Sandbox analysis requested for " + shortHash(r.URL.Query().Get("hash")) +
				". The " + guest + " worker will process it shortly."
		}
		if len(data.Files) > 25 {
			data.Files = data.Files[:25]
		}
		renderPage(w, tmpl, "payloads", &data)
	})
	http.HandleFunc("/api/payload-rows", func(w http.ResponseWriter, r *http.Request) {
		data := s.payloadsData(r.URL.Query().Get("source"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if offset < 0 {
			offset = 0
		}
		if offset >= len(data.Files) {
			data.Files = nil
		} else {
			end := min(offset+25, len(data.Files))
			data.Files = data.Files[offset:end]
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "payloadrows", data)
	})
	http.HandleFunc("/sandbox/submit", s.serveSandboxSubmit)
	http.HandleFunc("/ghidra/submit", s.serveGhidraSubmit)
	http.HandleFunc("/github-analysis/submit", s.serveGitHubAnalysisSubmit)
	http.HandleFunc("/payload-workbench", func(w http.ResponseWriter, r *http.Request) {
		s.serveWorkbenchIndex(w, r, tmpl)
	})
	http.HandleFunc("/payload-workbench/results", func(w http.ResponseWriter, r *http.Request) {
		s.serveWorkbenchResults(w, r, tmpl)
	})
	http.HandleFunc("/payload-workbench/", func(w http.ResponseWriter, r *http.Request) {
		s.serveWorkbenchPage(w, r, tmpl)
	})
	http.HandleFunc("/ghidra", func(w http.ResponseWriter, r *http.Request) {
		data, _ := ghidraData("", r.URL.Query().Get("q"))
		data.Analysis = r.URL.Query().Get("analysis")
		renderPage(w, tmpl, "ghidra", &data)
	})
	http.HandleFunc("/ghidra/", func(w http.ResponseWriter, r *http.Request) {
		sha, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/ghidra/"))
		if err != nil || !hashName.MatchString(sha) {
			http.NotFound(w, r)
			return
		}
		data, err := ghidraData(sha, "")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data.Analysis = r.URL.Query().Get("analysis")
		renderPage(w, tmpl, "ghidra", &data)
	})
	http.HandleFunc("/revdeck/", func(w http.ResponseWriter, r *http.Request) {
		sha, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/revdeck/"))
		if err != nil || !hashName.MatchString(sha) {
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
	http.HandleFunc("/github-analysis", func(w http.ResponseWriter, r *http.Request) {
		data, _ := s.githubAnalysisData("", r.URL.Query().Get("q"))
		data.Analysis = r.URL.Query().Get("analysis")
		renderPage(w, tmpl, "github-analysis", &data)
	})
	http.HandleFunc("/github-analysis/", func(w http.ResponseWriter, r *http.Request) {
		sha, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/github-analysis/"))
		if err != nil || !hashName.MatchString(sha) {
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
	http.HandleFunc("/sandbox", func(w http.ResponseWriter, r *http.Request) {
		data, _ := sandboxData("", r.URL.Query().Get("q"))
		renderPage(w, tmpl, "sandbox", &data)
	})
	http.HandleFunc("/sandbox/", func(w http.ResponseWriter, r *http.Request) {
		job, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/sandbox/"))
		if err != nil || job == "" {
			http.NotFound(w, r)
			return
		}
		data, err := sandboxData(job, "")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data.StaticYARA = s.yaraForSHA(data.Detail.SHA256).Matches
		_, captureErr := s.payloadPath(data.Detail.SHA256)
		data.Detail.CaptureAvailable = captureErr == nil
		data.Analysis = r.URL.Query().Get("analysis")
		renderPage(w, tmpl, "sandbox", &data)
	})
	http.HandleFunc("/commands", func(w http.ResponseWriter, r *http.Request) {
		data := s.commandsData(r)
		renderPage(w, tmpl, "commands", &data)
	})
	http.HandleFunc("/payload-analysis/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/payload-analysis/")
		analysis, err := s.analyzePayload(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "payload-analysis", &analysis)
	})
	http.HandleFunc("/export/events.csv", s.exportEventsCSV)
	http.HandleFunc("/export/commands.csv", s.exportCommandsCSV)
	http.HandleFunc("/payload/", s.servePayload)
	staticHandler := http.FileServer(http.FS(staticAssets))
	http.Handle("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		staticHandler.ServeHTTP(w, r)
	}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data := s.get()
		renderPage(w, tmpl, "page", &data)
	})

	srv := &http.Server{
		Addr:              getenv("LISTEN_ADDR", ":8080"),
		ReadHeaderTimeout: 5 * time.Second,
	}
	srv.ListenAndServe()
}
