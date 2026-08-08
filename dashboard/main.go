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

// rebuildIdleThreshold (#486) is how long the dashboard must see no requests
// before its periodic rebuild loop starts skipping ticks. A few multiples of
// the 15s tick itself, so one slow page load or a brief gap between an
// operator's clicks never trips it -- it only kicks in once nobody has been
// looking for a real stretch of time.
const rebuildIdleThreshold = 2 * time.Minute

// backgroundLoopsEnabled (#266) reports whether this instance should run
// the singleton alert/report loops -- see the call site's own comment for
// why exactly one dashboard replica, not every replica, must run them.
func backgroundLoopsEnabled() bool {
	return os.Getenv("DASHBOARD_BACKGROUND_LOOPS") != "false"
}

// healthzHandler (#828) always answers -- never refuses the connection,
// matching #353's own reasoning (see that fix's comment in main() below) --
// but reports 503 until the first rebuild() has real ES-derived data
// loaded, instead of an unconditional 200 the instant the listener starts.
// See the s.ready.Store(true) call site's comment for why this can't
// reintroduce #353's connection-refused/autoheal-restart-loop failure mode.
// A named function (not an inline closure registered in main()) so it's
// unit-testable on its own.
func healthzHandler(s *store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("starting"))
			return
		}
		w.Write([]byte("ok"))
	}
}

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
	setVNCBridgeOrigin(getenv("SANDBOX_VNC_BRIDGE_WS", ""))
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
			go g.threatIntelReloadLoop()
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
		// #384: loadGhidraResults/loadSandboxResults/loadGitHubAnalysisResults
		// are free functions called from many unrelated files (and directly by
		// tests, with no store around), not store methods -- a package-level
		// var lets them prefer #383's ES mirror when it's configured without a
		// signature change at every call site. Falls back to the local JSON
		// files unchanged whenever this stays nil (ELASTICSEARCH_URL unset,
		// all existing tests).
		esResultsClient = s.es
		s.mlAnomalies = &mlAnomalyStore{}
		s.llmAnalysis = &llmAnalysisStore{}
		s.agentCampaigns = &agentCampaignStore{}
		s.es.refresh()
		s.refreshMLAnomalies()
		s.refreshLLMAnalysis()
		s.refreshAgentCampaigns()
		go func() {
			for range time.Tick(time.Minute) {
				s.es.refresh()
				s.refreshMLAnomalies()
				s.refreshLLMAnalysis()
				s.refreshAgentCampaigns()
			}
		}()
	}
	// #151: query-time embedding for llm-analysis semantic search. Off
	// (ollamaURL left empty) unless OLLAMA_URL is both set and passes the
	// same local-only-endpoint check llm-worker's own config enforces --
	// serveLLMAnalysisSearch treats an empty ollamaURL as "unconfigured",
	// not a startup failure, same posture as GEOIP_CSV/ELASTICSEARCH_URL
	// above.
	if ollamaURL := os.Getenv("OLLAMA_URL"); ollamaURL != "" {
		if ollamaEndpointIsLocal(ollamaURL) {
			s.ollamaURL = ollamaURL
			s.embeddingModel = getenv("LLM_EMBEDDING_MODEL", "nomic-embed-text:latest")
		} else {
			fmt.Fprintf(os.Stderr, "dashboard: OLLAMA_URL %s rejected (must be a local/internal endpoint), semantic search disabled\n", ollamaURL)
		}
	}
	cooldown, err := time.ParseDuration(getenv("ALERT_COOLDOWN", "6h"))
	if err != nil || cooldown < 5*time.Minute {
		cooldown = 6 * time.Hour
	}
	// #494: no local-file fallback -- newAlertManager returns nil when s.es
	// is nil (Elasticsearch not configured), and every observe() call site
	// already treats a nil alertManager as "alerting disabled".
	s.alerts = newAlertManager(s.es, cooldown)
	// #913: same nil-when-unconfigured posture as s.alerts above -- every
	// call site (applyMLAnomalyAcks, serveMLAnomalyAck) already treats a nil
	// mlAnomalyAcks as "acknowledgment disabled".
	s.mlAnomalyAcks = newMLAnomalyAckManager(s.es)
	s.intelligence = &intelligenceStore{path: getenv("INTELLIGENCE_STATE_FILE", "/state/intelligence.json"), es: s.es}
	s.settings = newSettingsService(
		getenv("DASHBOARD_CONFIG_FILE", "/state/dashboard-config.json"),
		getenv("DASHBOARD_USERS_FILE", "/state/dashboard-users.json"),
		getenv("DASHBOARD_AUDIT_FILE", "/state/dashboard-audit.jsonl"),
		getenv("DASHBOARD_CONFIG_HISTORY_FILE", "/state/dashboard-config-history.jsonl"),
	)
	// #475: generated PDF reports are Elasticsearch-only, no local fallback
	// -- s.es is nil (Elasticsearch not configured) leaves definitions CRUD
	// working but generated-report methods return errReportsStorageUnavailable.
	s.reports = newReportStore(getenv("DASHBOARD_REPORTS_FILE", "/state/reports.json"), s.es)
	// #405 follow-up: run/recipe orchestration state is Elasticsearch-only,
	// no local fallback -- see workbench_domain.go's package comment on
	// workbenchService for why a run's document id being its own
	// idempotency key makes this safe to do (and safer than the old
	// local-disk mutex, which was never multi-instance-safe to begin with).
	s.workbench = newWorkbenchService(s.es)
	// #353: rebuild() walks every log file under LOG_DIR and used to run
	// synchronously here, before any route was even registered -- the
	// process refused every connection, including /healthz, until that
	// first full walk finished (confirmed live: tens of seconds on a
	// busy host, sometimes flapping the container's own healthcheck into
	// "unhealthy" and triggering an unwanted autoheal restart). Every
	// s.get()/s.getEvents() call in the handlers registered below already
	// runs per-request, not at init time, so there is nothing here that
	// actually needs the first rebuild to have completed -- a request
	// arriving before it finishes just sees the zero-value snapshot
	// (empty lists, zero counts) for a few seconds instead of the
	// connection being refused outright. notifyLoop's baseline pass is the
	// one real dependency (it must not alert on campaigns that already
	// existed at boot), so it stays sequenced after the first rebuild by
	// launching from inside the same goroutine rather than being
	// independently backgrounded.
	go func() {
		s.rebuild()
		// #828: distinct from #353's fix above -- that made the HTTP
		// listener itself start before rebuild() finishes, so a request
		// never gets refused outright. This marks the moment the first
		// rebuild's real ES-derived data is actually in s.snap, so
		// /healthz can tell "listening" apart from "has real data" (found
		// live: those were 60-120s apart on this host's real event
		// volume, during which a request saw an all-zero,
		// 0001-01-01-timestamped dashboard indistinguishable from
		// actually broken). /healthz still always answers immediately --
		// only its status code changes -- so this cannot reintroduce
		// #353's connection-refused/autoheal-restart-loop failure mode;
		// docker-compose.dashboard.yml's start_period is sized well above
		// the observed warm-up time specifically so a slow-but-normal
		// warm-up never counts as a real healthcheck failure either.
		s.ready.Store(true)
		// #266: with two dashboard replicas behind Traefik for zero-downtime
		// rolling updates, both would otherwise run these two loops
		// independently -- notifyLoop firing the same webhook alert twice
		// (once per replica) and reportScheduleLoop generating the same
		// scheduled PDF twice are real, user-visible duplicates, unlike
		// rebuild() above (each replica just recomputes its own in-memory
		// snapshot; no shared side effect to duplicate). DASHBOARD_BACKGROUND_LOOPS=false
		// on the secondary replica (docker-compose.dashboard.yml's
		// dashboard-b) opts it out of both, so exactly one replica ever
		// runs them -- not a general leader-election system, just enough to
		// avoid duplicate outbound side effects with a fixed two-replica
		// topology. Every replica still serves HTTP and runs rebuild()
		// regardless of this flag.
		if backgroundLoopsEnabled() {
			go s.notifyLoop(os.Getenv("ALERT_WEBHOOK_URL"))
			go s.reportScheduleLoop()
		}
		for range time.Tick(15 * time.Second) {
			// #486: skip this tick's log walk / ES round-trip once nobody has
			// hit the dashboard in a while -- touchActivity (below, wrapping
			// every request except /healthz) resets the idle clock, so the
			// very next tick after a request arrives rebuilds again. Bounded
			// staleness (at most one missed 15s tick) in exchange for not
			// paying rebuild's cost on an idle dashboard around the clock.
			if s.idleSince() > rebuildIdleThreshold {
				continue
			}
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
	http.HandleFunc("/healthz", healthzHandler(s))
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
	http.HandleFunc("/api/settings/es-storage-stats", s.serveSettingsESStorageStats)
	http.HandleFunc("/api/settings/reporter-stats", s.serveSettingsReporterStats)
	http.HandleFunc("/api/settings/services", s.serveSettingsServices)
	http.HandleFunc("/api/settings/services/", s.serveSettingsServiceItem)
	http.HandleFunc("/api/settings/audit", s.serveSettingsAudit)
	http.HandleFunc("/api/map-points", s.serveMapPoints)
	http.HandleFunc("/api/heatmap", s.serveHeatmap)
	http.HandleFunc("/api/attack-vectors", s.serveAttackVectors)
	http.HandleFunc("/api/quick-search", s.serveQuickSearch)
	http.HandleFunc("/api/filter-values", s.serveFilterValues)
	http.HandleFunc("/api/stream", s.serveEventsSSE)
	http.HandleFunc("/api/alerts", s.serveAlertsAPI)
	http.HandleFunc("/api/ml/anomalies", s.serveMLAnomaliesAPI)
	http.HandleFunc("/api/ml/stats", s.serveMLStatsAPI)
	http.HandleFunc("/api/llm/analysis", s.serveLLMAnalysisAPI)
	http.HandleFunc("/api/llm/analysis/search", s.serveLLMAnalysisSearch)
	http.HandleFunc("/api/agent-campaigns", s.serveAgentCampaignsAPI)
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
	http.HandleFunc("/api/reports/payload-options", s.serveReportPayloadOptions)
	http.HandleFunc("/api/reports/definitions", s.serveReportDefinitions)
	http.HandleFunc("/api/reports/definitions/", s.serveReportDefinitionByID)
	http.HandleFunc("/api/reports/payloads/", s.serveGeneratePayloadReport)
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
	http.HandleFunc("/investigate/cidr/", func(w http.ResponseWriter, r *http.Request) {
		cidr, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/investigate/cidr/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data, ok := s.cidrCorrelationData(cidr)
		if !ok {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "cidr-correlation", &data)
	})
	// #354: kind and value are carried as one URL-escaped path segment
	// (joined by \x00, the same separator clustersData's own internal
	// grouping key already uses) rather than two segments, since kind
	// itself contains spaces ("Autonomous system", "Provider class") that
	// would otherwise make it ambiguous where kind ends and value begins.
	http.HandleFunc("/investigate/cluster/", func(w http.ResponseWriter, r *http.Request) {
		raw, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/investigate/cluster/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		kind, value, ok := strings.Cut(raw, "\x00")
		if !ok {
			http.NotFound(w, r)
			return
		}
		data, ok := s.clusterCorrelationData(kind, value)
		if !ok {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "cluster-correlation", &data)
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
		data := s.clustersData(clustersRequestFilter(r))
		// Cluster Kind (Fingerprint/Payload/Autonomous system/Provider class)
		// only exists after clustersData's own aggregation groups events --
		// it isn't a storedEvent attribute the shared filter type can match
		// on, so it's filtered here as a narrow post-aggregation step (#280
		// Phase 4) instead of inside filter.match().
		if kind := r.URL.Query().Get("kind"); kind != "" {
			filtered := make([]clusterRow, 0, len(data.Rows))
			for _, row := range data.Rows {
				if row.Kind == kind {
					filtered = append(filtered, row)
				}
			}
			data.Rows = filtered
			data.Filters = append(data.Filters, "kind = "+kind)
		}
		data.filterBar = buildFilterBar(r, "/clusters",
			[2]string{"sensor", "Sensor"}, [2]string{"kind", "Kind"}, [2]string{"since", "Since (e.g. 24h)"})
		// #513/#59: exports exactly the current filtered scope (including the
		// post-aggregation kind= narrowing above), never the unfiltered set.
		data.ExportURL = "/export/clusters.csv"
		if encoded := r.URL.Query().Encode(); encoded != "" {
			data.ExportURL += "?" + encoded
		}
		renderPage(w, tmpl, "clusters", &data)
	})
	http.HandleFunc("/campaigns", func(w http.ResponseWriter, r *http.Request) {
		data := s.campaignsData(r)
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
		data := alertsPageData{
			snapshot:  s.get(),
			filterBar: buildFilterBar(r, "/alerts", [2]string{"state", "State"}, [2]string{"q", "Key or message contains"}),
		}
		renderPage(w, tmpl, "alerts", &data)
	})
	http.HandleFunc("/ml-anomalies", func(w http.ResponseWriter, r *http.Request) {
		if !s.mlPanelsEnabled() {
			http.NotFound(w, r)
			return
		}
		data := s.mlAnomaliesData(r)
		renderPage(w, tmpl, "ml-anomalies", &data)
	})
	http.HandleFunc("/llm-analysis", func(w http.ResponseWriter, r *http.Request) {
		data := s.llmAnalysisData(r)
		renderPage(w, tmpl, "llm-analysis", &data)
	})
	http.HandleFunc("/agent-campaigns", func(w http.ResponseWriter, r *http.Request) {
		if !s.mlPanelsEnabled() {
			http.NotFound(w, r)
			return
		}
		data := s.agentCampaignsData(r)
		renderPage(w, tmpl, "agent-campaigns", &data)
	})
	http.HandleFunc("/reports", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "reports", &data)
	})
	http.HandleFunc("/payloads", func(w http.ResponseWriter, r *http.Request) {
		data := s.payloadsData(parsePayloadsFilter(r))
		data.filterBar = buildFilterBar(r, "/payloads",
			[2]string{"sensor", "Sensor"}, [2]string{"since", "Since (e.g. 24h)"}, [2]string{"q", "Hash contains"})
		data.RowsURL = payloadsRowsURL(r)
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
		data := s.payloadsData(parsePayloadsFilter(r))
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
	http.HandleFunc("/gpu-queue/abort", serveGPUQueueAbort)
	http.HandleFunc("/github-analysis/submit", s.serveGitHubAnalysisSubmit)
	http.HandleFunc("/ml-anomalies/ack", s.serveMLAnomalyAck)
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
		data, err := ghidraData(strings.ToLower(sha), "")
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
	// #805: registered ahead of the "/sandbox/{job}" prefix route below --
	// Go's ServeMux resolves the longest matching pattern regardless of
	// registration order, so this exact match always wins over "vnc" being
	// parsed as a (nonexistent) job name there.
	http.HandleFunc("/sandbox/vnc", func(w http.ResponseWriter, r *http.Request) {
		s.serveSandboxVNC(w, r, tmpl)
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
	http.HandleFunc("/export/ips.csv", s.exportIPsCSV)
	http.HandleFunc("/export/campaigns.csv", s.exportCampaignsCSV)
	http.HandleFunc("/export/clusters.csv", s.exportClustersCSV)
	http.HandleFunc("/payload/", s.servePayload)
	http.HandleFunc("/tty/", func(w http.ResponseWriter, r *http.Request) { s.serveTTYReplay(w, r, tmpl) })
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

	// #486: touchActivity is the idle-rebuild loop's only signal that a real
	// viewer is present. /healthz is excluded deliberately -- Docker's own
	// healthcheck (and any external uptime monitor) hits it on a fixed
	// interval regardless of whether an operator is looking, which would
	// defeat idle detection entirely by keeping the dashboard "active"
	// forever on an unattended host.
	mux := http.DefaultServeMux
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			s.touchActivity()
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              getenv("LISTEN_ADDR", ":8080"),
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           handler,
	}
	srv.ListenAndServe()
}
