package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

// routes (#1323, item 2) builds the dashboard's complete route table on a
// dedicated http.ServeMux, replacing the implicit http.DefaultServeMux
// every registration used to share with anything else in the process (or
// any future import) that might also touch the package-level default mux.
// Extracted out of main() -- which isn't itself unit-testable, since it
// starts a real listener and never returns -- specifically so the full,
// real registration set can be exercised in a test: net/http.ServeMux
// panics at registration time on an ambiguous pattern conflict (#1312
// found this the hard way, converting a handful of routes to method-scoped
// wildcards), and that class of bug is invisible to go build/go vet/go
// test unless something actually calls Handle/HandleFunc for the complete
// set at once. See routes_test.go's TestRoutesRegisterWithoutConflict.
func (s *store) routes(tmpl *template.Template) *http.ServeMux {
	mux := http.NewServeMux()

	html := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	mux.HandleFunc("GET /healthz", healthzHandler(s))
	mux.HandleFunc("GET /auth/login", dashboardOIDC.serveLogin)
	mux.HandleFunc("GET /auth/callback", dashboardOIDC.serveCallback)
	mux.HandleFunc("GET /auth/logout", dashboardOIDC.serveLogout)
	mux.HandleFunc("GET /api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.get())
	})
	mux.HandleFunc("GET /api/runtime", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(currentRuntime())
	})
	// Current identity comes only from the server-side OIDC session.
	// Caller-supplied X-Auth-* headers are intentionally ignored.
	mux.HandleFunc("GET /api/whoami", s.serveWhoAmI)
	mux.HandleFunc("GET /api/settings/me", s.serveSettingsMe)
	mux.HandleFunc("PATCH /api/settings/me/preferences", s.servePreferencesPatch)
	mux.HandleFunc("POST /api/settings/me/preferences/reset", s.servePreferencesReset)
	mux.HandleFunc("GET /api/settings/config", s.serveSettingsConfig)
	mux.HandleFunc("PATCH /api/settings/config", s.serveSettingsConfig)
	mux.HandleFunc("POST /api/settings/config/validate", s.serveSettingsConfigValidate)
	mux.HandleFunc("POST /api/settings/config/rollback", s.serveSettingsConfigRollback)
	mux.HandleFunc("GET /api/settings/config/history", s.serveSettingsConfigHistory)
	mux.HandleFunc("GET /api/settings/users", s.serveSettingsUsers)
	mux.HandleFunc("GET /api/settings/es-storage-stats", s.serveSettingsESStorageStats)
	mux.HandleFunc("GET /api/settings/reporter-stats", s.serveSettingsReporterStats)
	mux.HandleFunc("GET /api/settings/services", s.serveSettingsServices)
	mux.HandleFunc("GET /api/settings/services/{name}/logs", s.serveSettingsServiceItem)
	mux.HandleFunc("POST /api/settings/services/{name}/{action}", s.serveSettingsServiceItem)
	mux.HandleFunc("GET /api/settings/audit", s.serveSettingsAudit)
	// #1487: dashboard-driven Canarytoken creation for external use.
	mux.HandleFunc("GET /api/settings/canarytokens/types", s.serveCanarytokensTypes)
	mux.HandleFunc("GET /api/settings/canarytokens", s.serveCanarytokensList)
	mux.HandleFunc("POST /api/settings/canarytokens/create", s.serveCanarytokensCreate)
	mux.HandleFunc("GET /api/settings/canarytokens/{id}/download", s.serveCanarytokensDownload)
	mux.HandleFunc("GET /api/problem-reports", s.serveProblemReports)
	mux.HandleFunc("POST /api/problem-reports", s.serveProblemReports)
	mux.HandleFunc("PATCH /api/problem-reports/{id}", s.serveProblemReportItem)
	mux.HandleFunc("GET /admin/problem-reports", func(w http.ResponseWriter, r *http.Request) {
		s.serveProblemReportsPage(w, r, tmpl)
	})
	mux.HandleFunc("GET /api/map-points", s.serveMapPoints)
	mux.HandleFunc("GET /api/os-distribution", s.serveOSDistribution)
	mux.HandleFunc("GET /api/endlessh-held-histogram", s.serveEndlesshHeldHistogram)
	mux.HandleFunc("GET /api/ml-backlog", s.serveMLBacklog)
	mux.HandleFunc("GET /api/netflow-bytes", s.serveNetflowBytes)
	mux.HandleFunc("GET /api/netflow-packets", s.serveNetflowPackets)
	mux.HandleFunc("GET /api/dionaea-cves", s.serveDionaeaCVEs)
	mux.HandleFunc("GET /api/tls-fingerprints", s.serveTLSFingerprints)
	mux.HandleFunc("GET /api/ssh-fingerprints", s.serveSSHFingerprints)
	mux.HandleFunc("GET /api/ml-anomaly-scores", s.serveMLAnomalyScores)
	mux.HandleFunc("GET /api/anomaly-trend", s.serveAnomalyTrend)
	mux.HandleFunc("GET /api/attacker-graph", s.serveAttackerGraph)
	mux.HandleFunc("GET /api/attacker-fusion", s.serveAttackerFingerprintFusion)
	mux.HandleFunc("GET /api/ghidra-callgraph/{sha}", s.serveGhidraInteractiveCallGraph)
	mux.HandleFunc("GET /api/attck-coverage", s.serveAttckCoverage)
	mux.HandleFunc("GET /api/campaign-timeline", s.serveCampaignTimeline)
	mux.HandleFunc("GET /api/kill-chain-sankey", s.serveKillChainSankey)
	mux.HandleFunc("GET /api/heatmap", s.serveHeatmap)
	mux.HandleFunc("GET /api/attack-vectors", s.serveAttackVectors)
	mux.HandleFunc("GET /api/quick-search", s.serveQuickSearch)
	mux.HandleFunc("GET /api/filter-values", s.serveFilterValues)
	mux.HandleFunc("GET /api/stream", s.serveEventsSSE)
	mux.HandleFunc("GET /api/alerts", s.serveAlertsAPI)
	mux.HandleFunc("POST /api/alerts", s.serveAlertsAPI)
	mux.HandleFunc("GET /api/ml/anomalies", s.serveMLAnomaliesAPI)
	mux.HandleFunc("GET /api/ml/stats", s.serveMLStatsAPI)
	mux.HandleFunc("GET /api/llm/analysis", s.serveLLMAnalysisAPI)
	mux.HandleFunc("GET /api/llm/analysis/search", s.serveLLMAnalysisSearch)
	mux.HandleFunc("GET /api/agent-campaigns", s.serveAgentCampaignsAPI)
	mux.HandleFunc("GET /api/auth-events", s.serveAuthEventsAPI)
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.eventsData(r))
	})
	mux.HandleFunc("GET /api/event-rows", func(w http.ResponseWriter, r *http.Request) {
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
		logTemplateErr("eventrows", tmpl.ExecuteTemplate(w, "eventrows", data))
	})
	mux.HandleFunc("GET /api/ip-rows", func(w http.ResponseWriter, r *http.Request) {
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
		logTemplateErr("iprows", tmpl.ExecuteTemplate(w, "iprows", data))
	})
	mux.HandleFunc("GET /api/campaigns", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.get().Campaigns)
	})
	mux.HandleFunc("GET /api/intelligence/archive", func(w http.ResponseWriter, r *http.Request) { s.intelligence.serveArchive(w, r) })
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		if s.es == nil {
			http.Error(w, "Elasticsearch integration disabled", http.StatusServiceUnavailable)
			return
		}
		s.es.history(w, r, false)
	})
	mux.HandleFunc("GET /api/dead-letters", func(w http.ResponseWriter, r *http.Request) {
		if s.es == nil {
			http.Error(w, "Elasticsearch integration disabled", http.StatusServiceUnavailable)
			return
		}
		s.es.deadLetters(w, r)
	})
	mux.HandleFunc("DELETE /api/dead-letters", func(w http.ResponseWriter, r *http.Request) {
		if s.es == nil {
			http.Error(w, "Elasticsearch integration disabled", http.StatusServiceUnavailable)
			return
		}
		s.es.purgeDeadLetters(w, r)
	})
	mux.HandleFunc("GET /api/sandbox", s.serveSandboxAPI)
	mux.HandleFunc("GET /api/sandbox/", s.serveSandboxAPI)
	mux.HandleFunc("GET /export/sandbox/", s.serveSandboxExport)
	mux.HandleFunc("GET /api/ghidra", s.serveGhidraAPI)
	mux.HandleFunc("GET /api/ghidra/", s.serveGhidraAPI)
	mux.HandleFunc("GET /export/ghidra/", serveGhidraExport)
	mux.HandleFunc("GET /api/revdeck/", serveRevdeckAPI)
	mux.HandleFunc("GET /api/cape/", serveCapeAPI)
	mux.HandleFunc("GET /api/github-analysis", s.serveGitHubAnalysisAPI)
	mux.HandleFunc("GET /api/github-analysis/", s.serveGitHubAnalysisAPI)
	mux.HandleFunc("GET /export/github-analysis/", s.serveGitHubAnalysisExport)
	mux.HandleFunc("GET /export/portbridge-manual-blackhole.txt", s.serveManualBlackholeExport)
	// #1312: an explicit method, not just serveIPBlockAction's own internal
	// r.Method check -- net/http.ServeMux (Go 1.22+) requires this,
	// otherwise this pattern and registerInvestigateRoutes' "GET
	// /investigate/ip/{ip}" (below) aren't a strict subset of one another
	// (this one covers every OTHER method for exactly this path that the
	// GET-only wildcard doesn't) and ServeMux panics at startup rather than
	// silently picking a winner -- confirmed live, this exact conflict.
	mux.HandleFunc("POST /investigate/ip/block", s.serveIPBlockAction)
	mux.HandleFunc("GET /api/payload-workbench/registry/", s.serveWorkbenchRegistry)
	mux.HandleFunc("GET /api/payload-workbench/model-status", s.serveWorkbenchModelStatus)
	mux.HandleFunc("GET /api/payload-workbench/correlation/", s.serveWorkbenchCorrelation)
	mux.HandleFunc("GET /api/payload-workbench/recipes", s.serveWorkbenchRecipes)
	mux.HandleFunc("POST /api/payload-workbench/recipes", s.serveWorkbenchRecipes)
	mux.HandleFunc("GET /api/payload-workbench/runs", s.serveWorkbenchRuns)
	mux.HandleFunc("POST /api/payload-workbench/runs", s.serveWorkbenchRuns)
	mux.HandleFunc("GET /api/payload-workbench/runs/{id}", s.serveWorkbenchRuns)
	mux.HandleFunc("POST /api/payload-workbench/runs/{id}/children/{n}/{action}", s.serveWorkbenchRuns)
	mux.HandleFunc("GET /metrics", s.serveMetrics)
	mux.HandleFunc("GET /export/history.json", func(w http.ResponseWriter, r *http.Request) {
		if s.es == nil {
			http.Error(w, "Elasticsearch integration disabled", http.StatusServiceUnavailable)
			return
		}
		s.es.history(w, r, true)
	})
	// Reports studio (R2): the single surface that designs, schedules, and
	// produces PDFs. The legacy /export/report.pdf endpoint and the per-page
	// PDF buttons were removed; dashboard pages link here instead.
	mux.HandleFunc("GET /api/reports/templates", s.serveReportTemplates)
	mux.HandleFunc("GET /api/reports/payload-options", s.serveReportPayloadOptions)
	mux.HandleFunc("GET /api/reports/definitions", s.serveReportDefinitions)
	mux.HandleFunc("POST /api/reports/definitions", s.serveReportDefinitions)
	mux.HandleFunc("GET /api/reports/definitions/{id}", s.serveReportDefinitionByID)
	mux.HandleFunc("PATCH /api/reports/definitions/{id}", s.serveReportDefinitionByID)
	mux.HandleFunc("DELETE /api/reports/definitions/{id}", s.serveReportDefinitionByID)
	mux.HandleFunc("POST /api/reports/definitions/{id}/generate", s.serveReportDefinitionByID)
	mux.HandleFunc("POST /api/reports/payloads/{hash}/generate", s.serveGeneratePayloadReport)
	mux.HandleFunc("GET /api/reports/generated", s.serveReportsGenerated)
	mux.HandleFunc("GET /api/reports/generated/{id}/pdf", s.serveReportGeneratedByID)
	mux.HandleFunc("DELETE /api/reports/generated/{id}", s.serveReportGeneratedByID)
	// Settings modal fragment: the shell fetches this once per session and
	// opens it as a centered overlay; there is no standalone /settings page.
	// Admin panes render only for a live-introspected admin; any identity
	// failure degrades to the personal panes, never to an error page.
	mux.HandleFunc("GET /api/settings/modal", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/settings/modal" {
			http.NotFound(w, r)
			return
		}
		html(w)
		data := settingsPageData{}
		if identity, err := resolveIdentity(r); err == nil && identity.Role == "admin" {
			data.Admin = true
		}
		logTemplateErr("settingsModal", tmpl.ExecuteTemplate(w, "settingsModal", data))
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		data := s.eventsData(r)
		data.Ready = s.ready.Load()
		renderPage(w, tmpl, "events", &data)
	})
	// The investigation command dock submits here. Resolution is server-side so
	// a query that names nothing lands on grouped results instead of a 404.
	mux.HandleFunc("GET /search", func(w http.ResponseWriter, r *http.Request) {
		s.serveSearch(w, r, tmpl)
	})
	mux.HandleFunc("GET /ips", func(w http.ResponseWriter, r *http.Request) {
		data := s.ipsData(r)
		if len(data.Rows) > 25 {
			data.Rows = data.Rows[:25]
		}
		data.Ready = s.ready.Load()
		renderPage(w, tmpl, "ips", &data)
	})
	// #1312: /investigate/ip/{ip}, /investigate/cidr/{cidr...},
	// /investigate/cluster, /sessions/{id}, /ghidra/{sha}, /revdeck/{sha},
	// /cape/{sha}, /github-analysis/{sha}, and /sandbox/{job} are
	// registered together in registerInvestigateRoutes -- see that
	// function's own comment for why (a fixed double-path-decoding bug and
	// the cluster drill-down's own confirmed 404 bug, both only testable
	// through a real ServeMux).
	s.registerInvestigateRoutes(mux, tmpl)
	mux.HandleFunc("GET /clusters", func(w http.ResponseWriter, r *http.Request) {
		data := clustersShell(r)
		data.Ready = s.ready.Load()
		renderPage(w, tmpl, "clusters", &data)
	})
	mux.HandleFunc("GET /clusters/fragment", func(w http.ResponseWriter, r *http.Request) {
		data := s.clustersHTTPData(r)
		data.Ready = s.ready.Load()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "clusters-body", &data)
	})
	mux.HandleFunc("GET /campaigns", func(w http.ResponseWriter, r *http.Request) {
		data := campaignsShell(r)
		data.Ready = s.ready.Load()
		renderPage(w, tmpl, "campaigns", &data)
	})
	mux.HandleFunc("GET /campaigns/fragment", func(w http.ResponseWriter, r *http.Request) {
		data := s.campaignsData(r)
		data.Ready = s.ready.Load()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "campaigns-body", &data)
	})
	// #1327 shell+hydrate: this used to call s.attackersData(r), an
	// unbounded readAttackers() Elasticsearch fetch of every attackers-v1
	// doc, before writing any response bytes. attackersShell needs
	// nothing but the request's own optional "id" query parameter -- the
	// real content is fetched client-side from the fragment route just
	// below (see attackersShell's own comment in attackers.go).
	mux.HandleFunc("GET /attackers", func(w http.ResponseWriter, r *http.Request) {
		data := attackersShell(r)
		renderPage(w, tmpl, "attackers", &data)
	})
	mux.HandleFunc("GET /attackers/fragment", func(w http.ResponseWriter, r *http.Request) {
		data := s.attackersData(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		tmpl.ExecuteTemplate(w, "attackers-body", &data)
	})
	mux.HandleFunc("GET /kill-chain", func(w http.ResponseWriter, r *http.Request) {
		data := s.killChainData()
		renderPage(w, tmpl, "kill-chain", &data)
	})
	mux.HandleFunc("GET /history", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "history", &data)
	})
	mux.HandleFunc("GET /dead-letters", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "dead-letters", &data)
	})
	mux.HandleFunc("GET /source-health", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		data.Ready = s.ready.Load()
		renderPage(w, tmpl, "source-health", &data)
	})
	mux.HandleFunc("GET /alerts", func(w http.ResponseWriter, r *http.Request) {
		// #1535: state (open/acknowledged) is no longer a filter-bar field --
		// the New/Acknowledged tabs in alerts.html own that axis now. Only
		// the free-text key-or-message search stays a query-string filter.
		data := alertsPageData{
			snapshot:  s.get(),
			filterBar: buildFilterBar(r, "/alerts", [2]string{"q", "Key or message contains"}),
		}
		renderPage(w, tmpl, "alerts", &data)
	})
	mux.HandleFunc("GET /ml-anomalies", func(w http.ResponseWriter, r *http.Request) {
		if !s.mlPanelsEnabled() {
			http.NotFound(w, r)
			return
		}
		data := s.mlAnomaliesData(r)
		renderPage(w, tmpl, "ml-anomalies", &data)
	})
	mux.HandleFunc("GET /auth-events", func(w http.ResponseWriter, r *http.Request) {
		data := s.authEventsData(r)
		renderPage(w, tmpl, "auth-events", &data)
	})
	// #1538: per-sensor detail view -- mailoney/http-honeypot's own
	// structured fields, queried live from Elasticsearch on each load (same
	// posture as auth-events above). See sensor_detail.go's package comment.
	mux.HandleFunc("GET /sensors", func(w http.ResponseWriter, r *http.Request) {
		data := s.sensorDetailData(r)
		renderPage(w, tmpl, "sensors", &data)
	})
	mux.HandleFunc("GET /llm-analysis", func(w http.ResponseWriter, r *http.Request) {
		data := s.llmAnalysisData(r)
		renderPage(w, tmpl, "llm-analysis", &data)
	})
	mux.HandleFunc("GET /agent-campaigns", func(w http.ResponseWriter, r *http.Request) {
		if !s.mlPanelsEnabled() {
			http.NotFound(w, r)
			return
		}
		data := s.agentCampaignsData(r)
		renderPage(w, tmpl, "agent-campaigns", &data)
	})
	mux.HandleFunc("GET /reports", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "reports", &data)
	})
	// #1487: instant shell, no query on page load -- Tokens/Create bait/
	// Reports all hydrate client-side (static/hp-canarytokens.js) against
	// the existing /api/settings/canarytokens* endpoints (#1508) and
	// /api/events?sensor=canarytokens, same posture as attackersShell above.
	mux.HandleFunc("GET /canarytokens", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		renderPage(w, tmpl, "canarytokens", &data)
	})
	// Design refresh (pick 13B): the settings surface as a full page. Same
	// server-side admin resolution as /api/settings/modal -- the fragment
	// itself is fetched by hp-settings.js and carries the admin panes only
	// when the live identity check passes.
	mux.HandleFunc("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		var data settingsPageView
		if identity, err := resolveIdentity(r); err == nil && identity.Role == "admin" {
			data.Admin = true
		}
		renderPage(w, tmpl, "settingsPage", &data)
	})
	mux.HandleFunc("GET /payloads", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("GET /api/payload-rows", func(w http.ResponseWriter, r *http.Request) {
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
		logTemplateErr("payloadrows", tmpl.ExecuteTemplate(w, "payloadrows", data))
	})
	// #1312: explicit methods for the same reason as /investigate/ip/block
	// above -- each of these three otherwise conflicts with
	// registerInvestigateRoutes' GET-only wildcard sibling
	// (/sandbox/submit vs "GET /sandbox/{job}", /ghidra/submit vs "GET
	// /ghidra/{sha}", /github-analysis/submit vs "GET
	// /github-analysis/{sha}") the same way /investigate/ip/block did.
	// serveSandboxSubmit/serveGhidraSubmit/serveGitHubAnalysisSubmit all
	// already reject a non-POST request themselves; this doesn't change
	// that, just lets ServeMux enforce it too (and register successfully).
	mux.HandleFunc("POST /sandbox/submit", s.serveSandboxSubmit)
	mux.HandleFunc("POST /ghidra/submit", s.serveGhidraSubmit)
	mux.HandleFunc("POST /gpu-queue/abort", serveGPUQueueAbort)
	mux.HandleFunc("POST /github-analysis/submit", s.serveGitHubAnalysisSubmit)
	mux.HandleFunc("POST /ml-anomalies/ack", s.serveMLAnomalyAck)
	// #1139: the standalone artifact-selection index merged into /payloads'
	// second tab -- old bookmarks/links redirect rather than 404.
	mux.HandleFunc("GET /payload-workbench", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/payloads#start-analysis", http.StatusFound)
	})
	mux.HandleFunc("GET /payload-workbench/results", func(w http.ResponseWriter, r *http.Request) {
		s.serveWorkbenchResults(w, r, tmpl)
	})
	mux.HandleFunc("GET /payload-workbench/", func(w http.ResponseWriter, r *http.Request) {
		s.serveWorkbenchPage(w, r, tmpl)
	})
	// #1180-adjacent: the standalone Ghidra list view merged into
	// /payload-workbench/results' fourth tab -- old bookmarks/links
	// redirect rather than 404, same convention as #1139's sandbox/
	// GitHub-analysis redirects just below. /ghidra/{sha} detail pages are
	// unaffected. The list view's own ?analysis= re-analyze flash message
	// only ever fires on the detail page (ghidra.html's own re-analyze
	// form always returns there), so there's nothing to carry across here.
	mux.HandleFunc("GET /ghidra", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/payload-workbench/results#ghidra", http.StatusFound)
	})
	// #1312: /ghidra/{sha} itself is registered by registerInvestigateRoutes
	// (called near the top of route setup, alongside /investigate/ip/{ip}
	// and friends) -- only this redirect stays here.
	// #1239: unlike /ghidra and /github-analysis just above, revdeck/cape
	// have no merged listing view to redirect a bare visit into -- both are
	// detail-only (capeData/revdeckData both error immediately on an empty
	// hash, #1156's own comment). Without this, a bare "/revdeck" request
	// fell through to net/http.ServeMux's own implicit redirect-to-
	// trailing-slash behavior, landing on "/revdeck/" with an empty sha --
	// which the handler below correctly treats as an invalid hash and
	// answers with a bare, chrome-less http.NotFound, indistinguishable
	// from a broken route. Redirecting to /payloads (the natural place to
	// find a real hash to visit either page with) fixes the reported
	// symptom regardless of which layer the ServeMux redirect itself
	// behaves correctly at.
	mux.HandleFunc("GET /revdeck", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/payloads", http.StatusFound)
	})
	mux.HandleFunc("GET /cape", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/payloads", http.StatusFound)
	})
	// #1312: /revdeck/{sha} and /cape/{sha} are registered by
	// registerInvestigateRoutes -- only the two redirects above stay here.
	// #1139: the standalone GitHub-analysis list view merged into
	// /payload-workbench/results' third tab -- old bookmarks/links redirect
	// rather than 404. /github-analysis/{sha} detail pages are unaffected.
	mux.HandleFunc("GET /github-analysis", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/payload-workbench/results#github", http.StatusFound)
	})
	// #1312: /github-analysis/{sha} is registered by
	// registerInvestigateRoutes -- only the redirect above stays here.
	// #1139: the standalone sandbox list view merged into
	// /payload-workbench/results' second tab -- old bookmarks/links redirect
	// rather than 404. /sandbox/{job} detail pages and /sandbox/vnc are
	// unaffected (registered separately below).
	mux.HandleFunc("GET /sandbox", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/payload-workbench/results#sandbox", http.StatusFound)
	})
	// #805: an exact match still wins over registerInvestigateRoutes' "GET
	// /sandbox/{job}" wildcard for exactly this path, matching this
	// comment's original claim -- but #1312 found that guarantee only
	// holds when the exact match's own method set is a subset of the
	// wildcard's. A bare "/sandbox/vnc" (matching every method) is NOT a
	// subset of "GET /sandbox/{job}" (GET only) -- it additionally
	// matches every other method for this one path, which the wildcard
	// doesn't cover -- so net/http.ServeMux (Go 1.22+) treated the two as
	// a genuine conflict and panicked at startup rather than picking a
	// winner (confirmed live). serveSandboxVNC is only ever a page
	// navigation (GET), so restricting this registration to GET restores
	// the strict-subset relationship the original comment assumed.
	mux.HandleFunc("GET /sandbox/vnc", func(w http.ResponseWriter, r *http.Request) {
		s.serveSandboxVNC(w, r, tmpl)
	})
	// #1312: /sandbox/{job} itself is registered by registerInvestigateRoutes.
	mux.HandleFunc("GET /commands", func(w http.ResponseWriter, r *http.Request) {
		data := s.commandsData(r)
		renderPage(w, tmpl, "commands", &data)
	})
	// #1268: TTY session replays previously had no dedicated, browsable
	// entry point -- only surfaced inline on the one event row that carries
	// TTYReplay (/events, /sessions/<id>). Same in-memory-cache shape as
	// /commands just above.
	mux.HandleFunc("GET /recordings", func(w http.ResponseWriter, r *http.Request) {
		data := s.recordingsData(r)
		renderPage(w, tmpl, "recordings", &data)
	})
	mux.HandleFunc("GET /payload-analysis/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/payload-analysis/")
		// #1157: payloadAnalysisShell, not analyzePayloadFast -- even
		// analyzePayloadFast's "fast half" (#1142) turned out not to be fast
		// enough for a multi-megabyte payload (567ms measured against a real
		// 5.26MB capture, all of it before html/template writes a single
		// byte, since Go's renderer buffers the whole document first). The
		// shell resolves and validates the hash only; the Identity/Findings/
		// Content tabs hydrate in via /api/payload-analysis/<hash>/static,
		// the same pattern SandboxRuns/GitHubAnalysis/Correlation already
		// use via /api/payload-analysis/<hash>/aggregation. See
		// payloadAnalysisShell's own comment.
		shell, err := s.payloadAnalysisShell(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		renderPage(w, tmpl, "payload-analysis", &shell)
	})
	mux.HandleFunc("GET /api/payload-analysis/", func(w http.ResponseWriter, r *http.Request) {
		// #1157: one prefix, two hydration endpoints -- static (this
		// route's addition) and aggregation (#1142, unchanged). Dispatched
		// on the action segment of the path; servePayloadAggregation keeps
		// owning its own "aggregation" validation/404, so the default case
		// here just falls through to it unchanged.
		rest := strings.TrimPrefix(r.URL.Path, "/api/payload-analysis/")
		if _, action, ok := strings.Cut(rest, "/"); ok && action == "static" {
			s.servePayloadStaticAnalysis(w, r)
			return
		}
		s.servePayloadAggregation(w, r)
	})
	mux.HandleFunc("GET /export/events.csv", s.exportEventsCSV)
	mux.HandleFunc("GET /export/commands.csv", s.exportCommandsCSV)
	mux.HandleFunc("GET /export/ips.csv", s.exportIPsCSV)
	mux.HandleFunc("GET /export/campaigns.csv", s.exportCampaignsCSV)
	mux.HandleFunc("GET /export/clusters.csv", s.exportClustersCSV)
	mux.HandleFunc("GET /payload/", s.servePayload)
	mux.HandleFunc("GET /tty/", func(w http.ResponseWriter, r *http.Request) { s.serveTTYReplay(w, r, tmpl) })
	mux.Handle("GET /static/", staticAssetHandler())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data := s.get()
		data.Ready = s.ready.Load()
		renderPage(w, tmpl, "page", &data)
	})

	return mux
}
