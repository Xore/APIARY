// dashboard — a tiny live view over the honeypot log volume.
//
// It walks /logs recursively every 15 seconds, parses every JSON-lines log the
// sensors export (cowrie, multipot, http-honeypot, dionaea, conpot, tanner —
// including rotated files like cowrie.json.2026-07-18), aggregates them into a
// snapshot and serves an auto-refreshing HTML page plus /api/stats.
//
// It exposes attacker data, so every application route is protected by the
// native Keycloak OIDC middleware below. Traefik remains the TLS boundary but
// is not trusted to assert dashboard identity.
package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
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

// trackedHandler (#1312) wraps mux with #486's idle-activity tracking and
// the OIDC auth gate, in that order relative to each other -- touchActivity
// now only runs for a request that actually reaches mux, i.e. one the OIDC
// gate already let through. Previously touchActivity ran BEFORE the OIDC
// gate (an inline closure built directly in main()), so any unauthenticated
// probe against a normal route -- redirected to login or 401'd inside
// middleware() before next.ServeHTTP was ever reached -- still kept the
// idle-rebuild loop alive indefinitely, the exact failure mode #486 itself
// was meant to prevent. /healthz stays excluded for the same reason as
// before: Docker's own healthcheck (and any external uptime monitor) hits
// it on a fixed interval regardless of whether an operator is looking,
// which would defeat idle detection entirely on an unattended host.
//
// A named function (not an inline closure), matching healthzHandler's own
// convention just above, so it's unit-testable -- and, #1312's other
// finding, built exactly once here rather than reconstructing the OIDC
// wrapper on every single request the way the old inline closure did.
func trackedHandler(s *store, oidc *oidcAuth, mux http.Handler) http.Handler {
	tracked := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			s.touchActivity()
		}
		mux.ServeHTTP(w, r)
	})
	return oidc.middleware(tracked)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		addr := getenv("LISTEN_ADDR", ":8080")
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		c := http.Client{Timeout: 3 * time.Second}
		r, err := c.Get("http://" + addr + "/healthz")
		if err != nil {
			os.Exit(1)
		}
		// #1312: close the response body even on the success path -- Go's
		// http.Client docs require this for the underlying connection to
		// be returned to the pool. Harmless in practice (this process
		// exits immediately after either branch below, which reclaims
		// everything anyway), but there is no reason to leave it unclosed.
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}
	var err error
	dashboardOIDC, err = newOIDCAuth(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "dashboard: OIDC initialization failed: %v\n", err)
		os.Exit(1)
	}

	authAccountURL := validatedAuthAccountURL()
	setVNCBridgeOrigin(getenv("SANDBOX_VNC_BRIDGE_WS", ""))
	s := &store{
		dir:                   getenv("LOG_DIR", "/logs"),
		logStreamMaxBytes:     configuredLogStreamMaxBytes(os.Getenv("LOG_STREAM_MAX_BYTES")),
		logStreamAlertPercent: configuredLogStreamAlertPercent(os.Getenv("LOG_STREAM_ALERT_PERCENT")),
		authAccountURL:        authAccountURL,
		authAdminURL:          validatedExternalURL("AUTH_ADMIN_URL"),
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
		s.authEvents = &authEventStore{}
		s.es.refresh()
		s.refreshMLAnomalies()
		s.refreshLLMAnalysis()
		s.refreshAgentCampaigns()
		s.refreshAuthEvents()
		go func() {
			for range time.Tick(time.Minute) {
				s.es.refresh()
				s.refreshMLAnomalies()
				s.refreshLLMAnalysis()
				s.refreshAgentCampaigns()
				s.refreshAuthEvents()
				// #913-follow-up: s.mlAnomalyAcks isn't constructed until
				// after this block (below, once s.es itself is set) -- by
				// the time this first fires (a minute after startup) it's
				// long since non-nil, and refreshMLAnomalyAcks is a no-op
				// on nil anyway, same guard every other refresh* here has.
				s.refreshMLAnomalyAcks()
			}
		}()
	}
	// #1579: started here, after s.es is assigned above, not immediately
	// after s.payloadDirs is populated further up -- payloadInventoryLoop's
	// very first call reads s.es with no synchronization against this
	// function's own write to it, and a `go` statement only guarantees the
	// new goroutine sees everything the launching goroutine did BEFORE that
	// statement, not after. Starting it earlier let that first call lose
	// the race on a freshly (re)started process and silently no-op on a nil
	// s.es, leaving the overview KPI's payload count at 0 -- distinct from
	// the ES-unconfigured case (a real, permanent no-op both here and in
	// refreshPayloadCacheAsync's own guard) because it self-healed within
	// about a minute, once rebuild()'s own independent 15s-interval calls
	// to refreshPayloadCacheAsync eventually ran with s.es already set and
	// warmed the cache -- exactly the kind of gap a post-deploy audit
	// (freshly restarted process, checked within that window) would catch
	// and a later recheck would no longer reproduce. /payloads itself never
	// showed this: payloadsData() calls refreshPayloadCacheAsync()
	// synchronously per-request, and by the time an operator's browser
	// issues that request s.es has always long since been assigned.
	go s.payloadInventoryLoop()
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
	// #914: same nil-when-unconfigured posture as s.alerts above -- every
	// call site (serveIPBlockAction, serveManualBlackholeExport) already
	// treats a nil ipBlocks as "manual blocking disabled".
	s.ipBlocks = newIPBlockManager(s.es)
	// #1487: same local-only-endpoint posture as OLLAMA_URL above --
	// CANARYTOKENS_API_URL must point at the self-hosted Canarytokens
	// frontend's WireGuard-tunnel address (docker-compose.canarytokens.yml,
	// e.g. http://10.8.0.2:19426), never a public endpoint. Unset or
	// rejected leaves s.canarytokens nil, and every call site treats that
	// as "canarytoken creation disabled" (settings_modal.html's Canarytokens
	// pane reports itself unavailable rather than erroring).
	if canarytokensAPIURL := os.Getenv("CANARYTOKENS_API_URL"); canarytokensAPIURL != "" {
		if canarytokensAPIURLIsLocal(canarytokensAPIURL) {
			s.canarytokens = newCanarytokensClient(canarytokensAPIURL, os.Getenv("CANARYTOKENS_API_ROOT"))
		} else {
			fmt.Fprintf(os.Stderr, "dashboard: CANARYTOKENS_API_URL %s rejected (must be a local/internal endpoint), canarytoken creation disabled\n", canarytokensAPIURL)
		}
	}
	s.canarytokensHistory = newCanarytokensManager(s.es)
	// #1487 items 3/5: honeyfs-implant (#1553) plants a credential live
	// into a honeypot's filesystem. Same local-only-endpoint posture as
	// CANARYTOKENS_API_URL above -- HONEYFS_IMPLANT_URL must point at the
	// service's own WireGuard-tunnel address (compose.yml, e.g.
	// http://10.8.0.2:19428), never a public endpoint. Unset or rejected
	// leaves s.honeyfsImplant nil, and every call site treats that as
	// "credential provisioning/rotation disabled". HONEYFS_IMPLANT_TOKEN is
	// the optional defense-in-depth bearer token honeyfs-implant's own
	// requireToken supports (main.go, #1553) -- empty by default, matching
	// that service's own "network reachability is the trust boundary"
	// posture.
	if honeyfsImplantURL := os.Getenv("HONEYFS_IMPLANT_URL"); honeyfsImplantURL != "" {
		if honeyfsImplantURLIsLocal(honeyfsImplantURL) {
			s.honeyfsImplant = newHoneyfsImplantClient(honeyfsImplantURL, os.Getenv("HONEYFS_IMPLANT_TOKEN"))
		} else {
			fmt.Fprintf(os.Stderr, "dashboard: HONEYFS_IMPLANT_URL %s rejected (must be a local/internal endpoint), credential provisioning disabled\n", honeyfsImplantURL)
		}
	}
	s.credentials = newCredentialsManager(s.es)
	// #913: same nil-when-unconfigured posture as s.alerts above -- every
	// call site (applyMLAnomalyAcks, serveMLAnomalyAck) already treats a nil
	// mlAnomalyAcks as "acknowledgment disabled".
	s.mlAnomalyAcks = newMLAnomalyAckManager(s.es)
	// Populate the ack cache before the first request can reach
	// /ml-anomalies or /api/ml/anomalies (applyMLAnomalyAcks reads only the
	// cache now, never Elasticsearch directly -- see ml_anomaly_ack.go);
	// thereafter kept warm by the 1-minute ticker above, same as
	// refreshMLAnomalies/refreshLLMAnalysis/refreshAgentCampaigns.
	s.refreshMLAnomalyAcks()
	s.intelligence = &intelligenceStore{path: getenv("INTELLIGENCE_STATE_FILE", "/state/intelligence.json"), es: s.es}
	// #787: config/users are Elasticsearch-backed singleton documents (see
	// settings_store_es.go) -- s.es nil (Elasticsearch not configured)
	// leaves both permanently degraded/read-only, serving compiled
	// defaults, the same "always usable" posture the old file-backed store
	// had for a missing/corrupt file.
	s.settings = newSettingsService(
		s.es,
		getenv("DASHBOARD_AUDIT_FILE", "/state/dashboard-audit.jsonl"),
		getenv("DASHBOARD_CONFIG_HISTORY_FILE", "/state/dashboard-config-history.jsonl"),
	)
	// #475/#787: report definitions and generated PDF reports are both
	// Elasticsearch-only now, no local fallback -- s.es nil leaves
	// definitions CRUD degraded/read-only (serving compiled defaults) and
	// generated-report methods return errReportsStorageUnavailable.
	s.reports = newReportStore(s.es)
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
		// DASHBOARD_BACKGROUND_LOOPS gates the two loops with outbound side
		// effects -- notifyLoop (webhook alerts) and reportScheduleLoop
		// (scheduled PDFs) -- which must run on exactly one replica or every
		// alert/PDF duplicates. The #266 rolling pair that needed this is
		// retired (single replica per Xore; unset means enabled, so the one
		// dashboard runs both), but the flag stays for any future return to
		// replicas. Serving HTTP and rebuild() are never gated by it.
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
	// in Keycloak stop producing activity immediately — token introspection
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
	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))

	handler := trackedHandler(s, dashboardOIDC, s.routes(tmpl))

	srv := &http.Server{
		Addr:              getenv("LISTEN_ADDR", ":8080"),
		ReadHeaderTimeout: 5 * time.Second,
		// #1312: bounds how long reading the rest of a request (past the
		// headers ReadHeaderTimeout already covers) or an idle keep-alive
		// connection may sit open, closing the gap #1312 found -- neither
		// had any deadline before. Deliberately no WriteTimeout: it applies
		// per-connection for the whole response, which would kill
		// /api/stream's long-lived SSE connections at a fixed wall-clock
		// age regardless of whether the client is still actively
		// consuming events -- the issue's own text flags this as needing
		// special handling, not a blanket value, and the acceptance
		// criteria only asks for read/idle deadlines here.
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
		Handler:     handler,
	}

	// #1312: graceful shutdown -- SIGTERM is what `docker stop`/Compose
	// send before escalating to SIGKILL after its own stop_grace_period.
	// Without this, the process previously only reacted to a hard kill,
	// dropping in-flight requests (including a live /api/stream SSE
	// connection) mid-response instead of letting Shutdown drain them.
	// docker-compose.dashboard.yml sets no stop_grace_period for either
	// dashboard service, so Docker's own default (10s) applies -- the
	// shutdown timeout below stays comfortably under that so this code's
	// own drain-and-exit has a real chance to finish (and exit 0 cleanly)
	// before Docker's SIGKILL would otherwise fire regardless.
	//
	// srv.Shutdown()'s own docs are explicit that ListenAndServe() below
	// returns (with ErrServerClosed) the moment Shutdown is CALLED, not
	// once it completes -- "make sure the program doesn't exit and waits
	// instead for Shutdown to return". Without idleConnsClosed, main()
	// would reach its end and the whole process would exit the instant
	// Shutdown started, making the shutdownCtx timeout below meaningless
	// and defeating graceful shutdown entirely (exactly as abrupt as no
	// signal handling at all).
	idleConnsClosed := make(chan struct{})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "dashboard: graceful shutdown: %v\n", err)
		}
		close(idleConnsClosed)
	}()

	// #1312: ListenAndServe always returns a non-nil error -- exactly
	// http.ErrServerClosed on the graceful path above, anything else (most
	// commonly the configured port already being in use) is a real startup
	// or runtime failure. Previously this was discarded entirely, letting
	// main() return and the process exit 0 with no logged cause even when
	// the dashboard never actually started serving traffic.
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "dashboard: HTTP server: %v\n", err)
		os.Exit(1)
	}
	<-idleConnsClosed
}
