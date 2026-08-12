package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	recentCap          = 18
	recentPerSensorCap = 4
)

type snapshot struct {
	pageMeta
	// Ready mirrors s.ready.Load() at request time (#1142) -- NOT stored in
	// rebuild()'s own snap, since by the time s.ready ever reads true the
	// first rebuild() that flips it (main.go) has already populated s.snap
	// with real data, so a fresh read here is always consistent with the
	// rest of this same snapshot value. Lets overview.html tell "no data
	// yet because the first rebuild() cycle hasn't finished" apart from "no
	// data because this honeypot is genuinely quiet" -- the same all-zero
	// snapshot otherwise looks identical for both (see main.go's own
	// #828 comment on s.ready.Store(true) for the exact confusion this
	// caused before /healthz got a way to tell them apart).
	Ready     bool
	Generated time.Time
	Total     int
	UniqueIPs int
	// Unattributed counts events that reached a sensor over the WireGuard
	// tunnel and could not be joined back to a real client IP. They are real
	// attacks with an unknown source, deliberately not attributed to the tunnel
	// peer; see aggregate.go and issue #54.
	Unattributed  int
	Logins        int
	Last24h       int
	Previous24h   int
	Change24h     string
	ActivityState string
	Downloads     int // payload-observation events (file_download etc.) -- not deduplicated, feeds honeypot_payload_observations
	// UniquePayloads is the same distinct-binary count /payloads shows
	// (s.payloadCache.UniqueTotal, a disk scan across s.payloadDirs) --
	// #470: Downloads counts per-event observations from the log tail
	// window and is a wildly different, much smaller number, so the
	// overview's "Captured payloads" card must not use it.
	UniquePayloads int
	GeoOn          bool
	MapTileURL     string
	MapAttribution string
	Sensors        []sensorRow
	Protocols      []kv
	TopIPs         []kv
	TopPorts       []kv
	TopCreds       []kv
	TopCommands    []kv
	TopPaths       []kv
	Alerts         []kv
	AlertCats      []kv
	Countries      []kv
	ASNs           []kv
	Providers      []kv
	Clients        []kv // ssh/telnet client banners
	Fingerprints   []kv // HASSH / JA3 / JA4 / User-Agent / client identities
	OSDistribution []kv // p0f OS guess only (#1277) -- split out of Fingerprints above
	// EndlesshTotalHeldMs/EndlesshHeldBuckets (#1294): summed and bucketed
	// in aggregate.go's rebuild() in-memory pass, not a live ES aggregation
	// -- see endlessh_stats.go's own header comment for why.
	EndlesshTotalHeldMs int64
	// EndlesshTotalHeldHuman is EndlesshTotalHeldMs pre-formatted ("3h 24m")
	// -- computed server-side (rebuild(), via endlesshHeldHumanDuration)
	// rather than a template helper, matching this struct's existing
	// Time/TimeUTC-style convention of shipping display-ready strings.
	EndlesshTotalHeldHuman string
	EndlesshHeldBuckets    map[string]int
	MapPoints              []mapPoint
	Payloads               []payloadRow
	Campaigns              []campaignRow
	SensorHeatmap          []heatmapRow
	Recent                 []storedEvent
	ES                     esStatus
	Runtime                runtimeStatus
	YARA                   yaraStatus
}

type runtimeStatus struct {
	Uptime, Heap, Reserved, ContainerUsage, ContainerLimit string
	Goroutines                                             int
}

func currentRuntime() runtimeStatus {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	formatCgroup := func(value string) string {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return firstNonEmpty(value, "unavailable")
		}
		return humanBytes(n)
	}
	return runtimeStatus{Uptime: time.Since(processStarted).Round(time.Second).String(), Heap: humanBytes(int64(m.HeapAlloc)), Reserved: humanBytes(int64(m.Sys)), ContainerUsage: formatCgroup(read("/sys/fs/cgroup/memory.current")), ContainerLimit: formatCgroup(read("/sys/fs/cgroup/memory.max")), Goroutines: runtime.NumGoroutine()}
}

// sensorRow is one line of the sensor health card: hit count plus how long
// ago the sensor last logged anything — a silent sensor is the first hint
// that a forward/mount broke.
type sensorRow struct {
	Name  string
	Count int
	Ago   string
	State string
	Link  string `json:",omitempty"`
}

// heatmapRow is one sensor's row in the "Activity by sensor" heatmap
// (#191/#193, replacing the single 24h bar chart): one cell per hour of a
// 24h window. Pct is quantized into five steps (0/25/50/75/100) against the
// busiest single cell across every row, not per-row -- a quiet sensor's own
// busiest hour should not read as visually "hot" as the noisiest sensor's
// peak. See Xore/theme's docs/CSP.md for why Pct feeds a nonced <style>
// element instead of an inline style attribute.
type heatmapRow struct {
	Sensor string
	Cells  []heatmapCell
}

type heatmapCell struct {
	Label string
	Count int
	Pct   int
}

// storedEvent is one fully-normalised event kept in memory so the /events
// and /ips drill-down pages can filter without re-reading the logs.
type storedEvent struct {
	when time.Time
	Time string
	// UTC is the same instant as Time, machine-readable (RFC3339), for
	// client-side timezone conversion (#282) -- Time itself stays a fixed
	// UTC display string since it's computed once in rebuild()'s shared,
	// cross-viewer cache, long before any per-viewer preference is known.
	UTC           string
	Sensor        string
	Persona       string `json:",omitempty"`
	Site          string `json:",omitempty"`
	Asset         string `json:",omitempty"`
	PersonaOrg    string `json:",omitempty"`
	SrcIP         string
	Country       string  `json:",omitempty"`
	City          string  `json:",omitempty"`
	Lat           float64 `json:",omitempty"`
	Lon           float64 `json:",omitempty"`
	ASN           uint    `json:",omitempty"`
	Org           string  `json:",omitempty"`
	Provider      string  `json:",omitempty"`
	Intel         string  `json:",omitempty"`
	Proto         string  `json:",omitempty"`
	Port          string  `json:",omitempty"`
	User          string  `json:",omitempty"`
	Pass          string  `json:",omitempty"`
	Command       string  `json:",omitempty"`
	Path          string  `json:",omitempty"`
	Alert         string  `json:",omitempty"`
	Session       string  `json:",omitempty"`
	Shasum        string  `json:",omitempty"`
	Download      string  `json:",omitempty"`
	TTYReplay     string  `json:",omitempty"`
	ClientVer     string  `json:",omitempty"`
	Fingerprint   string  `json:",omitempty"`
	FingerKind    string  `json:",omitempty"`
	Category      string  `json:",omitempty"`
	Severity      int     `json:",omitempty"`
	HeldMs        int     `json:",omitempty"` // endlessh (#1294): tarpit hold duration, disconnect events only
	ICSSeverity   string  `json:",omitempty"` // dnp3 (#1290): "critical"/"high" for control-function app_function codes
	Detail        string
	IsLogin       bool   `json:",omitempty"`
	HasCredential bool   `json:",omitempty"`
	Kibana        string `json:",omitempty"`
	EveBox        string `json:",omitempty"`
	Arkime        string `json:",omitempty"`
}

type store struct {
	mu                sync.RWMutex
	subsMu            sync.Mutex
	payloadMu         sync.Mutex
	ipsMu             sync.Mutex
	hashPathMu        sync.Mutex
	hashPathCache     map[string]string    // sha256 -> resolved payload path (#364)
	hashPathMiss      map[string]time.Time // sha256 -> when the full content-hash scan last found nothing (#516)
	snap              snapshot
	events            []storedEvent // newest first; replaced wholesale each rebuild
	payloadCache      payloadsPage
	payloadCacheAt    time.Time
	payloadRefreshing bool
	ipsCache          ipsPage
	ipsCacheAt        time.Time
	// githubAnalysisMu/githubAnalysisCache/githubAnalysisCacheAt/
	// githubAnalysisRefreshing back refreshGithubAnalysisCacheAsync
	// (github_analysis.go, #1156-follow-up) -- same background-refreshed-
	// cache shape as payloadMu/payloadCache/payloadCacheAt/payloadRefreshing
	// above, scoped to the GitHub-analysis listing view only.
	githubAnalysisMu         sync.Mutex
	githubAnalysisCache      []githubAnalysisResult
	githubAnalysisCacheAt    time.Time
	githubAnalysisRefreshing bool
	// ghidraMu/ghidraCache/ghidraCacheAt/ghidraRefreshing back
	// refreshGhidraCacheAsync (ghidra.go, #1156-follow-up) -- same
	// background-refreshed-cache shape as githubAnalysisMu/... above, scoped
	// to the Ghidra listing view only.
	ghidraMu         sync.Mutex
	ghidraCache      []ghidraResult
	ghidraCacheAt    time.Time
	ghidraRefreshing bool
	// sandboxMu/sandboxCache/sandboxCacheAt/sandboxRefreshing back
	// refreshSandboxCacheAsync (sandbox.go, #1156-follow-up) -- same
	// background-refreshed-cache shape as githubAnalysisMu/... and
	// ghidraMu/... above, scoped to the sandbox listing view only. Job-scoped
	// detail lookups (/sandbox/{job}) do not read this cache.
	sandboxMu         sync.Mutex
	sandboxCache      []sandboxResult
	sandboxCacheAt    time.Time
	sandboxRefreshing bool
	// problemReportsMu/problemReportsCache/problemReportsCacheAt/
	// problemReportsRefreshing back refreshProblemReportsCacheAsync
	// (problem_reports.go, #1157 follow-up) -- same background-refreshed-
	// cache shape as githubAnalysisMu/... above, scoped to the
	// /admin/problem-reports listing view only.
	problemReportsMu         sync.Mutex
	problemReportsCache      []problemReport
	problemReportsCacheAt    time.Time
	problemReportsRefreshing bool
	dir                      string
	payloadDirs              []string // dionaea, cowrie and generated script artifact directories
	scriptDir                string   // writable directory for safely retained inline scripts
	geo                      *geoDB   // nil if no GeoIP database configured
	es                       *esClient
	mlAnomalies              *mlAnomalyStore     // ml-worker's scored anomalies, polled via es (#64); nil until initialised in main()
	llmAnalysis              *llmAnalysisStore   // llm-worker's guarded model output, polled via es (#150); nil until initialised in main()
	agentCampaigns           *agentCampaignStore // agent-intrusion-worker's correlated campaign verdicts, polled via es (#154 phase 5); nil until initialised in main()
	authEvents               *authEventStore     // auth-events-worker's redacted Keycloak/gateway auth-failure events, polled via es (#1066); nil until initialised in main()
	// ollamaURL/embeddingModel (#151) back serveLLMAnalysisSearch's
	// query-time embedding call. ollamaURL empty means semantic search is
	// unconfigured/rejected -- the same "feature quietly off" posture geo
	// and es above take, not a startup failure.
	ollamaURL      string
	embeddingModel string
	alerts         *alertManager
	ipBlocks       *ipBlockManager      // #914: manual IP block state; nil until initialised in main()
	mlAnomalyAcks  *mlAnomalyAckManager // #913: ack/dismiss state for ml-anomalies, mirrors alerts' own shape; nil until initialised in main()
	intelligence   *intelligenceStore
	settings       *settingsService  // typed settings stores; nil only in partial test fixtures
	reports        *reportStore      // Reports studio definitions + generated PDFs; nil only in test fixtures
	workbench      *workbenchService // immutable recipes + correlated analyzer runs (#155)
	expected       []string          // configured feeds shown even before their first event
	subs           map[chan struct{}]struct{}
	authAccountURL string // validated once at startup; see validatedAuthAccountURL
	authAdminURL   string // validated Keycloak admin-console URL; exposed only to dashboard admins
	// lastActivity (#486) is a unix-second timestamp of the most recent
	// dashboard request, touched by touchActivity (main.go's request
	// middleware) and read by the periodic rebuild loop to skip its ES/log
	// round-trip while no one is looking. atomic, not mu-guarded: it is
	// written on every request, far hotter than rebuild's own 15s tick, and
	// a torn read only ever costs one extra or one skipped rebuild.
	lastActivity atomic.Int64
	// ready (#828) is set true once, after the very first rebuild() call at
	// startup completes -- /healthz reads it so Docker's healthcheck can
	// tell "the HTTP server is listening" (true almost instantly) apart
	// from "there is real ES-derived data to serve" (found live: takes
	// 60-120s against this host's real event volume). Before this, a
	// redeploy's rolling healthcheck passed within seconds of container
	// start, well before the first rebuild finished, so a request landing
	// in that window saw an all-zero, 0001-01-01-timestamped dashboard
	// that looked broken but wasn't -- see docker-compose.dashboard.yml's
	// matching start_period bump.
	ready atomic.Bool
}

// touchActivity records that a real dashboard request just arrived.
func (s *store) touchActivity() { s.lastActivity.Store(time.Now().Unix()) }

// idleSince reports how long it has been since the last recorded request.
// Before the first request (or if touchActivity was never called), it
// reports zero duration -- treated as "not idle" by callers, since a
// freshly booted dashboard should not skip its first ticks.
func (s *store) idleSince() time.Duration {
	last := s.lastActivity.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.Unix(last, 0))
}

// rebuild re-reads every log file and recomputes the snapshot.
func (s *store) get() snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// getEvents returns the current event slice. rebuild replaces the slice
// wholesale (never mutates in place), so it is safe to use after unlock.
func (s *store) getEvents() []storedEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.events
}

// notifyLoop always evaluates and persists operational rules. Webhook delivery
// is optional; the dashboard alert queue remains useful without an endpoint.
func (s *store) notifyLoop(endpoint string) {
	client := &http.Client{Timeout: 8 * time.Second}
	campaignThreshold, _ := strconv.Atoi(getenv("ALERT_CAMPAIGN_SCORE", "80"))
	if campaignThreshold < 1 || campaignThreshold > 100 {
		campaignThreshold = 80
	}
	current := func(markOnly bool) {
		snap := s.get()
		var messages []string
		for _, c := range snap.Campaigns {
			if c.Score < campaignThreshold {
				continue
			}
			key := "campaign:" + c.CIDR
			message := fmt.Sprintf("honeypot campaign %s score=%d events=%d sensors=%s ports=%s", c.CIDR, c.Score, c.Events, c.Sensors, c.Ports)
			link := eventsURL(url.Values{"cidr": {c.CIDR}})
			if s.alerts == nil || s.alerts.observe(key, message, link, markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		for _, feed := range snap.Sensors {
			if feed.State == "stale" {
				message := "honeypot feed stale: " + feed.Name + " (last event " + feed.Ago + ")"
				if s.alerts == nil || s.alerts.observe("stale:"+feed.Name, message, "", markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
		}
		if snap.ActivityState == "spike" {
			message := fmt.Sprintf("honeypot activity spike: %d events in 24h (%s)", snap.Last24h, snap.Change24h)
			if s.alerts == nil || s.alerts.observe("activity:spike", message, "", markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		if snap.ES.Enabled {
			if snap.ES.IngestState == "stale" || snap.ES.FilebeatState != "healthy" {
				message := fmt.Sprintf("honeypot ingestion unhealthy: ingest=%s age=%s filebeat=%s", snap.ES.IngestState, snap.ES.LastIngestAge, snap.ES.FilebeatState)
				if s.alerts == nil || s.alerts.observe("pipeline:ingestion", message, "", markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
			if snap.ES.RecentDeadLetters > 0 {
				message := fmt.Sprintf("honeypot ingest rejected %d documents in the last 24h", snap.ES.RecentDeadLetters)
				if s.alerts == nil || s.alerts.observe("pipeline:dead-letters", message, "", markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
			if snap.ES.FilebeatFailed > 0 || snap.ES.FilebeatDropped > 0 {
				message := fmt.Sprintf("Filebeat reports failed=%d dropped=%d active=%d", snap.ES.FilebeatFailed, snap.ES.FilebeatDropped, snap.ES.FilebeatActive)
				if s.alerts == nil || s.alerts.observe("pipeline:filebeat-loss", message, "", markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
		}
		otSources := map[string]string{}
		for _, event := range s.getEvents() {
			if event.when.IsZero() || time.Since(event.when) > 10*time.Minute {
				continue
			}
			for _, item := range techniquesForEvent(event) {
				if item.ID == "T1692.001" {
					otSources[event.SrcIP+" via "+event.Sensor] = event.SrcIP
				}
			}
		}
		for source, srcIP := range otSources {
			message := "industrial control command/write attempt: " + source
			link := eventsURL(url.Values{"ip": {srcIP}})
			if s.alerts == nil || s.alerts.observe("ot-command:"+source, message, link, markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		if yaraSamples, ok := loadYaraSamplesES(s.es); ok {
			for hash, sample := range yaraSamples {
				if len(sample.Matches) == 0 {
					continue
				}
				message := fmt.Sprintf("YARA payload match: %s rules=%s source=%s", hash, strings.Join(sample.Matches, ","), sample.Source)
				link := "/payload-analysis/" + url.PathEscape(hash)
				if s.alerts == nil || s.alerts.observe("yara:"+hash, message, link, markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
		}
		sandboxStatus := loadSandboxStatus()
		if sandboxStatus.HandoffOld {
			message := fmt.Sprintf("sandbox handoff stalled: %d dashboard request(s) are waiting for the host watcher", sandboxStatus.Handoff)
			if s.alerts == nil || s.alerts.observe("sandbox:handoff", message, "", markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		if sandboxStatus.WorkerState == "stale" || sandboxStatus.WorkerState == "error" {
			message := fmt.Sprintf("sandbox worker unhealthy: state=%s queued=%d running=%d", sandboxStatus.WorkerState, sandboxStatus.Counts.Queued, sandboxStatus.Counts.Running)
			if s.alerts == nil || s.alerts.observe("sandbox:worker", message, "", markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		if sandboxStatus.Counts.Failed > 0 {
			message := fmt.Sprintf("sandbox queue has %d failed job(s)", sandboxStatus.Counts.Failed)
			if s.alerts == nil || s.alerts.observe("sandbox:failed", message, "", markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		ghidraAlerts(s, &messages, markOnly)
		githubAnalysisAlerts(s, &messages, markOnly)
		llmAnalysisAlerts(s, &messages, markOnly)
		capeAlerts(s, &messages, markOnly)
		sandboxRiskThreshold, _ := strconv.Atoi(getenv("SANDBOX_ALERT_RISK_SCORE", "50"))
		if sandboxRiskThreshold < 1 || sandboxRiskThreshold > 100 {
			sandboxRiskThreshold = 50
		}
		for _, result := range loadSandboxResults() {
			if result.RiskScore < sandboxRiskThreshold {
				continue
			}
			message := fmt.Sprintf("sandbox high-risk behavior: sha256=%s score=%d level=%s techniques=%d", result.SHA256, result.RiskScore, result.RiskLevel, len(result.Techniques))
			link := "/sandbox/" + url.PathEscape(result.Job)
			if s.alerts == nil || s.alerts.observe("sandbox:risk:"+result.Job, message, link, markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		for _, message := range messages {
			if endpoint == "" {
				continue
			}
			body, _ := json.Marshal(map[string]string{"content": message, "text": message})
			req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if resp, err := client.Do(req); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}
	current(true) // baseline: do not alert on every historical campaign at boot
	for range time.Tick(5 * time.Minute) {
		current(false)
	}
}
