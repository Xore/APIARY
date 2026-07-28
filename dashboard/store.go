package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tailCap limits how much of a single log file is re-read each cycle so a
// multi-GB log can't stall the refresh loop. 8 MiB of JSON lines is far more
// history than the UI displays.
const (
	tailCap            = 8 << 20
	recentCap          = 18
	recentPerSensorCap = 4
)

type snapshot struct {
	Generated      time.Time
	Total          int
	UniqueIPs      int
	Logins         int
	Last24h        int
	Previous24h    int
	Change24h      string
	ActivityState  string
	Downloads      int // captured malware payloads (cowrie file_download)
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
	MapPoints      []mapPoint
	Payloads       []payloadRow
	Campaigns      []campaignRow
	Timeline       []bucket
	Recent         []storedEvent
	ES             esStatus
	Runtime        runtimeStatus
	YARA           yaraStatus
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

// bucket is one hour of the 24h activity chart. Pct is the bar height
// relative to the busiest hour (0-100).
type bucket struct {
	Label string
	Count int
	Pct   int
}

// storedEvent is one fully-normalised event kept in memory so the /events
// and /ips drill-down pages can filter without re-reading the logs.
type storedEvent struct {
	when          time.Time
	Time          string
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
	ClientVer     string  `json:",omitempty"`
	Fingerprint   string  `json:",omitempty"`
	FingerKind    string  `json:",omitempty"`
	Category      string  `json:",omitempty"`
	Severity      int     `json:",omitempty"`
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
	snap              snapshot
	events            []storedEvent // newest first; replaced wholesale each rebuild
	payloadCache      payloadsPage
	payloadCacheAt    time.Time
	payloadRefreshing bool
	ipsCache          ipsPage
	ipsCacheAt        time.Time
	dir               string
	payloadDirs       []string // dionaea, cowrie and generated script artifact directories
	scriptDir         string   // writable directory for safely retained inline scripts
	geo               *geoDB   // nil if no GeoIP database configured
	es                *esClient
	alerts            *alertManager
	intelligence      *intelligenceStore
	yaraFile          string
	expected          []string // configured feeds shown even before their first event
	subs              map[chan struct{}]struct{}
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
			if s.alerts == nil || s.alerts.observe(key, message, markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		for _, feed := range snap.Sensors {
			if feed.State == "stale" {
				message := "honeypot feed stale: " + feed.Name + " (last event " + feed.Ago + ")"
				if s.alerts == nil || s.alerts.observe("stale:"+feed.Name, message, markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
		}
		if snap.ActivityState == "spike" {
			message := fmt.Sprintf("honeypot activity spike: %d events in 24h (%s)", snap.Last24h, snap.Change24h)
			if s.alerts == nil || s.alerts.observe("activity:spike", message, markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		if snap.ES.Enabled {
			if snap.ES.IngestState == "stale" || snap.ES.FilebeatState != "healthy" {
				message := fmt.Sprintf("honeypot ingestion unhealthy: ingest=%s age=%s filebeat=%s", snap.ES.IngestState, snap.ES.LastIngestAge, snap.ES.FilebeatState)
				if s.alerts == nil || s.alerts.observe("pipeline:ingestion", message, markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
			if snap.ES.RecentDeadLetters > 0 {
				message := fmt.Sprintf("honeypot ingest rejected %d documents in the last 24h", snap.ES.RecentDeadLetters)
				if s.alerts == nil || s.alerts.observe("pipeline:dead-letters", message, markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
			if snap.ES.FilebeatFailed > 0 || snap.ES.FilebeatDropped > 0 {
				message := fmt.Sprintf("Filebeat reports failed=%d dropped=%d active=%d", snap.ES.FilebeatFailed, snap.ES.FilebeatDropped, snap.ES.FilebeatActive)
				if s.alerts == nil || s.alerts.observe("pipeline:filebeat-loss", message, markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
		}
		otSources := map[string]bool{}
		for _, event := range s.getEvents() {
			if event.when.IsZero() || time.Since(event.when) > 10*time.Minute {
				continue
			}
			for _, item := range techniquesForEvent(event) {
				if item.ID == "T1692.001" {
					otSources[event.SrcIP+" via "+event.Sensor] = true
				}
			}
		}
		for source := range otSources {
			message := "industrial control command/write attempt: " + source
			if s.alerts == nil || s.alerts.observe("ot-command:"+source, message, markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		if s.yaraFile != "" {
			for hash, sample := range loadYARA(s.yaraFile).Samples {
				if len(sample.Matches) == 0 {
					continue
				}
				message := fmt.Sprintf("YARA payload match: %s rules=%s source=%s", hash, strings.Join(sample.Matches, ","), sample.Source)
				if s.alerts == nil || s.alerts.observe("yara:"+hash, message, markOnly) {
					if !markOnly {
						messages = append(messages, message)
					}
				}
			}
		}
		sandboxStatus := loadSandboxStatus()
		if sandboxStatus.HandoffOld {
			message := fmt.Sprintf("sandbox handoff stalled: %d dashboard request(s) are waiting for the host watcher", sandboxStatus.Handoff)
			if s.alerts == nil || s.alerts.observe("sandbox:handoff", message, markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		if sandboxStatus.WorkerState == "stale" || sandboxStatus.WorkerState == "error" {
			message := fmt.Sprintf("sandbox worker unhealthy: state=%s queued=%d running=%d", sandboxStatus.WorkerState, sandboxStatus.Counts.Queued, sandboxStatus.Counts.Running)
			if s.alerts == nil || s.alerts.observe("sandbox:worker", message, markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		if sandboxStatus.Counts.Failed > 0 {
			message := fmt.Sprintf("sandbox queue has %d failed job(s)", sandboxStatus.Counts.Failed)
			if s.alerts == nil || s.alerts.observe("sandbox:failed", message, markOnly) {
				if !markOnly {
					messages = append(messages, message)
				}
			}
		}
		sandboxRiskThreshold, _ := strconv.Atoi(getenv("SANDBOX_ALERT_RISK_SCORE", "50"))
		if sandboxRiskThreshold < 1 || sandboxRiskThreshold > 100 {
			sandboxRiskThreshold = 50
		}
		for _, result := range loadSandboxResults() {
			if result.RiskScore < sandboxRiskThreshold {
				continue
			}
			message := fmt.Sprintf("sandbox high-risk behavior: sha256=%s score=%d level=%s techniques=%d", result.SHA256, result.RiskScore, result.RiskLevel, len(result.Techniques))
			if s.alerts == nil || s.alerts.observe("sandbox:risk:"+result.Job, message, markOnly) {
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
