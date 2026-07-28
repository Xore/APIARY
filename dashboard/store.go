package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
func (s *store) rebuild() {
	var (
		total, logins, last24, previous24, downloads int
		srcIPs                                       = map[string]int{}
		sensors                                      = map[string]int{}
		protos                                       = map[string]int{}
		creds                                        = map[string]int{}
		commands                                     = map[string]int{}
		ports                                        = map[string]int{}
		paths                                        = map[string]int{}
		alerts                                       = map[string]int{}
		alertCats                                    = map[string]int{}
		countries                                    = map[string]int{}
		asns                                         = map[string]int{}
		providers                                    = map[string]int{}
		clients                                      = map[string]int{}
		fingerprints                                 = map[string]int{}
		points                                       = map[string]*mapPoint{}
		payloads                                     = map[string]*payloadRow{}
		lastSeen                                     = map[string]time.Time{}
		hourly                                       [24]int
		evs                                          []storedEvent
		seen                                         = map[string]bool{}
	)
	now := time.Now()

	// Recover real attacker IPs for cowrie (which only sees the tunnel peer)
	// by joining on the tunnel ephemeral port recorded in the portbridge log.
	viaMap := s.buildViaMap()

	for _, fn := range logFiles(s.dir) {
		rel, _ := filepath.Rel(s.dir, fn)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		dirSensor := "logs"
		if len(parts) > 1 {
			dirSensor = parts[0]
		}
		for _, line := range strings.Split(string(readTail(fn)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var e map[string]any
			if json.Unmarshal([]byte(line), &e) != nil {
				continue
			}
			ev := classify(e, dirSensor)
			if ev.skip {
				continue
			}
			ev.proto = normalizeProtocol(ev.proto)
			// Commands containing inline shell/PowerShell/VBS/etc. programs are
			// retained as inert, hash-addressed artifacts. They are never run.
			s.captureScriptPayload(&ev)
			// cowrie / dionaea / conpot only see the tunnel peer (10.8.0.1)
			// because their ports aren't PROXY-wrapped. Recover the real attacker
			// IP by matching the connection's src_port to the via_port portbridge
			// dialed from — every event in one connection shares that port, so
			// the whole chain (and its geo lookup below) gets the real IP.
			if ev.ip == tunnelPeerIP {
				if real := viaLookup(viaMap, eventSrcPort(e), ev.port); real != "" {
					ev.ip = real
				}
			}
			if key := dedupeKey(ev); key != "" {
				if seen[key] {
					continue
				}
				seen[key] = true
			}
			geo := geoInfo{Country: ev.country}
			if s.geo != nil && ev.ip != "" {
				geo = s.geo.lookup(ev.ip)
				if ev.country != "" {
					geo.Country = ev.country
				}
			}
			total++
			sensors[ev.sensor]++
			if ev.ip != "" {
				srcIPs[ev.ip]++
			}
			if ev.proto != "" {
				protos[ev.proto]++
			}
			if ev.isLogin {
				logins++
			}
			if ev.isLogin && validCredentialPair(ev.user, ev.pass) {
				creds[ev.user+" / "+ev.pass]++
			}
			if ev.command != "" {
				// Keep the sensor in the aggregate key so the command drill-down
				// can link to the exact source as well as the command text.
				commands[ev.sensor+"\x00"+ev.command]++
			}
			if ev.port != "" {
				ports[ev.port]++
			}
			// The HTTP OPTIONS asterisk-form is a request target, not a path.
			if strings.HasPrefix(ev.path, "/") {
				paths[ev.path]++
			}
			// Capture/decoder health warnings remain searchable in /events but
			// should not be presented as attacker detections on the overview.
			if ev.alert != "" && !isOperationalAlert(ev.alert) {
				alerts[ev.alert]++
			}
			if ev.category != "" && ev.sensor == "suricata" && !isOperationalAlert(ev.alert) {
				alertCats[ev.category]++
			}
			if ev.clientVer != "" {
				clients[ev.clientVer]++
			}
			if ev.fingerprint != "" {
				fingerprints[ev.fingerKind+"\x00"+ev.fingerprint]++
			}
			if geo.Country != "" {
				countries[geo.Country]++
			}
			if geo.ASN != 0 {
				asns[fmt.Sprintf("AS%d %s", geo.ASN, geo.Org)]++
			}
			provider := firstNonEmpty(geo.Intel, geo.Provider)
			if provider != "" {
				providers[provider]++
			}
			if geo.Lat != 0 || geo.Lon != 0 {
				p := points[ev.ip]
				if p == nil {
					p = &mapPoint{IP: ev.ip, Country: geo.Country, City: geo.City, Lat: geo.Lat, Lon: geo.Lon, ASN: geo.ASN, Org: geo.Org, Provider: geo.Provider, Intel: geo.Intel}
					points[ev.ip] = p
				}
				p.Count++
			}
			if ev.shasum != "" {
				downloads++
				p := payloads[ev.shasum]
				if p == nil {
					p = &payloadRow{Shasum: ev.shasum, Download: ev.download}
					payloads[ev.shasum] = p
				}
				p.Count++
			}
			if ev.when.After(lastSeen[ev.sensor]) {
				lastSeen[ev.sensor] = ev.when
			}
			if !ev.when.IsZero() {
				if age := now.Sub(ev.when); age >= 0 && age < 24*time.Hour {
					hourly[23-int(age.Hours())]++
					last24++
				} else if age >= 24*time.Hour && age < 48*time.Hour {
					previous24++
				}
			}
			evs = append(evs, storedEvent{
				when:          ev.when,
				Time:          ev.whenStr,
				Sensor:        ev.sensor,
				Persona:       ev.persona,
				Site:          ev.site,
				Asset:         ev.asset,
				PersonaOrg:    ev.personaOrg,
				SrcIP:         ev.ip,
				Country:       geo.Country,
				City:          geo.City,
				Lat:           geo.Lat,
				Lon:           geo.Lon,
				ASN:           geo.ASN,
				Org:           geo.Org,
				Provider:      geo.Provider,
				Intel:         geo.Intel,
				Proto:         ev.proto,
				Port:          ev.port,
				User:          ev.user,
				Pass:          ev.pass,
				Command:       ev.command,
				Path:          ev.path,
				Alert:         ev.alert,
				Session:       ev.session,
				Shasum:        ev.shasum,
				Download:      ev.download,
				ClientVer:     ev.clientVer,
				Fingerprint:   ev.fingerprint,
				FingerKind:    ev.fingerKind,
				Category:      ev.category,
				Severity:      ev.severity,
				Detail:        ev.detail,
				IsLogin:       ev.isLogin,
				HasCredential: ev.isLogin && validCredentialPair(ev.user, ev.pass),
				Kibana:        investigationURL(os.Getenv("KIBANA_PUBLIC_URL"), "kibana", ev.ip, ev.when),
				EveBox:        investigationURL(os.Getenv("EVEBOX_PUBLIC_URL"), "evebox", ev.ip, ev.when),
				Arkime:        investigationURL(os.Getenv("ARKIME_PUBLIC_URL"), "arkime", ev.ip, ev.when),
			})
		}
	}

	// Newest first; /events pages retain the complete tail. The dashboard feed
	// caps each sensor so a noisy source (normally cowrie) cannot hide every
	// lower-volume sensor such as conpot or dionaea.
	sort.Slice(evs, func(i, j int) bool { return evs[i].when.After(evs[j].when) })
	recents := balancedRecent(evs, recentCap, recentPerSensorCap)
	campaigns := correlateCampaigns(evs, now.Add(-7*24*time.Hour))

	// Feed freshness rows, busiest first. Expected sensors remain visible with
	// zero events, making a missing mount/path obvious without Docker access.
	for _, name := range s.expected {
		if _, ok := sensors[name]; !ok {
			sensors[name] = 0
		}
	}
	var sensorRows []sensorRow
	for _, sensor := range topN(sensors, 30) {
		sensorRows = append(sensorRows, sensorRow{
			Name: sensor.Key, Count: sensor.Count, Ago: ago(lastSeen[sensor.Key]),
			State: feedState(lastSeen[sensor.Key], now),
			Link:  eventsURL(url.Values{"sensor": {sensor.Key}}),
		})
	}

	// Command rows: split the sensor back out of the map key for display + link.
	cmdRows := topN(commands, 15)
	for i, r := range cmdRows {
		sensor, cmd, _ := strings.Cut(r.Key, "\x00")
		cmdRows[i].Key = "[" + sensor + "] " + compactText(cmd, 68)
		cmdRows[i].Title = cmd
		cmdRows[i].Link = eventsURL(url.Values{"sensor": {sensor}, "cmd": {cmd}})
	}

	// 24h chart: scale every bar against the busiest hour.
	maxHour := 1
	for _, c := range hourly {
		if c > maxHour {
			maxHour = c
		}
	}
	timeline := make([]bucket, len(hourly))
	for i, c := range hourly {
		t := now.Add(-time.Duration(len(hourly)-1-i) * time.Hour)
		timeline[i] = bucket{Label: t.Format("15"), Count: c, Pct: c * 100 / maxHour}
	}

	// Payload rows sorted by frequency, with a VirusTotal link per hash.
	var payloadRows []payloadRow
	for _, p := range payloads {
		p.Link = eventsURL(url.Values{"shasum": {p.Shasum}})
		p.VT = "https://www.virustotal.com/gui/file/" + p.Shasum
		payloadRows = append(payloadRows, *p)
	}
	sort.Slice(payloadRows, func(i, j int) bool {
		if payloadRows[i].Count != payloadRows[j].Count {
			return payloadRows[i].Count > payloadRows[j].Count
		}
		return payloadRows[i].Shasum < payloadRows[j].Shasum
	})
	var pointRows []mapPoint
	for _, p := range points {
		p.X = (p.Lon + 180) / 360 * 1000
		p.Y = (90 - p.Lat) / 180 * 450
		p.R = min(14, 3+int(math.Sqrt(float64(p.Count))))
		pointRows = append(pointRows, *p)
	}
	sort.Slice(pointRows, func(i, j int) bool { return pointRows[i].Count > pointRows[j].Count })
	if len(pointRows) > 500 {
		pointRows = pointRows[:500]
	}

	change, activity := "no prior baseline", "baseline unavailable"
	if previous24 > 0 {
		pct := (last24 - previous24) * 100 / previous24
		change = fmt.Sprintf("%+d%% vs previous 24h", pct)
		activity = "normal"
		if pct >= 100 {
			activity = "spike"
		} else if pct >= 35 {
			activity = "elevated"
		} else if pct <= -50 {
			activity = "low"
		}
	}
	snap := snapshot{
		Generated:      now,
		Total:          total,
		UniqueIPs:      len(srcIPs),
		Logins:         logins,
		Last24h:        last24,
		Previous24h:    previous24,
		Change24h:      change,
		ActivityState:  activity,
		Downloads:      downloads,
		GeoOn:          s.geo != nil,
		MapTileURL:     getenv("MAP_TILE_URL", "https://tile.openstreetmap.org/{z}/{x}/{y}.png"),
		MapAttribution: getenv("MAP_ATTRIBUTION", "© OpenStreetMap contributors"),
		Sensors:        sensorRows,
		Protocols:      linkRows(topN(protos, 12), "proto"),
		TopIPs:         linkRows(topN(srcIPs, 15), "ip"),
		TopPorts:       linkRows(topN(ports, 15), "port"),
		TopCreds:       credentialRows(topN(creds, 15)),
		TopCommands:    cmdRows,
		TopPaths:       linkRows(topN(paths, 15), "path"),
		Alerts:         linkRows(topN(alerts, 15), "sig"),
		AlertCats:      linkRows(topN(alertCats, 10), "cat"),
		Countries:      linkRows(topN(countries, 12), "country"),
		ASNs:           asnRows(topN(asns, 12)),
		Providers:      linkRows(topN(providers, 10), "provider"),
		Clients:        linkRows(topN(clients, 10), "client"),
		Fingerprints:   fingerprintRows(fingerprints, 12),
		MapPoints:      pointRows,
		Payloads:       payloadRows,
		Campaigns:      campaigns,
		Timeline:       timeline,
		Recent:         recents,
		Runtime:        currentRuntime(),
		YARA:           yaraSummary(s.yaraFile),
	}
	if s.es != nil {
		snap.ES = s.es.get()
	}
	s.mu.Lock()
	s.snap = snap
	s.events = evs
	s.mu.Unlock()
	if s.intelligence != nil && s.intelligence.due() {
		s.intelligence.save(intelligenceSnapshot{Version: 1, Generated: now, Campaigns: campaigns, Clusters: s.clustersData().Rows})
	}
	s.broadcast()
}

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
