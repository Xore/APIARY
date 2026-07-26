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
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// hashName matches a dionaea capture filename: a bare md5/sha1/sha256 hex hash.
// Enforced on the download path so a request can never escape the binaries dir.
var hashName = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)

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

var processStarted = time.Now()

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

// payloadRow is one captured malware sample: its hash, where the attacker put
// it, and how many times it was seen. The hash links out to VirusTotal.
type payloadRow struct {
	Shasum   string
	Download string
	Count    int
	Link     string // /events?shasum=…
	VT       string // VirusTotal lookup URL
}

type kv struct {
	Key   string
	Count int
	Link  string `json:",omitempty"` // optional /events?… drill-down URL
	Title string `json:",omitempty"` // full value when Key is shortened for display
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

// campaignRow correlates related sources by routable network over a rolling
// seven-day window. It deliberately retains only counts and short summaries;
// the link opens the complete matching event chain.
type campaignRow struct {
	CIDR         string
	Score        int
	Events       int
	UniqueIPs    int
	Sensors      string
	Ports        string
	Creds        int
	Payloads     int
	Alerts       int
	ASNs         string
	Providers    string
	Fingerprints int
	Sequence     string
	First        string
	Last         string
	Link         string
	Explanation  string
}

type mapPoint struct {
	IP       string  `json:"ip"`
	Country  string  `json:"country,omitempty"`
	City     string  `json:"city,omitempty"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	ASN      uint    `json:"asn,omitempty"`
	Org      string  `json:"organization,omitempty"`
	Provider string  `json:"provider_type,omitempty"`
	Intel    string  `json:"intel,omitempty"`
	Count    int     `json:"count"`
	X        float64 `json:"-"`
	Y        float64 `json:"-"`
	R        int     `json:"-"`
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

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// logFiles walks the log volume and returns every JSON-lines file, wherever a
// sensor put it (each sensor writes to its own subdirectory).
func logFiles(dir string) []string {
	var files []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// match foo.json and rotated foo.json.2026-07-18 / foo.json.1
		if strings.Contains(d.Name(), ".json") {
			files = append(files, p)
		}
		return nil
	})
	return files
}

// readTail returns up to tailCap bytes from the end of the file, aligned to
// the next full line when truncated.
func readTail(fn string) []byte {
	f, err := os.Open(fn)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	if st.Size() > tailCap {
		if _, err := f.Seek(st.Size()-tailCap, io.SeekStart); err != nil {
			return nil
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	if st.Size() > tailCap {
		if i := strings.IndexByte(string(data), '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	return data
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

// balancedRecent keeps global newest-first ordering while limiting how many
// rows one sensor may occupy. This is presentation-only: aggregates and the
// /events explorer still include every parsed event.
func balancedRecent(evs []storedEvent, limit, perSensor int) []storedEvent {
	if limit <= 0 || perSensor <= 0 {
		return nil
	}
	out := make([]storedEvent, 0, min(limit, len(evs)))
	counts := make(map[string]int)
	for _, ev := range evs {
		if isOverviewNoise(ev) {
			continue
		}
		if counts[ev.Sensor] >= perSensor {
			continue
		}
		out = append(out, ev)
		counts[ev.Sensor]++
		if len(out) == limit {
			break
		}
	}
	return out
}

// isOverviewNoise removes collection faults and internal-only traffic from the
// short live sample. The complete event explorer intentionally retains them.
func isOverviewNoise(ev storedEvent) bool {
	if ev.Sensor == "suricata" && isOperationalAlert(ev.Alert) {
		return true
	}
	if ev.SrcIP == tunnelPeerIP {
		return true
	}
	if addr, err := netip.ParseAddr(ev.SrcIP); err == nil && (addr.IsLoopback() || addr.IsLinkLocalUnicast()) {
		return true
	}
	return false
}

// dedupeKey removes duplicate representations of the same observation. This
// matters most for Dionaea, where log_json and log_incident both describe a
// connection. Rich payload/auth incidents retain their own detail and remain.
func dedupeKey(ev event) string {
	if ev.sensor == "" || ev.when.IsZero() {
		return ""
	}
	detail := ev.detail
	bucket := ev.when.UnixNano()
	if ev.sensor == "dionaea" && ev.shasum == "" && ev.user == "" && ev.pass == "" {
		if strings.HasPrefix(detail, "connection.") || strings.Contains(detail, "/") {
			detail = "connection"
			bucket = ev.when.Unix() / 3
		}
	}
	return fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s", ev.sensor, ev.ip, ev.port, ev.proto, bucket, detail, ev.session)
}

func campaignCIDR(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return ""
	}
	a = a.Unmap()
	bits := 64
	if a.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(a, bits).Masked().String()
}

func sortedSet(m map[string]bool, limit int) string {
	items := make([]string, 0, len(m))
	for item := range m {
		if item != "" {
			items = append(items, item)
		}
	}
	sort.Strings(items)
	if len(items) > limit {
		items = append(items[:limit], fmt.Sprintf("+%d", len(items)-limit))
	}
	return strings.Join(items, " ")
}

func correlateCampaigns(evs []storedEvent, since time.Time) []campaignRow {
	type agg struct {
		events, alerts  int
		ips, sensors    map[string]bool
		ports, creds    map[string]bool
		payloads        map[string]bool
		asns, providers map[string]bool
		fingerprints    map[string]bool
		sequence        []string
		first, last     time.Time
	}
	groups := map[string]*agg{}
	for _, e := range evs {
		if e.when.IsZero() || e.when.Before(since) {
			continue
		}
		cidr := campaignCIDR(e.SrcIP)
		if cidr == "" {
			continue
		}
		a := groups[cidr]
		if a == nil {
			a = &agg{ips: map[string]bool{}, sensors: map[string]bool{}, ports: map[string]bool{}, creds: map[string]bool{}, payloads: map[string]bool{}, asns: map[string]bool{}, providers: map[string]bool{}, fingerprints: map[string]bool{}}
			groups[cidr] = a
		}
		a.events++
		a.ips[e.SrcIP], a.sensors[e.Sensor], a.ports[e.Port] = true, true, true
		if e.IsLogin && validCredentialPair(e.User, e.Pass) {
			a.creds[e.User+" / "+e.Pass] = true
		}
		if e.Shasum != "" {
			a.payloads[e.Shasum] = true
		}
		if e.Alert != "" {
			a.alerts++
		}
		if e.ASN != 0 {
			a.asns[fmt.Sprintf("AS%d", e.ASN)] = true
		}
		if p := firstNonEmpty(e.Intel, e.Provider); p != "" {
			a.providers[p] = true
		}
		if e.Fingerprint != "" {
			a.fingerprints[e.Fingerprint] = true
		}
		if len(a.sequence) < 8 && (len(a.sequence) == 0 || a.sequence[len(a.sequence)-1] != e.Sensor) {
			a.sequence = append(a.sequence, e.Sensor)
		}
		if a.first.IsZero() || e.when.Before(a.first) {
			a.first = e.when
		}
		if e.when.After(a.last) {
			a.last = e.when
		}
	}
	rows := make([]campaignRow, 0, len(groups))
	for cidr, a := range groups {
		score := min(100, min(a.events, 30)+len(a.sensors)*15+len(a.ips)*3+len(a.creds)*8+len(a.payloads)*20+min(a.alerts, 15)*2+len(a.fingerprints)*3+len(a.providers)*2)
		var why []string
		if len(a.sensors) > 1 {
			why = append(why, fmt.Sprintf("cross-sensor activity (%d)", len(a.sensors)))
		}
		if len(a.ips) > 1 {
			why = append(why, fmt.Sprintf("%d related source IPs", len(a.ips)))
		}
		if len(a.payloads) > 0 {
			why = append(why, fmt.Sprintf("%d shared payloads", len(a.payloads)))
		}
		if len(a.creds) > 0 {
			why = append(why, fmt.Sprintf("%d reused credentials", len(a.creds)))
		}
		if a.alerts > 0 {
			why = append(why, fmt.Sprintf("%d IDS alerts", a.alerts))
		}
		if len(a.fingerprints) > 0 {
			why = append(why, fmt.Sprintf("%d fingerprints", len(a.fingerprints)))
		}
		if len(why) == 0 {
			why = append(why, "repeated activity from one routable network")
		}
		rows = append(rows, campaignRow{
			CIDR: cidr, Score: score, Events: a.events, UniqueIPs: len(a.ips),
			Sensors: sortedSet(a.sensors, 6), Ports: sortedSet(a.ports, 8),
			Creds: len(a.creds), Payloads: len(a.payloads), Alerts: a.alerts,
			ASNs: sortedSet(a.asns, 4), Providers: sortedSet(a.providers, 4), Fingerprints: len(a.fingerprints),
			Sequence: strings.Join(a.sequence, " ← "),
			First:    a.first.Format("2006-01-02 15:04"), Last: a.last.Format("2006-01-02 15:04"),
			Link:        eventsURL(url.Values{"cidr": {cidr}, "since": {"168h"}}),
			Explanation: strings.Join(why, "; "),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		if rows[i].Events != rows[j].Events {
			return rows[i].Events > rows[j].Events
		}
		return rows[i].CIDR < rows[j].CIDR
	})
	if len(rows) > 50 {
		rows = rows[:50]
	}
	return rows
}

func eventsURL(v url.Values) string { return "/events?" + v.Encode() }

func investigationURL(base, kind, ip string, when time.Time) string {
	if base == "" || ip == "" {
		return ""
	}
	base = strings.TrimRight(base, "/")
	switch kind {
	case "arkime":
		return base + "/sessions?date=-1&expression=" + url.QueryEscape("ip == "+ip)
	case "evebox":
		// EveBox's SPA reads inbox searches from the URL fragment. A normal
		// server-side query path opens the shell but does not populate its
		// alert search field.
		return base + "/#/inbox?q=" + url.QueryEscape(ip)
	default:
		from, to := when.Add(-5*time.Minute).UTC().Format(time.RFC3339), when.Add(5*time.Minute).UTC().Format(time.RFC3339)
		return base + "/app/discover#/?_g=" + url.QueryEscape("(time:(from:'"+from+"',to:'"+to+"'))") + "&_a=" + url.QueryEscape("(query:(language:kuery,query:'"+ip+"'))")
	}
}

// linkRows attaches a single-param /events drill-down link to each row.
func linkRows(rows []kv, param string) []kv {
	for i := range rows {
		rows[i].Link = eventsURL(url.Values{param: {rows[i].Key}})
	}
	return rows
}

// credentialRows preserves the exact raw pair in the drill-down URL while
// making empty values explicit in the table instead of rendering a dangling
// separator that can be mistaken for a display bug.
func credentialRows(rows []kv) []kv {
	for i := range rows {
		raw := rows[i].Key
		rows[i].Link = eventsURL(url.Values{"cred": {raw}})
		user, pass, ok := strings.Cut(raw, " / ")
		if !ok {
			continue
		}
		if user == "" {
			user = "(empty)"
		}
		if pass == "" {
			pass = "(empty)"
		}
		rows[i].Key = user + " / " + pass
	}
	return rows
}

// validCredentialPair prevents protocol fields and command payloads from
// leaking into the login ranking when a sensor reuses username/password keys
// for non-authentication incident data.
func validCredentialPair(user, pass string) bool {
	if user == "" && pass == "" || len(user) > 128 || len(pass) > 512 {
		return false
	}
	for _, value := range []string{user, pass} {
		lower := strings.ToLower(value)
		if strings.ContainsAny(value, "\x00\r\n") || strings.Contains(lower, `\x00`) || strings.Contains(lower, `\u0000`) {
			return false
		}
	}
	if strings.ContainsAny(user, " \t/;|&<>") {
		return false
	}
	lowerPass := strings.ToLower(strings.TrimSpace(pass))
	for _, marker := range []string{"/bin/", "busybox", "linuxshell", "powershell", "cmd.exe"} {
		if strings.Contains(lowerPass, marker) {
			return false
		}
	}
	return true
}

// normalizeProtocol collapses implementation-specific service names into the
// protocol labels an operator expects. This also prevents one protocol from
// appearing as several separate rows.
func normalizeProtocol(proto string) string {
	p := strings.ToLower(strings.TrimSpace(proto))
	switch p {
	case "smbd":
		return "smb"
	case "mssqld", "tds":
		return "mssql"
	case "mysqld":
		return "mysql"
	case "mongod":
		return "mongodb"
	case "pptpd":
		return "pptp"
	case "sipcall", "sipsession":
		return "sip"
	case "httpd":
		return "http"
	case "ftpd":
		return "ftp"
	default:
		return p
	}
}

// isOperationalAlert identifies sensor/capture health findings that are useful
// in the event explorer but misleading in an attacker-focused alert ranking.
func isOperationalAlert(signature string) bool {
	s := strings.ToLower(strings.TrimSpace(signature))
	return strings.Contains(s, "truncated packet") || strings.HasPrefix(s, "suricata af-packet")
}

// asnRows keeps the human-readable organization while filtering on the exact
// numeric ASN embedded at the beginning of each aggregate key.
func asnRows(rows []kv) []kv {
	for i := range rows {
		asn := strings.TrimPrefix(strings.Fields(rows[i].Key)[0], "AS")
		rows[i].Link = eventsURL(url.Values{"asn": {asn}})
	}
	return rows
}

func fingerprintRows(counts map[string]int, n int) []kv {
	rows := topN(counts, n)
	for i := range rows {
		kind, value, ok := strings.Cut(rows[i].Key, "\x00")
		if !ok {
			value = rows[i].Key
		}
		if kind == "" {
			kind = "fingerprint"
		}
		rows[i].Key = kind + ": " + compactText(value, 76)
		rows[i].Title = value
		rows[i].Link = eventsURL(url.Values{"fingerprint": {value}})
	}
	return rows
}

func compactText(value string, limit int) string {
	runes := []rune(strings.TrimSpace(value))
	if limit < 2 || len(runes) <= limit {
		return string(runes)
	}
	return string(runes[:limit-1]) + "…"
}

// event is one normalised log record, whatever sensor it came from.
type event struct {
	sensor      string
	persona     string
	site        string
	asset       string
	personaOrg  string
	detail      string
	ip          string
	proto       string
	user        string
	pass        string
	command     string
	port        string // public port the attacker targeted, where the sensor knows it
	path        string // HTTP path probed (http-honeypot / tanner)
	alert       string // suricata alert signature
	session     string // cowrie session id — correlates every event in one login
	shasum      string // sha-256 of a captured payload (cowrie downloads)
	download    string // where the attacker tried to write the payload
	clientVer   string // ssh/telnet client banner (cowrie) — cheap fingerprint
	fingerprint string // user-agent/client identity reused across sensors
	fingerKind  string // HASSH / JA3 / JA4 / User-Agent / client banner
	category    string // suricata alert category / http probe class
	country     string // ISO country code, from a cf-ipcountry header when present
	severity    int    // suricata alert severity (1 = most severe)
	isLogin     bool
	skip        bool
	when        time.Time
	whenStr     string
}

// tunnelPeerIP is the WireGuard peer address cowrie logs for every session:
// portbridge terminates the attacker's TCP on the VPS and re-dials over the
// tunnel, and cowrie's haproxy endpoint is disabled (Twisted incompat), so the
// only real-IP source for cowrie is the portbridge conn-log (see buildViaMap).
const tunnelPeerIP = "10.8.0.1"

// viaEntry is one portbridge connection indexed by its tunnel-side local port.
type viaEntry struct {
	ip   string
	port string // portbridge listen port (22/23/…) — a sanity check on the join
}

// buildViaMap indexes the portbridge connection log by via_port: the tunnel
// ephemeral port portbridge dialed the honeypot from, which equals the src_port
// the honeypot observes for that same connection. Entries are kept as a
// chronological list per port because an ephemeral port is reused over time —
// possibly across different honeypot ports — so the lookup can pick the most
// recent entry whose listen port matches the event (see viaLookup).
func (s *store) buildViaMap() map[int][]viaEntry {
	m := map[int][]viaEntry{}
	data := readTail(filepath.Join(s.dir, "portbridge", "portbridge.json"))
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if str(e["sensor"]) != "portbridge" {
			continue
		}
		vp := int(numFloat(e["via_port"]))
		if vp == 0 {
			continue
		}
		m[vp] = append(m[vp], viaEntry{ip: str(e["src_ip"]), port: num(e["port"])})
	}
	return m
}

// viaLookup returns the real attacker IP for a tunnel-peer connection: the most
// recent portbridge entry for this via_port whose listen port matches the
// honeypot port the event hit (port="" matches anything). Empty if none.
func viaLookup(m map[int][]viaEntry, srcPort int, port string) string {
	cands := m[srcPort]
	for i := len(cands) - 1; i >= 0; i-- { // newest first
		if port == "" || cands[i].port == "" || cands[i].port == port {
			return cands[i].ip
		}
	}
	return ""
}

// classify normalises one raw JSON record. dirSensor is the name of the
// subdirectory the log file lives in — used as the sensor name for formats we
// don't specifically recognise, so every log under /logs shows up.
func classify(e map[string]any, dirSensor string) event {
	ev := event{
		sensor: dirSensor, persona: str(e["persona_id"]), site: str(e["site_id"]),
		asset: str(e["asset_id"]), personaOrg: str(e["organization"]),
	}
	ev.when, ev.whenStr = when(e)
	ev.ip = ipOf(e)

	// Drop loopback healthchecks: multipot's -healthcheck dials 127.0.0.1:6379
	// and http-honeypot's Docker HEALTHCHECK GETs http://127.0.0.1:8080/. A real
	// external attacker never appears as loopback, so unless a trusted forwarded
	// header carries a real client IP this is pure noise.
	if (ev.ip == "127.0.0.1" || ev.ip == "::1") && !hasForwardedIP(e) {
		ev.skip = true
		return ev
	}

	// ---- cowrie -----------------------------------------------------------
	if eid, ok := e["eventid"].(string); ok && strings.HasPrefix(eid, "cowrie.") {
		ev.sensor = "cowrie"
		ev.persona, ev.site, ev.asset, ev.personaOrg = "nexusai-gpu01", "nexusai-berlin-ml", "gpu01", "NexusAI Research GmbH"
		ev.user, ev.pass = str(e["username"]), str(e["password"])
		ev.session = str(e["session"]) // ties every event in one login together
		if p := str(e["protocol"]); p != "" {
			ev.proto = p // ssh / telnet
		}
		// cowrie sees its container port (2222/2223) — report the public one on
		// every event so port drill-downs are complete, not just on connect.
		switch num(e["dst_port"]) {
		case "2222":
			ev.port = "22"
		case "2223":
			ev.port = "23"
		}
		switch {
		case strings.Contains(eid, "login"):
			ev.isLogin = true
			ev.detail = eid[len("cowrie."):] + ": " + ev.user + " / " + ev.pass
		case eid == "cowrie.command.input", eid == "cowrie.command.failed":
			ev.command = str(e["input"])
			ev.detail = "cmd: " + ev.command
		case eid == "cowrie.session.file_download", eid == "cowrie.session.file_upload":
			ev.shasum = str(e["shasum"])
			ev.download = firstNonEmpty(str(e["destfile"]), str(e["url"]), str(e["filename"]))
			ev.detail = "payload " + shortHash(ev.shasum)
			if ev.download != "" {
				ev.detail += " -> " + ev.download
			}
		case eid == "cowrie.client.version":
			ev.clientVer = str(e["version"])
			ev.fingerprint = ev.clientVer
			ev.fingerKind = "SSH client"
			ev.detail = "client: " + ev.clientVer
		case eid == "cowrie.client.kex":
			ev.fingerprint = str(e["hassh"])
			ev.fingerKind = "HASSH"
			ev.detail = "SSH HASSH: " + ev.fingerprint
		case eid == "cowrie.session.connect":
			ev.detail = "connect"
		case eid == "cowrie.session.closed":
			ev.detail = "closed"
			if d := num(e["duration"]); d != "" {
				ev.detail = "closed after " + d + "s"
			}
		default:
			ev.detail = eid[len("cowrie."):]
		}
		return ev
	}

	// ---- multipot ---------------------------------------------------------
	if s, ok := e["sensor"].(string); ok && s == "multipot" {
		kind := str(e["event"])
		if kind == "listening" || kind == "multipot_started" || kind == "listen_error" {
			ev.skip = true
			return ev
		}
		ev.sensor = "multipot"
		ev.proto = str(e["proto"])
		ev.port = num(e["port"])
		ev.user, ev.pass = str(e["username"]), str(e["password"])
		switch kind {
		case "login":
			ev.isLogin = true
			ev.detail = ev.proto + " login: " + ev.user + " / " + ev.pass
		case "command":
			ev.command = str(e["command"])
			ev.detail = ev.proto + ": " + ev.command
		default:
			ev.detail = ev.proto + " " + kind
		}
		return ev
	}

	// ---- dionaea incident handler ----------------------------------------
	// log_incident records every lifecycle and payload incident as
	// {origin:"dionaea.*", data:{connection:{...}, ...}}. Keep these richer
	// records in addition to log_json's one-record-per-connection summary.
	if origin := str(e["origin"]); strings.HasPrefix(origin, "dionaea.") {
		ev.sensor = "dionaea"
		ev.persona, ev.site, ev.asset, ev.personaOrg = "meridian-legacy", "meridian-hamburg-dc1", "legacy-svc-02", "Meridian Retail Systems Ltd."
		kind := strings.TrimPrefix(origin, "dionaea.")
		data, _ := e["data"].(map[string]any)
		conn, _ := data["connection"].(map[string]any)
		ev.proto = str(conn["protocol"])
		ev.ip = firstNonEmpty(str(conn["remote_ip"]), ev.ip)
		ev.port = num(conn["local_port"])
		ev.user = firstNonEmpty(str(data["username"]), str(data["user"]), str(data["login"]))
		ev.pass = firstNonEmpty(str(data["password"]), str(data["pass"]))
		ev.download = firstNonEmpty(str(data["url"]), str(data["path"]), str(data["file"]), str(data["filename"]))
		ev.shasum = firstNonEmpty(str(data["sha256"]), str(data["sha256hash"]),
			str(data["sha1"]), str(data["md5"]), str(data["md5hash"]))
		if ev.shasum == "" && ev.download != "" {
			base := filepath.Base(ev.download)
			if hashName.MatchString(base) {
				ev.shasum = base
			}
		}
		ev.isLogin = (ev.user != "" || ev.pass != "") &&
			(strings.Contains(kind, "login") || strings.Contains(kind, "auth"))
		ev.detail = kind
		if ev.download != "" {
			ev.detail += " " + ev.download
		}
		if ev.shasum != "" && !strings.Contains(ev.detail, ev.shasum) {
			ev.detail += " [" + shortHash(ev.shasum) + "]"
		}
		return ev
	}

	// ---- dionaea (log_json: one record per connection) --------------------
	// The dtagdevsec image puts addresses at the top level (src_ip/src_port/
	// dst_port, already read into ev.ip via ipOf); older builds nest them under
	// connection.remote_ip/local_port. Support both. The tunnel-peer IP is
	// rewritten to the real attacker below via the portbridge via_port join.
	if conn, ok := e["connection"].(map[string]any); ok {
		ev.sensor = "dionaea"
		ev.persona, ev.site, ev.asset, ev.personaOrg = "meridian-legacy", "meridian-hamburg-dc1", "legacy-svc-02", "Meridian Retail Systems Ltd."
		ev.proto = str(conn["protocol"])
		if rip := str(conn["remote_ip"]); rip != "" {
			ev.ip = rip
		}
		ev.port = firstNonEmpty(num(e["dst_port"]), num(conn["local_port"]))
		ev.detail = strings.TrimSpace(ev.proto + "/" + str(conn["transport"]) + " " + str(conn["type"]))
		if ev.port != "" {
			ev.detail += " -> :" + ev.port
		}
		// credential capture (e.g. ftp/mysql logins) rides along on the record
		if credsAny, ok := e["credentials"].([]any); ok && len(credsAny) > 0 {
			if c, ok := credsAny[0].(map[string]any); ok {
				ev.user, ev.pass = str(c["username"]), str(c["password"])
				ev.isLogin = true
			}
		}
		return ev
	}

	// ---- conpot -----------------------------------------------------------
	if strings.HasPrefix(dirSensor, "conpot") || e["data_type"] != nil || e["sensorid"] != nil {
		ev.sensor = "conpot"
		if strings.HasPrefix(dirSensor, "conpot-") {
			ev.sensor = dirSensor
		}
		ev.persona, ev.site, ev.asset, ev.personaOrg = personaForSensor(ev.sensor)
		ev.proto = str(e["data_type"])
		ev.port = num(e["dst_port"]) // tunnel-peer IP rewritten via via_port below
		// The extra PLCs listen on canonical ports inside their containers but
		// are published on distinct VPS ports. Normalize before the portbridge
		// join so its listen-port sanity check can recover the attacker IP.
		switch dirSensor + ":" + ev.port {
		case "conpot-s7-1200:102":
			ev.port = "1102"
		case "conpot-s7-1200:502":
			ev.port = "1502"
		case "conpot-s7-1500:102":
			ev.port = "2102"
		case "conpot-s7-1500:502":
			ev.port = "2502"
		}
		req := firstNonEmpty(str(e["request"]), str(e["event_type"]))
		ev.detail = strings.TrimSpace(ev.proto + " " + req)
		if ev.detail == "" {
			ev.detail = "probe"
		}
		return ev
	}

	// ---- tanner session report (legacy "peer" shape) ----------------------
	if peer, ok := e["peer"].(map[string]any); ok {
		ev.sensor = "tanner"
		ev.persona, ev.site, ev.asset, ev.personaOrg = "meridian-customer-portal", "meridian-public-web", "customer-portal-02", "Meridian Retail Systems Ltd."
		ev.proto = "http"
		ev.ip = firstNonEmpty(str(peer["ip"]), ev.ip)
		var paths []string
		if ps, ok := e["paths"].([]any); ok {
			for _, p := range ps {
				if pm, ok := p.(map[string]any); ok {
					paths = append(paths, str(pm["path"]))
				}
				if len(paths) >= 3 {
					break
				}
			}
		}
		if len(paths) == 0 && str(e["path"]) != "" {
			paths = append(paths, str(e["path"]))
		}
		if len(paths) > 0 {
			ev.path = paths[0]
		}
		ev.detail = strings.Join(paths, " ")
		if at, ok := e["attack_types"].([]any); ok && len(at) > 0 {
			var kinds []string
			for _, a := range at {
				kinds = append(kinds, str(a))
			}
			ev.detail += "  [" + strings.Join(kinds, ",") + "]"
		}
		if ev.detail == "" {
			ev.detail = "web session"
		}
		return ev
	}

	// ---- tanner_report.json (method/path/headers shape) + http-honeypot ----
	// Both share the request-log shape. tanner reports come from the tanner
	// dir; http-honeypot sets a "sensor"/"category" field. Real client IP and
	// country ride in Cloudflare headers when fronted by CF.
	if str(e["method"]) != "" || str(e["category"]) != "" {
		if str(e["category"]) == "startup" {
			ev.skip = true
			return ev
		}
		hdr := headerMap(e["headers"])
		ev.sensor = "http"
		if rawSensor := str(e["sensor"]); rawSensor != "" && rawSensor != "http-honeypot" {
			ev.sensor = rawSensor
		}
		if dirSensor == "tanner" || headerVal(hdr, "cf-ray") != "" && str(e["sensor"]) == "" {
			ev.sensor = "tanner"
		}
		if ev.sensor == "tanner" && ev.persona == "" {
			ev.persona, ev.site, ev.asset, ev.personaOrg = "meridian-customer-portal", "meridian-public-web", "customer-portal-02", "Meridian Retail Systems Ltd."
		}
		ev.proto = "http"
		ev.user, ev.pass = str(e["username"]), str(e["password"])
		ev.path = str(e["path"])
		ev.category = str(e["category"])
		if ev.fingerprint = headerVal(hdr, "x-ja4"); ev.fingerprint != "" {
			ev.fingerKind = "JA4"
		} else if ev.fingerprint = headerVal(hdr, "x-ja3"); ev.fingerprint != "" {
			ev.fingerKind = "JA3"
		} else if ev.fingerprint = headerVal(hdr, "user-agent"); ev.fingerprint != "" {
			ev.fingerKind = "User-Agent"
		}
		// Prefer the trustworthy CF/Traefik forwarded IP over the transport peer.
		ev.ip = firstNonEmpty(headerVal(hdr, "cf-connecting-ip"), headerVal(hdr, "x-real-ip"),
			firstHop(headerVal(hdr, "x-forwarded-for")), ev.ip, str(e["src_ip"]))
		ev.country = headerVal(hdr, "cf-ipcountry")
		ev.detail = strings.TrimSpace(str(e["method"]) + " " + ev.path)
		if ev.user != "" || ev.pass != "" {
			ev.isLogin = true
			ev.detail += "  (" + ev.user + " / " + ev.pass + ")"
		}
		return ev
	}

	// ---- suricata eve.json (VPS logs mounted at /logs/suricata) -----------
	if et := str(e["event_type"]); et != "" && dirSensor == "suricata" {
		if et != "alert" {
			ev.skip = true // flow/dns/netflow/stats records would swamp the counts
			return ev
		}
		ev.sensor = "suricata"
		ev.proto = strings.ToLower(str(e["proto"]))
		ev.port = num(e["dest_port"])
		if tls, ok := e["tls"].(map[string]any); ok {
			if ev.fingerprint = str(tls["ja4"]); ev.fingerprint != "" {
				ev.fingerKind = "JA4"
			} else if ja3, ok := tls["ja3"].(map[string]any); ok {
				ev.fingerprint, ev.fingerKind = str(ja3["hash"]), "JA3"
			}
		}
		if httpData, ok := e["http"].(map[string]any); ok && ev.fingerprint == "" {
			ev.fingerprint, ev.fingerKind = str(httpData["http_user_agent"]), "User-Agent"
		}
		if sshData, ok := e["ssh"].(map[string]any); ok && ev.fingerprint == "" {
			if client, ok := sshData["client"].(map[string]any); ok {
				ev.fingerprint, ev.fingerKind = str(client["software_version"]), "SSH client"
			}
		}
		if a, ok := e["alert"].(map[string]any); ok {
			ev.alert = str(a["signature"])
			ev.category = str(a["category"])
			ev.severity = int(numFloat(a["severity"]))
			ev.detail = ev.alert
			if ev.category != "" {
				ev.detail += "  [" + ev.category + "]"
			}
		}
		if ev.detail == "" {
			ev.detail = "alert"
		}
		return ev
	}

	// ---- portbridge connection log (real attacker IP for every port) ------
	if s := str(e["sensor"]); s == "portbridge" {
		// buildViaMap consumes these records separately to recover the real
		// attacker IP for tunnelled sensors. They are transport metadata, not
		// honeypot observations, so never count or display them as a sensor.
		ev.skip = true
		return ev
	}

	// ---- anything else under /logs ----------------------------------------
	// Unknown JSON record: attribute it to its directory so new sensors show
	// up without a code change.
	if p := str(e["proto"]); p != "" && p != "-" {
		ev.proto = p
	}
	ev.detail = firstNonEmpty(str(e["event"]), str(e["event_type"]), str(e["message"]), str(e["msg"]), "event")
	return ev
}

func personaForSensor(sensor string) (persona, site, asset, org string) {
	values := map[string][4]string{
		"conpot":          {"rheinwerk-water-s7-200", "rheinwerk-intake", "plc-intake-01", "Rheinwerk Municipal Water"},
		"conpot-s7-1200":  {"rheinwerk-water-s7-1200", "rheinwerk-treatment", "plc-filter-02", "Rheinwerk Municipal Water"},
		"conpot-s7-1500":  {"nordchem-s7-1500", "nordchem-reactor-4", "plc-reactor-04", "NordChem Process Industries"},
		"conpot-iec104":   {"elbegrid-iec104", "elbegrid-substation-17", "rtu-sub17-a", "ElbeGrid Distribution"},
		"conpot-guardian": {"northfuel-guardian", "northfuel-station-042", "tankmon-042", "NorthFuel Service GmbH"},
		"conpot-kamstrup": {"stadtwaerme-kamstrup", "stadtwaerme-loop-west", "heatmeter-west-0382", "Stadtwaerme Nord"},
	}
	v := values[sensor]
	return v[0], v[1], v[2], v[3]
}

// when extracts a timestamp from the record in whatever shape the sensor
// logged it (ISO string under several key names, or a unix epoch number).
func when(e map[string]any) (time.Time, string) {
	for _, k := range []string{"timestamp", "time", "@timestamp", "start_time", "ts"} {
		switch v := e[k].(type) {
		case string:
			if v == "" {
				continue
			}
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339,
				"2006-01-02T15:04:05.999999-0700", // suricata eve.json
				"2006-01-02T15:04:05.999999", "2006-01-02 15:04:05,999", "2006-01-02 15:04:05"} {
				if t, err := time.Parse(layout, v); err == nil {
					return t, t.Format("2006-01-02 15:04:05")
				}
			}
			return time.Time{}, v // unknown format — display raw, sorts last
		case float64:
			if v <= 0 {
				continue
			}
			t := time.Unix(int64(v), int64((v-float64(int64(v)))*1e9))
			return t, t.Format("2006-01-02 15:04:05")
		}
	}
	return time.Time{}, ""
}

// ipOf hunts for a source address across the field names the sensors use.
func ipOf(e map[string]any) string {
	for _, k := range []string{"src_ip", "remote_ip", "peer_ip", "client_ip", "ip"} {
		if v := str(e[k]); v != "" {
			return v
		}
	}
	// conpot: "remote": ["1.2.3.4", 51234]
	if r, ok := e["remote"].([]any); ok && len(r) > 0 {
		return str(r[0])
	}
	return ""
}

// eventSrcPort returns the tunnel-side peer port used to correlate a sensor
// event with the VPS portbridge connection that carried it.
func eventSrcPort(e map[string]any) int {
	if p := int(numFloat(e["src_port"])); p != 0 {
		return p
	}
	if conn, ok := e["connection"].(map[string]any); ok {
		if p := int(numFloat(conn["remote_port"])); p != 0 {
			return p
		}
	}
	if data, ok := e["data"].(map[string]any); ok {
		if conn, ok := data["connection"].(map[string]any); ok {
			return int(numFloat(conn["remote_port"]))
		}
	}
	return 0
}

// ago renders a last-seen time as a rough relative age.
func ago(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func feedState(last, now time.Time) string {
	if last.IsZero() {
		return "waiting"
	}
	age := now.Sub(last)
	if age < 20*time.Minute {
		return "active"
	}
	if age < 24*time.Hour {
		return "quiet"
	}
	return "stale"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// shortHash trims a sha-256 to its first 12 hex chars for compact display.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// headerMap coerces a JSON headers object into a plain string map.
func headerMap(v any) map[string]string {
	m := map[string]string{}
	if raw, ok := v.(map[string]any); ok {
		for k, val := range raw {
			m[strings.ToLower(k)] = str(val)
		}
	}
	return m
}

// headerVal reads a header case-insensitively (keys are already lowercased).
func headerVal(m map[string]string, key string) string { return m[strings.ToLower(key)] }

// hasForwardedIP reports whether a record carries a trusted forwarded client IP
// (Cloudflare / reverse-proxy headers) — used to avoid dropping a real request
// that merely arrived over loopback from a local proxy.
func hasForwardedIP(e map[string]any) bool {
	h := headerMap(e["headers"])
	return headerVal(h, "cf-connecting-ip") != "" ||
		headerVal(h, "x-forwarded-for") != "" ||
		headerVal(h, "x-real-ip") != ""
}

// firstHop returns the left-most address of an X-Forwarded-For chain.
func firstHop(xff string) string {
	if xff == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(xff, ",")[0])
}

func numFloat(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func num(v any) string {
	if f, ok := v.(float64); ok {
		return fmt.Sprintf("%.0f", f)
	}
	return ""
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

// filter holds the /events query parameters. All set fields must match (AND).
type filter struct {
	ip, cidr, port, sensor, proto, path string // exact match, except CIDR containment
	persona, site, asset                string // exact honeypot identity metadata
	cred, cmd, session, shasum          string // exact match
	cat, country, client                string // exact match
	fingerprint, provider, org, asn     string // exact enriched metadata
	sig, q                              string // case-insensitive substring
	typ                                 string // login | command | alert | download
	since                               time.Time
	sinceStr                            string
}

func parseFilter(r *http.Request) filter {
	v := r.URL.Query()
	f := filter{
		ip: v.Get("ip"), cidr: v.Get("cidr"), port: v.Get("port"), sensor: v.Get("sensor"),
		proto: v.Get("proto"), path: v.Get("path"), cred: v.Get("cred"),
		persona: v.Get("persona"), site: v.Get("site"), asset: v.Get("asset"),
		cmd: v.Get("cmd"), session: v.Get("session"), shasum: v.Get("shasum"),
		cat: v.Get("cat"), country: v.Get("country"), client: v.Get("client"),
		fingerprint: v.Get("fingerprint"), provider: v.Get("provider"), org: v.Get("org"), asn: v.Get("asn"),
		sig: v.Get("sig"), q: v.Get("q"), typ: v.Get("type"),
	}
	if d, err := time.ParseDuration(v.Get("since")); err == nil && d > 0 {
		f.since = time.Now().Add(-d)
		f.sinceStr = v.Get("since")
	}
	return f
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func (f filter) match(e storedEvent) bool {
	if f.ip != "" && e.SrcIP != f.ip {
		return false
	}
	if f.cidr != "" {
		prefix, pErr := netip.ParsePrefix(f.cidr)
		addr, aErr := netip.ParseAddr(e.SrcIP)
		if pErr != nil || aErr != nil || !prefix.Contains(addr.Unmap()) {
			return false
		}
	}
	if f.port != "" && e.Port != f.port {
		return false
	}
	if f.sensor != "" && e.Sensor != f.sensor {
		return false
	}
	if f.proto != "" && e.Proto != f.proto {
		return false
	}
	if f.persona != "" && e.Persona != f.persona {
		return false
	}
	if f.site != "" && e.Site != f.site {
		return false
	}
	if f.asset != "" && e.Asset != f.asset {
		return false
	}
	if f.path != "" && e.Path != f.path {
		return false
	}
	if f.cred != "" && ((e.User == "" && e.Pass == "") || e.User+" / "+e.Pass != f.cred) {
		return false
	}
	if f.cmd != "" && e.Command != f.cmd {
		return false
	}
	if f.session != "" && e.Session != f.session {
		return false
	}
	if f.shasum != "" && e.Shasum != f.shasum {
		return false
	}
	if f.cat != "" && e.Category != f.cat {
		return false
	}
	if f.country != "" && e.Country != f.country {
		return false
	}
	if f.client != "" && e.ClientVer != f.client {
		return false
	}
	if f.fingerprint != "" && e.Fingerprint != f.fingerprint {
		return false
	}
	if f.provider != "" && firstNonEmpty(e.Intel, e.Provider) != f.provider {
		return false
	}
	if f.org != "" && e.Org != f.org {
		return false
	}
	if f.asn != "" && strconv.FormatUint(uint64(e.ASN), 10) != strings.TrimPrefix(strings.ToUpper(f.asn), "AS") {
		return false
	}
	if f.sig != "" && (e.Alert == "" || !containsFold(e.Alert, f.sig)) {
		return false
	}
	switch f.typ {
	case "login":
		if !e.IsLogin {
			return false
		}
	case "command":
		if e.Command == "" {
			return false
		}
	case "alert":
		if e.Alert == "" {
			return false
		}
	case "download":
		if e.Shasum == "" {
			return false
		}
	}
	if !f.since.IsZero() && (e.when.IsZero() || e.when.Before(f.since)) {
		return false
	}
	if f.q != "" {
		blob := strings.Join([]string{e.SrcIP, e.Sensor, e.Detail, e.User, e.Pass,
			e.Command, e.Path, e.Alert, e.Session, e.Shasum, e.ClientVer, e.Fingerprint,
			e.FingerKind, e.Country, e.Org, e.Provider, e.Intel,
			e.Persona, e.Site, e.Asset, e.PersonaOrg}, " ")
		if !containsFold(blob, f.q) {
			return false
		}
	}
	return true
}

// describe renders the active filters as human-readable chips.
func (f filter) describe() []string {
	var out []string
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+" = "+v)
		}
	}
	add("ip", f.ip)
	add("network", f.cidr)
	add("port", f.port)
	add("sensor", f.sensor)
	add("proto", f.proto)
	add("path", f.path)
	add("persona", f.persona)
	add("site", f.site)
	add("asset", f.asset)
	add("credentials", f.cred)
	add("command", f.cmd)
	add("session", f.session)
	add("payload", shortHash(f.shasum))
	add("category", f.cat)
	add("country", f.country)
	add("client", f.client)
	add("fingerprint", f.fingerprint)
	add("provider", f.provider)
	add("organization", f.org)
	add("ASN", f.asn)
	add("signature", f.sig)
	add("type", f.typ)
	add("search", f.q)
	if f.sinceStr != "" {
		out = append(out, "last "+f.sinceStr)
	}
	return out
}

func (f filter) filtered(evs []storedEvent) []storedEvent {
	out := make([]storedEvent, 0, 64)
	for _, e := range evs {
		if f.match(e) {
			out = append(out, e)
		}
	}
	return out
}

// eventsPage is the data for the /events drill-down view.
type eventsPage struct {
	Generated time.Time
	Filters   []string
	Total     int
	Shown     int
	Offset    int
	From      int
	To        int
	Page      int
	Pages     int
	PerPage   int
	PrevURL   string
	NextURL   string
	RowsURL   string
	ReportURL string
	Chain     bool // single-IP view rendered chronologically as an attack chain
	IP        string
	Events    []storedEvent
}

type attackerPage struct {
	Generated    time.Time
	IP           string
	Country      string
	ASN          uint
	Org          string
	Provider     string
	First        string
	Last         string
	Total        int
	Sessions     int
	PayloadCount int
	Sensors      []kv
	Creds        []kv
	Commands     []kv
	Payloads     []kv
	Paths        []kv
	Alerts       []kv
	Events       []storedEvent
	Techniques   []attackTechnique
}

func (s *store) attackerData(ip string) (attackerPage, bool) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return attackerPage{}, false
	}
	p := attackerPage{Generated: time.Now(), IP: ip}
	sensors, creds, commands := map[string]int{}, map[string]int{}, map[string]int{}
	payloads, paths, alerts := map[string]int{}, map[string]int{}, map[string]int{}
	sessions := map[string]bool{}
	for _, event := range s.getEvents() {
		if event.SrcIP != ip {
			continue
		}
		p.Events = append(p.Events, event)
		p.Total++
		if p.Last == "" {
			p.Last, p.Country, p.ASN, p.Org = event.Time, event.Country, event.ASN, event.Org
			p.Provider = firstNonEmpty(event.Intel, event.Provider)
		}
		p.First = event.Time
		sensors[event.Sensor]++
		if event.Session != "" {
			sessions[event.Session] = true
		}
		if event.HasCredential {
			creds[event.User+" / "+event.Pass]++
		}
		if event.Command != "" {
			commands[event.Command]++
		}
		if event.Shasum != "" {
			payloads[event.Shasum]++
			p.PayloadCount++
		}
		if event.Path != "" {
			paths[event.Path]++
		}
		if event.Alert != "" {
			alerts[event.Alert]++
		}
	}
	if p.Total == 0 {
		return p, false
	}
	for i, j := 0, len(p.Events)-1; i < j; i, j = i+1, j-1 {
		p.Events[i], p.Events[j] = p.Events[j], p.Events[i]
	}
	if len(p.Events) > 250 {
		p.Events = p.Events[len(p.Events)-250:]
	}
	p.Sessions = len(sessions)
	p.Sensors, p.Creds, p.Commands = topN(sensors, 20), topN(creds, 15), topN(commands, 15)
	p.Payloads, p.Paths, p.Alerts = topN(payloads, 15), topN(paths, 15), topN(alerts, 15)
	p.Techniques = aggregateTechniques(p.Events)
	return p, true
}

// ipRow is one line of the /ips listing.
type ipRow struct {
	IP       string
	Country  string
	Count    int
	Logins   int
	Sensors  string
	Sessions int
	First    string
	Last     string
}

type ipsPage struct {
	Generated time.Time
	Rows      []ipRow
	Total     int
}

const defaultEventRows = 25

func (s *store) eventsData(r *http.Request) eventsPage {
	f := parseFilter(r)
	events := s.getEvents()
	total := 0
	for _, event := range events {
		if f.match(event) {
			total++
		}
	}
	chain := f.ip != ""
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 25 || perPage > 500 {
		perPage = defaultEventRows
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pages := max(1, (total+perPage-1)/perPage)
	if page > pages {
		page = pages
	}
	start := min(total, (page-1)*perPage)
	end := min(total, start+perPage)
	out := make([]storedEvent, 0, end-start)
	matched := 0
	appendWindow := func(event storedEvent) {
		if !f.match(event) {
			return
		}
		if matched >= start && matched < end {
			out = append(out, event)
		}
		matched++
	}
	if chain {
		// attack chain: oldest first, so the story reads top to bottom
		for i := len(events) - 1; i >= 0; i-- {
			appendWindow(events[i])
		}
	} else {
		for _, event := range events {
			appendWindow(event)
		}
	}
	pageURL := func(target int) string {
		q := r.URL.Query()
		q.Set("page", strconv.Itoa(target))
		q.Set("per_page", strconv.Itoa(perPage))
		return "/events?" + q.Encode()
	}
	prevURL, nextURL := "", ""
	if page > 1 {
		prevURL = pageURL(page - 1)
	}
	if page < pages {
		nextURL = pageURL(page + 1)
	}
	rowsQuery := r.URL.Query()
	rowsQuery.Del("page")
	rowsQuery.Del("per_page")
	rowsURL := "/api/event-rows"
	if encoded := rowsQuery.Encode(); encoded != "" {
		rowsURL += "?" + encoded
	}
	return eventsPage{
		Generated: time.Now(),
		Filters:   f.describe(),
		Total:     total,
		Shown:     len(out),
		Offset:    start,
		From:      start + boolInt(total > 0),
		To:        end,
		Page:      page,
		Pages:     pages,
		PerPage:   perPage,
		PrevURL:   prevURL,
		NextURL:   nextURL,
		RowsURL:   rowsURL,
		ReportURL: reportURL(r.URL.Query()),
		Chain:     chain,
		IP:        f.ip,
		Events:    out,
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *store) ipsData() ipsPage {
	s.ipsMu.Lock()
	defer s.ipsMu.Unlock()
	if !s.ipsCacheAt.IsZero() && time.Since(s.ipsCacheAt) < 30*time.Second {
		return s.ipsCache
	}
	s.ipsCache = s.buildIPsData()
	s.ipsCacheAt = time.Now()
	return s.ipsCache
}

func (s *store) buildIPsData() ipsPage {
	type agg struct {
		count, logins int
		country       string
		sensors       map[string]bool
		sessions      map[string]bool
		first, last   string
	}
	m := map[string]*agg{}
	// events are newest-first: the first time we see an IP is its most recent
	// event, the last time is its oldest.
	for _, e := range s.getEvents() {
		if e.SrcIP == "" {
			continue
		}
		a := m[e.SrcIP]
		if a == nil {
			a = &agg{sensors: map[string]bool{}, sessions: map[string]bool{}}
			m[e.SrcIP] = a
		}
		a.count++
		if e.IsLogin {
			a.logins++
		}
		if e.Country != "" {
			a.country = e.Country
		}
		a.sensors[e.Sensor] = true
		if e.Session != "" {
			a.sessions[e.Session] = true
		}
		if e.Time != "" {
			if a.last == "" {
				a.last = e.Time
			}
			a.first = e.Time
		}
	}
	rows := make([]ipRow, 0, len(m))
	for ip, a := range m {
		var sensors []string
		for s := range a.sensors {
			sensors = append(sensors, s)
		}
		sort.Strings(sensors)
		rows = append(rows, ipRow{
			IP: ip, Country: a.country, Count: a.count, Logins: a.logins,
			Sensors: strings.Join(sensors, " "), Sessions: len(a.sessions),
			First: a.first, Last: a.last,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].IP < rows[j].IP
	})
	return ipsPage{Generated: time.Now(), Rows: rows, Total: len(rows)}
}

// capturedFile is one unique artifact from any configured payload source.
type capturedFile struct {
	Hash         string
	Size         int64
	SizeH        string
	Mtime        string
	MIME         string
	Kind         string
	KindCode     string
	Platform     string
	AnalysisPath string
	Dynamic      bool
	Sources      []string
	Copies       int
}

type payloadSourceStat struct {
	Name   string
	Count  int
	Link   string
	Active bool
}

type payloadsPage struct {
	Generated   time.Time
	Enabled     bool
	Loading     bool
	Files       []capturedFile
	Sources     []payloadSourceStat
	Filter      string
	ResultTotal int
	UniqueTotal int
	TotalH      string
	Notice      string
}

func payloadSourceName(dir string) string {
	lower := strings.ToLower(filepath.ToSlash(dir))
	switch {
	case strings.Contains(lower, "dionaea"):
		return "dionaea"
	case strings.Contains(lower, "cowrie"):
		return "cowrie"
	case strings.Contains(lower, "script"):
		return "scripts"
	default:
		name := strings.TrimSpace(filepath.Base(filepath.Clean(dir)))
		if name == "" || name == "." || name == string(filepath.Separator) {
			return "payloads"
		}
		return name
	}
}

// payloadsData inventories all configured capture directories recursively,
// merges identical hash-addressed artifacts, and preserves every contributing
// source. Dionaea binaries, Cowrie transfers, and retained inline scripts are
// therefore visible in one page instead of being presented as Dionaea-only.
func (s *store) payloadsData(filter string) payloadsPage {
	filter = strings.ToLower(strings.TrimSpace(filter))
	s.refreshPayloadCacheAsync()
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	base := s.payloadCache
	p := payloadsPage{
		Generated: time.Now(), Enabled: len(s.payloadDirs) != 0,
		Loading: s.payloadCacheAt.IsZero() && s.payloadRefreshing,
		Filter:  filter, UniqueTotal: base.UniqueTotal,
		Sources: append([]payloadSourceStat(nil), base.Sources...),
	}
	for i := range p.Sources {
		p.Sources[i].Active = p.Sources[i].Name == filter
	}
	var total int64
	for _, file := range base.Files {
		if filter != "" {
			matched := false
			for _, source := range file.Sources {
				if source == filter {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		p.Files = append(p.Files, file)
		total += file.Size
	}
	p.ResultTotal = len(p.Files)
	p.TotalH = humanBytes(total)
	return p
}

const payloadCacheTTL = 2 * time.Minute

// refreshPayloadCacheAsync keeps slow volume walks off the HTTP request path.
// Existing inventory remains available while a refresh is running.
func (s *store) refreshPayloadCacheAsync() {
	s.payloadMu.Lock()
	if s.payloadRefreshing || (!s.payloadCacheAt.IsZero() && time.Since(s.payloadCacheAt) < payloadCacheTTL) {
		s.payloadMu.Unlock()
		return
	}
	s.payloadRefreshing = true
	s.payloadMu.Unlock()
	go func() {
		fresh := s.scanPayloads()
		s.payloadMu.Lock()
		s.payloadCache = fresh
		s.payloadCacheAt = time.Now()
		s.payloadRefreshing = false
		s.payloadMu.Unlock()
	}()
}

func (s *store) payloadInventoryLoop() {
	s.refreshPayloadCacheAsync()
	ticker := time.NewTicker(payloadCacheTTL)
	defer ticker.Stop()
	for range ticker.C {
		s.refreshPayloadCacheAsync()
	}
}

func (s *store) scanPayloads() payloadsPage {
	p := payloadsPage{Generated: time.Now(), Enabled: len(s.payloadDirs) != 0}
	if len(s.payloadDirs) == 0 {
		return p
	}
	files := map[string]*capturedFile{}
	sourceSets := map[string]map[string]bool{}
	sourceCounts := map[string]int{}
	for _, dir := range s.payloadDirs {
		source := payloadSourceName(dir)
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() || !hashName.MatchString(d.Name()) {
				return nil
			}
			fi, err := d.Info()
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			hash := strings.ToLower(d.Name())
			if sourceSets[hash] == nil {
				sourceSets[hash] = map[string]bool{}
			}
			if !sourceSets[hash][source] {
				sourceSets[hash][source] = true
				sourceCounts[source]++
			}
			if existing := files[hash]; existing != nil {
				existing.Copies++
				if modified := fi.ModTime().Format("2006-01-02 15:04"); modified > existing.Mtime {
					existing.Mtime = modified
				}
				return nil
			}
			mime := "application/octet-stream"
			classification := classifyPayload(nil)
			if f, err := os.Open(path); err == nil {
				head := make([]byte, 64<<10)
				n, _ := f.Read(head)
				f.Close()
				head = head[:n]
				mime = http.DetectContentType(head)
				classification = classifyPayload(head)
			}
			files[hash] = &capturedFile{
				Hash: hash, Size: fi.Size(), SizeH: humanBytes(fi.Size()),
				Mtime: fi.ModTime().Format("2006-01-02 15:04"), MIME: mime,
				Kind: classification.Label, KindCode: classification.Code,
				Platform: classification.Platform, AnalysisPath: classification.AnalysisPath,
				Dynamic: classification.Dynamic, Copies: 1,
			}
			return nil
		})
	}
	var total int64
	for hash, file := range files {
		for source := range sourceSets[hash] {
			file.Sources = append(file.Sources, source)
		}
		sort.Strings(file.Sources)
		p.UniqueTotal++
		total += file.Size
		p.Files = append(p.Files, *file)
	}
	for source, count := range sourceCounts {
		p.Sources = append(p.Sources, payloadSourceStat{
			Name: source, Count: count, Link: "/payloads?source=" + url.QueryEscape(source),
		})
	}
	sort.Slice(p.Sources, func(i, j int) bool { return p.Sources[i].Name < p.Sources[j].Name })
	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].Mtime > p.Files[j].Mtime })
	p.TotalH = humanBytes(total)
	return p
}

// servePayload streams one captured binary as a download. The hash is validated
// against hashName so the path can never escape binDir.
func (s *store) servePayload(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if len(s.payloadDirs) == 0 {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/payload/")
	if !hashName.MatchString(name) {
		http.Error(w, "invalid payload id", http.StatusBadRequest)
		return
	}
	path, err := s.payloadPath(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	// Force a download of an inert blob — never let a browser sniff/run it.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.malware.bin"`)
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
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

	s := &store{dir: getenv("LOG_DIR", "/logs"), yaraFile: os.Getenv("YARA_RESULTS_FILE")}
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
		s.es.refresh()
		go func() {
			for range time.Tick(time.Minute) {
				s.es.refresh()
			}
		}()
	}
	cooldown, err := time.ParseDuration(getenv("ALERT_COOLDOWN", "6h"))
	if err != nil || cooldown < 5*time.Minute {
		cooldown = 6 * time.Hour
	}
	s.alerts = newAlertManager(getenv("ALERT_STATE_FILE", "/state/alerts.json"), cooldown)
	s.intelligence = &intelligenceStore{path: getenv("INTELLIGENCE_STATE_FILE", "/state/intelligence.json")}
	s.rebuild()
	go s.notifyLoop(os.Getenv("ALERT_WEBHOOK_URL"))
	go func() {
		for range time.Tick(15 * time.Second) {
			s.rebuild()
		}
	}()

	// `dict` lets the template pass named args into the reusable "tbl" block.
	funcs := template.FuncMap{
		"worldMap": func() template.HTML { return template.HTML(worldMapSVG) },
		"json": func(value any) string {
			b, _ := json.MarshalIndent(value, "", "  ")
			return string(b)
		},
		"dict": func(pairs ...any) map[string]any {
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i+1 < len(pairs); i += 2 {
				key, _ := pairs[i].(string)
				m[key] = pairs[i+1]
			}
			return m
		},
	}
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
	http.HandleFunc("/api/map-points", s.serveMapPoints)
	http.HandleFunc("/api/stream", s.serveEventsSSE)
	http.HandleFunc("/api/alerts", s.serveAlertsAPI)
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
		data := s.ipsData()
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
		s.es.deadLetters(w, r)
	})
	http.HandleFunc("/api/sandbox", serveSandboxAPI)
	http.HandleFunc("/api/sandbox/", serveSandboxAPI)
	http.HandleFunc("/export/sandbox/", serveSandboxExport)
	http.HandleFunc("/metrics", s.serveMetrics)
	http.HandleFunc("/export/history.json", func(w http.ResponseWriter, r *http.Request) {
		if s.es == nil {
			http.Error(w, "Elasticsearch integration disabled", http.StatusServiceUnavailable)
			return
		}
		s.es.history(w, r, true)
	})
	http.HandleFunc("/export/report.pdf", s.servePDFReport)
	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		tmpl.ExecuteTemplate(w, "events", s.eventsData(r))
	})
	http.HandleFunc("/ips", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		data := s.ipsData()
		if len(data.Rows) > 25 {
			data.Rows = data.Rows[:25]
		}
		tmpl.ExecuteTemplate(w, "ips", data)
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
		html(w)
		tmpl.ExecuteTemplate(w, "attacker", data)
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
		html(w)
		tmpl.ExecuteTemplate(w, "session", data)
	})
	http.HandleFunc("/clusters", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		tmpl.ExecuteTemplate(w, "clusters", s.clustersData())
	})
	http.HandleFunc("/campaigns", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		tmpl.ExecuteTemplate(w, "campaigns", s.get())
	})
	http.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		tmpl.ExecuteTemplate(w, "history", s.get())
	})
	http.HandleFunc("/dead-letters", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		tmpl.ExecuteTemplate(w, "dead-letters", s.get())
	})
	http.HandleFunc("/source-health", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		tmpl.ExecuteTemplate(w, "source-health", s.get())
	})
	http.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		tmpl.ExecuteTemplate(w, "alerts", s.get())
	})
	http.HandleFunc("/payloads", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		data := s.payloadsData(r.URL.Query().Get("source"))
		if r.URL.Query().Get("analysis") == "queued" && hashName.MatchString(r.URL.Query().Get("hash")) {
			data.Notice = "Sandbox analysis requested for " + shortHash(r.URL.Query().Get("hash")) + ". The isolated worker will process it shortly."
		}
		if len(data.Files) > 25 {
			data.Files = data.Files[:25]
		}
		tmpl.ExecuteTemplate(w, "payloads", data)
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
	http.HandleFunc("/sandbox", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		data, _ := sandboxData("", r.URL.Query().Get("q"))
		tmpl.ExecuteTemplate(w, "sandbox", data)
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
		html(w)
		tmpl.ExecuteTemplate(w, "sandbox", data)
	})
	http.HandleFunc("/commands", func(w http.ResponseWriter, r *http.Request) {
		html(w)
		tmpl.ExecuteTemplate(w, "commands", s.commandsData())
	})
	http.HandleFunc("/payload-analysis/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/payload-analysis/")
		analysis, err := s.analyzePayload(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		html(w)
		tmpl.ExecuteTemplate(w, "payload-analysis", analysis)
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
		html(w)
		tmpl.ExecuteTemplate(w, "page", s.get())
	})

	srv := &http.Server{
		Addr:              getenv("LISTEN_ADDR", ":8080"),
		ReadHeaderTimeout: 5 * time.Second,
	}
	srv.ListenAndServe()
}
