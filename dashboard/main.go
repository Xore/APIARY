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
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// hashName matches a dionaea capture filename: a bare md5/sha1/sha256 hex hash.
// Enforced on the download path so a request can never escape the binaries dir.
var hashName = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)

var processStarted = time.Now()

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

// tunnelPeerIP is the WireGuard peer address cowrie logs for every session:
// portbridge terminates the attacker's TCP on the VPS and re-dials over the
// tunnel, and cowrie's haproxy endpoint is disabled (Twisted incompat), so the
// only real-IP source for cowrie is the portbridge conn-log (see buildViaMap).
const tunnelPeerIP = "10.8.0.1"

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
	// Forward-auth identity for the sidebar profile row (headers only, no secrets).
	http.HandleFunc("/api/whoami", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{
			"user": r.Header.Get("X-Auth-User"),
			"role": r.Header.Get("X-Auth-Role"),
		})
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
