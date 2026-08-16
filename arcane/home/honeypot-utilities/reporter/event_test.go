package main

import (
	"encoding/json"
	"testing"
)

func TestParseEventFindsIPAcrossFieldNames(t *testing.T) {
	cases := []struct {
		name string
		line string
		ip   string
	}{
		{"src_ip", `{"src_ip":"203.0.113.7","eventid":"cowrie.login.failed"}`, "203.0.113.7"},
		{"remote_ip", `{"remote_ip":"203.0.113.8"}`, "203.0.113.8"},
		{"conpot remote array", `{"remote":["203.0.113.9",5060]}`, "203.0.113.9"},
		{"no ip at all", `{"message":"startup"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := parseEvent("test", []byte(c.line))
			if c.ip == "" {
				if ok {
					t.Fatalf("expected no event, got %+v", ev)
				}
				return
			}
			if !ok || ev.IP != c.ip {
				t.Fatalf("got ip=%q ok=%v, want %q", ev.IP, ok, c.ip)
			}
		})
	}
}

func TestParseEventRejectsGarbageJSON(t *testing.T) {
	if _, ok := parseEvent("test", []byte("not json")); ok {
		t.Fatal("malformed JSON should not produce an event")
	}
}

func TestKindOfClassification(t *testing.T) {
	cases := []struct {
		line string
		kind string
	}{
		{`{"eventid":"cowrie.login.failed","username":"root"}`, "login"},
		{`{"eventid":"cowrie.command.input"}`, "command"},
		{`{"eventid":"cowrie.session.file_download","shasum":"abc"}`, "download"},
		{`{"path":"/wp-login.php"}`, "scan"},
		{`{"message":"nothing recognizable"}`, ""},
	}
	for _, c := range cases {
		var raw map[string]any
		if err := json.Unmarshal([]byte(c.line), &raw); err != nil {
			t.Fatal(err)
		}
		if got := kindOf(raw); got != c.kind {
			t.Errorf("kindOf(%s) = %q, want %q", c.line, got, c.kind)
		}
	}
}

// TestParseSuricataEventOnlyReportsAlerts (#69) uses the exact real eve.json
// line shapes captured live on this deployment: an "alert" event (real
// signature, category, and src_ip -- an ET SCAN hit), and a non-alert event
// (a flow record, the same shape the dominant volume of eve.json actually
// is on this host). Only the alert is reportable; the flow record must be
// silently skipped, not logged as a "skipped: uncategorized" audit entry --
// eve.json's http/dns/tls/flow/fileinfo/stats records outnumber alerts by
// orders of magnitude here, and auditing every one of them as "skipped"
// would swamp the log with noise for a record type that was never
// reportable in the first place.
func TestParseSuricataEventOnlyReportsAlerts(t *testing.T) {
	alertLine := `{"timestamp":"2026-07-31T20:59:06.297282+0200","event_type":"alert","src_ip":"185.220.101.5","dest_ip":"203.0.113.50","dest_port":5432,"alert":{"action":"allowed","gid":1,"signature_id":2010939,"rev":3,"signature":"ET SCAN Suspicious inbound to PostgreSQL port 5432","category":"Potentially Bad Traffic","severity":2}}`
	ev, ok := parseEvent("suricata", []byte(alertLine))
	if !ok {
		t.Fatal("a real alert event with src_ip must produce an event")
	}
	if ev.IP != "185.220.101.5" {
		t.Fatalf("ip = %q, want 185.220.101.5", ev.IP)
	}
	if ev.Kind != "Potentially Bad Traffic" {
		t.Fatalf("kind = %q, want the alert's own category text", ev.Kind)
	}

	flowLine := `{"timestamp":"2026-07-31T20:59:06.297282+0200","event_type":"flow","src_ip":"185.220.101.5","dest_ip":"203.0.113.50","flow":{"pkts_toserver":3,"pkts_toclient":2,"bytes_toserver":180,"bytes_toclient":120,"state":"established"}}`
	if _, ok := parseEvent("suricata", []byte(flowLine)); ok {
		t.Fatal("a non-alert eve.json record (flow, dns, http, tls, ...) must not produce an event")
	}
}

// TestParseSuricataEventTimestamp confirms timeOf actually parses eve.json's
// real timestamp shape -- a colon-less numeric zone offset ("+0200"), which
// none of the pre-existing layouts (RFC3339, RFC3339Nano, the plain
// space-separated form) accept. Verified directly: before this layout was
// added, every Suricata event's When silently fell back to time.Now()
// instead of the event's own real time.
func TestParseSuricataEventTimestamp(t *testing.T) {
	line := `{"timestamp":"2026-07-31T20:59:06.297282+0200","event_type":"alert","src_ip":"185.220.101.5","alert":{"category":"Misc Attack"}}`
	ev, ok := parseEvent("suricata", []byte(line))
	if !ok {
		t.Fatal("expected a parsed event")
	}
	if ev.When.Year() != 2026 || ev.When.Month() != 7 || ev.When.Day() != 31 {
		t.Fatalf("timestamp did not parse, got %v (likely fell back to time.Now())", ev.When)
	}
}

// TestSuricataCategoriesMapping (#69) checks both directions this switch
// has to get right: a real attack-classification category maps to a real
// AbuseIPDB code, and Suricata's own decoder-health noise -- confirmed the
// dominant alert category on this deployment's real eve.json, not a
// hypothetical edge case -- maps to nil rather than being reported as if it
// were attacker behavior.
func TestSuricataCategoriesMapping(t *testing.T) {
	for _, category := range []string{
		"Potentially Bad Traffic", "Attempted Administrator Privilege Gain", "Misc Attack",
	} {
		if cats := suricataCategories(category); len(cats) == 0 {
			t.Errorf("suricataCategories(%q) = nil, want at least one AbuseIPDB category", category)
		}
	}
	for _, category := range []string{
		"Generic Protocol Command Decode", "Not Suspicious Traffic", "", "some unrecognized future category",
	} {
		if cats := suricataCategories(category); cats != nil {
			t.Errorf("suricataCategories(%q) = %v, want nil", category, cats)
		}
	}
}

func TestCategoriesConservativeByDefault(t *testing.T) {
	if cats := categories("unknown-sensor", "login"); cats != nil {
		t.Fatalf("an unrecognized sensor should map to no categories, got %v", cats)
	}
	if cats := categories("cowrie", "login"); len(cats) == 0 {
		t.Fatal("cowrie login should map to at least one category")
	}
	// Found during #68's dry-run review: a real http-honeypot "login" event
	// (a fake web login form credential attempt) was falling through to nil
	// -- categorize.go had a case for http-honeypot "scan" but not "login".
	if cats := categories("http-honeypot", "login"); len(cats) == 0 {
		t.Fatal("http-honeypot login should map to at least one category")
	}
}
