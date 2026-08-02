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
