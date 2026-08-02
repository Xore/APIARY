package main

import "testing"

// TestBlocklistDeServiceMapping (#69) checks both directions: cowrie's
// unambiguous SSH fit maps through, and everything else -- including
// sensors that ARE reportable to AbuseIPDB -- maps to "" because
// Blocklist.de's protocol/daemon-specific vocabulary can't honestly
// represent them (see blocklistDeService's doc comment for why each one is
// excluded).
func TestBlocklistDeServiceMapping(t *testing.T) {
	cases := []struct {
		sensor, kind, want string
	}{
		{"cowrie", "login", "ssh"},
		{"cowrie", "command", "ssh"},
		{"cowrie", "download", ""},
		{"dionaea", "download", ""},
		{"http-honeypot", "login", ""},
		{"http-honeypot", "scan", ""},
		{"multipot", "", ""},
		{"conpot", "", ""},
		{"suricata", "Potentially Bad Traffic", ""},
		{"unknown-sensor", "login", ""},
	}
	for _, c := range cases {
		if got := blocklistDeService(c.sensor, c.kind); got != c.want {
			t.Errorf("blocklistDeService(%q, %q) = %q, want %q", c.sensor, c.kind, got, c.want)
		}
	}
}
