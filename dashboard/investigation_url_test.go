package main

import (
	"testing"
	"time"
)

func TestEveBoxInvestigationURL(t *testing.T) {
	got := investigationURL("https://evebox.hp.example.org/", "evebox", "203.0.113.42", time.Time{})
	want := "https://evebox.hp.example.org/#/inbox?q=203.0.113.42"
	if got != want {
		t.Fatalf("investigationURL() = %q, want %q", got, want)
	}
}

// The Open-in menu used to be built from three independent variables whose
// Compose defaults pointed at honeypot.example, so an operator who configured
// everything .env.example documented still got placeholder links (#97). One
// domain now drives all three, and an explicit URL still wins for deployments
// that route the tools under a path instead of a subdomain.
func TestInvestigationBaseResolution(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		kind string
		want string
	}{
		{"derived from the domain", map[string]string{"HONEYPOT_DOMAIN": "example.org"}, "kibana", "https://kibana.example.org"},
		{"an explicit URL wins", map[string]string{
			"HONEYPOT_DOMAIN": "example.org", "EVEBOX_PUBLIC_URL": "https://hp.example.org/evebox",
		}, "evebox", "https://hp.example.org/evebox"},
		{"a trailing dot on the domain is tolerated", map[string]string{"HONEYPOT_DOMAIN": "example.org."}, "arkime", "https://arkime.example.org"},
		{"whitespace is not a configured value", map[string]string{"HONEYPOT_DOMAIN": "  "}, "kibana", ""},
		{"nothing configured yields no link", nil, "kibana", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{"HONEYPOT_DOMAIN", "KIBANA_PUBLIC_URL", "EVEBOX_PUBLIC_URL", "ARKIME_PUBLIC_URL"} {
				t.Setenv(key, tc.env[key])
			}
			if got := investigationBase(tc.kind); got != tc.want {
				t.Fatalf("investigationBase(%q) = %q, want %q", tc.kind, got, tc.want)
			}
		})
	}
}

// A link nobody can follow is a nuisance; a link to a domain we do not own is
// a disclosure, because the IP under investigation travels in the URL. The
// reserved .example TLD can only be left over from the shipped placeholder, so
// it must render as no link at all rather than as a working one.
func TestPlaceholderHostsProduceNoLink(t *testing.T) {
	for _, base := range []string{
		"https://kibana.honeypot.example",
		"https://evebox.honeypot.example/",
		"https://arkime.example",
		"://not a url",
	} {
		if got := investigationURL(base, "kibana", "203.0.113.42", time.Now()); got != "" {
			t.Fatalf("investigationURL(%q) = %q, want no link", base, got)
		}
	}
}
