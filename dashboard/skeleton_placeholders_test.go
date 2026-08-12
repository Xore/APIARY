package main

import (
	"html/template"
	"strings"
	"testing"
	"time"
)

// #1155: Events/IPs/Campaigns/Clusters all read from rebuild()'s own
// s.getEvents() cache, the same one overview's snapshot reads -- so they
// share overview's exact cold-start gap (#1142) before the first
// rebuild() cycle finishes. Confirmed live that the other four pages
// originally proposed for this issue (ML anomalies/LLM analysis/Agent
// campaigns/Auth-failure events) do NOT have this gap: their own refresh
// calls run synchronously in main() before the HTTP listener starts, so
// unlike rebuild() (deliberately backgrounded by #353) there is no window
// where a request reaches them before their cache is populated -- see the
// comment left on #1155 itself. Not covered here for that reason.
func TestListingPagesShowSkeletonPlaceholdersBeforeFirstRebuildInsteadOfEmptyStates(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	render := func(name string, data any) string {
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, name, data); err != nil {
			t.Fatalf("%s page does not execute: %v", name, err)
		}
		return out.String()
	}

	cases := []struct {
		name          string
		emptyData     any
		readyData     any
		realEmptyText string
	}{
		{
			name:          "events",
			emptyData:     &eventsPage{Ready: false},
			readyData:     &eventsPage{Ready: true},
			realEmptyText: "no events match this filter",
		},
		{
			name:          "ips",
			emptyData:     &ipsPage{Ready: false},
			readyData:     &ipsPage{Ready: true},
			realEmptyText: "no source IPs recorded yet",
		},
		{
			name:          "campaigns",
			emptyData:     &campaignsPage{Ready: false},
			readyData:     &campaignsPage{Ready: true},
			realEmptyText: "no active campaigns in the last seven days",
		},
		{
			name:          "clusters",
			emptyData:     &clustersPage{Ready: false},
			readyData:     &clustersPage{Ready: true},
			realEmptyText: "No multi-source pivots are present",
		},
		// githubanalysisresultspanel (#1156-follow-up) gates on Loading, not
		// Ready -- it reads from its own background-refreshed cache
		// (s.githubAnalysisCache), not rebuild()'s s.getEvents(), so its
		// cold-start signal is genuinely different (see github_analysis.go's
		// own refreshGithubAnalysisCacheAsync comment) -- but the render
		// harness itself only cares that "no rows yet" renders a skeleton
		// vs. the real empty state, which is exactly what this shares with
		// the other four cases.
		{
			name:          "githubanalysisresultspanel",
			emptyData:     &githubAnalysisPageData{Loading: true},
			readyData:     &githubAnalysisPageData{Loading: false},
			realEmptyText: "No GitHub analyses match this view.",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			warming := render(c.name, c.emptyData)
			if !strings.Contains(warming, "skeleton") {
				t.Fatalf("%s: Ready=false with no rows must render a skeleton placeholder", c.name)
			}
			if strings.Contains(warming, c.realEmptyText) {
				t.Fatalf("%s: Ready=false must not show the real empty-state text %q -- that claims a genuinely empty result, not a still-warming dashboard", c.name, c.realEmptyText)
			}

			quiet := render(c.name, c.readyData)
			if strings.Contains(quiet, "skeleton") {
				t.Fatalf("%s: Ready=true with no rows is a genuinely empty result, not a loading state -- must not show a skeleton placeholder", c.name)
			}
			if !strings.Contains(quiet, c.realEmptyText) {
				t.Fatalf("%s: Ready=true with no rows must still show its real empty state %q", c.name, c.realEmptyText)
			}
		})
	}
}

// Real data must always win over both the skeleton and the empty state,
// regardless of Ready -- a card with content is never "still loading".
func TestListingPagesNeverMaskRealDataRegardlessOfReady(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	render := func(name string, data any) string {
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, name, data); err != nil {
			t.Fatalf("%s page does not execute: %v", name, err)
		}
		return out.String()
	}

	ips := render("ips", &ipsPage{Ready: false, Rows: []ipRow{{IP: "203.0.113.9", Count: 3}}})
	if !strings.Contains(ips, "203.0.113.9") {
		t.Fatal("real IP data must render even while Ready=false, not be masked by the skeleton")
	}

	clusters := render("clusters", &clustersPage{Ready: false, Rows: []clusterRow{{Kind: "Payload", Value: "abc123", Link: "/x"}}})
	if !strings.Contains(clusters, "abc123") {
		t.Fatal("real cluster data must render even while Ready=false, not be masked by the skeleton")
	}

	campaigns := render("campaigns", &campaignsPage{Ready: false, Campaigns: []campaignRow{{CIDR: "203.0.113.0/24", Score: 90}}})
	if !strings.Contains(campaigns, "203.0.113.0/24") {
		t.Fatal("real campaign data must render even while Ready=false, not be masked by the skeleton")
	}

	events := render("events", &eventsPage{Ready: false, Events: []storedEvent{{Sensor: "cowrie", SrcIP: "203.0.113.9", when: time.Now()}}})
	if !strings.Contains(events, "203.0.113.9") {
		t.Fatal("real event data must render even while Ready=false, not be masked by the skeleton")
	}
}
