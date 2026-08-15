package main

import (
	"html/template"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestClusterIPsMatchesClustersDataGrouping (#354): clusterIPs must find
// exactly the same member IPs clustersData's own row would report a count
// for -- it re-implements the same kind/value grouping deliberately (not
// shared code) but the two must never disagree about who belongs to a
// cluster.
func TestClusterIPsMatchesClustersDataGrouping(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "8.8.8.8", Sensor: "cowrie", Fingerprint: "shared-hassh"},
		{SrcIP: "8.8.4.4", Sensor: "cowrie", Fingerprint: "shared-hassh"},
		{SrcIP: "9.9.9.9", Sensor: "dionaea", Shasum: "deadbeef"},
		{SrcIP: "1.1.1.1", Sensor: "cowrie", ASN: 15169, Org: "Google"},
		{SrcIP: "2.2.2.2", Sensor: "cowrie", ASN: 15169, Org: "Google"},
	}}
	page := s.clustersData(filter{})

	for _, row := range page.Rows {
		ips := s.clusterIPs(row.Kind, row.Value)
		if len(ips) != row.Sources {
			t.Errorf("clusterIPs(%q, %q) = %d IPs, clustersData row reports Sources=%d", row.Kind, row.Value, len(ips), row.Sources)
		}
	}

	fingerprintIPs := s.clusterIPs("Fingerprint", "shared-hassh")
	if len(fingerprintIPs) != 2 {
		t.Fatalf("expected 2 IPs for the shared fingerprint, got %v", fingerprintIPs)
	}
	asnIPs := s.clusterIPs("Autonomous system", "AS15169 Google")
	if len(asnIPs) != 2 {
		t.Fatalf("expected 2 IPs for the shared ASN, got %v", asnIPs)
	}
	// A value with only one contributing IP is not a cluster at all --
	// clusterIPs itself doesn't enforce that threshold (clusterCorrelationData
	// does), but it must still report accurately.
	if ips := s.clusterIPs("Payload", "deadbeef"); len(ips) != 1 {
		t.Fatalf("expected 1 IP for the single-source payload, got %v", ips)
	}
}

// TestClusterCorrelationDataRequiresAtLeastTwoMembersAndAvailableES (#354):
// mirrors cidrCorrelationData's own two preconditions -- fewer than two
// member IPs isn't a cluster to correlate, and an unconfigured/failing
// Elasticsearch must report not-found rather than an empty shell page.
func TestClusterCorrelationDataRequiresAtLeastTwoMembersAndAvailableES(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "8.8.8.8", Sensor: "cowrie", Fingerprint: "solo"},
	}}
	if _, ok := s.clusterCorrelationData("Fingerprint", "solo"); ok {
		t.Fatal("a single-IP value must not be treated as a correlatable cluster")
	}

	s.events = append(s.events, storedEvent{SrcIP: "9.9.9.9", Sensor: "dionaea", Fingerprint: "solo"})
	if _, ok := s.clusterCorrelationData("Fingerprint", "solo"); ok {
		t.Fatal("expected not-found when Elasticsearch is unconfigured (s.es == nil)")
	}

	var gotPath string
	es := httptest.NewServer(correlationSearchStub(t, &gotPath, sampleCorrelationResponse))
	defer es.Close()
	s.es = newESClient(es.URL, "")

	page, ok := s.clusterCorrelationData("Fingerprint", "solo")
	if !ok {
		t.Fatal("expected success once two IPs share the value and Elasticsearch is configured")
	}
	if page.IPCount != 2 || page.Kind != "Fingerprint" || page.Value != "solo" {
		t.Fatalf("unexpected page: %+v", page)
	}
	if !strings.Contains(gotPath, url.QueryEscape("source.ip:(")) {
		t.Fatalf("query did not use a terms-style IP match: %s", gotPath)
	}
}

// TestClusterCorrelationPageRenders (#354) proves the clusters drill-down
// shell renders the cluster identity immediately and the independently
// hydrated fragment renders the records.
func TestClusterCorrelationPageRenders(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	data := clusterCorrelationPage{
		Kind: "Fingerprint", Value: "shared-hassh", IPCount: 2,
		Correlation: ipCorrelation{
			Available: true, Total: 2,
			Records: []correlatedRecord{{Sensor: "cowrie", Summary: "cowrie.login.success"}},
		},
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "cluster-correlation", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "shared-hassh") {
		t.Fatal("page does not render the cluster value")
	}
	if strings.Contains(body, "cowrie.login.success") || !strings.Contains(body, "data-hp-correlation-fragment-url") {
		t.Fatal("initial page must render the correlation shell without embedding backend records")
	}
	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "cluster-correlation-body", &data); err != nil {
		t.Fatalf("render fragment: %v", err)
	}
	if !strings.Contains(buf.String(), "cowrie.login.success") {
		t.Fatal("correlation fragment does not render a correlated record")
	}
}
