package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func seedCampaignDoc(t *testing.T, es *esClient, doc campaignWorkerDoc) {
	t.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.docIndex(campaignsIndex, doc.CIDR, body, true, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func seedClusterDoc(t *testing.T, es *esClient, id string, doc clusterWorkerDoc) {
	t.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.docIndex(clustersIndex, id, body, true, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestReadCampaignsFromWorkerIndexMapsFields(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	seedCampaignDoc(t, es, campaignWorkerDoc{
		CIDR: "203.0.113.0/24", Score: 66, Events: 5, UniqueIPs: 2,
		Sensors: []string{"cowrie", "dionaea"}, Ports: []string{"22"}, Creds: 1, Payloads: 1,
		Providers: []string{"cloud"}, Fingerprints: 1,
		First: "2026-08-05T00:00:00Z", Last: "2026-08-11T00:00:00Z",
		Explanation: "cross-sensor activity (2)",
	})

	s := &store{es: es}
	rows, ok := s.readCampaignsFromWorkerIndex()
	if !ok || len(rows) != 1 {
		t.Fatalf("ok=%v rows=%+v", ok, rows)
	}
	r := rows[0]
	if r.CIDR != "203.0.113.0/24" || r.Score != 66 || r.Events != 5 || r.UniqueIPs != 2 {
		t.Fatalf("got %+v", r)
	}
	if r.Sensors != "cowrie dionaea" || r.Providers != "cloud" {
		t.Fatalf("expected space-joined sensors/providers, got %+v", r)
	}
	if r.Link != "/events?cidr=203.0.113.0%2F24&since=168h" {
		t.Fatalf("link = %q", r.Link)
	}
	// Known gaps (see readCampaignsFromWorkerIndex's own doc comment):
	// correlator-worker's campaign aggregation never grouped by ASN, and an
	// aggregation bucket has no per-event ordering to derive Sequence from.
	if r.ASNs != "" || r.Sequence != "" {
		t.Fatalf("expected ASNs/Sequence to be empty (known gap), got %+v", r)
	}
}

func TestReadCampaignsFromWorkerIndexNoESConfigured(t *testing.T) {
	s := &store{}
	_, ok := s.readCampaignsFromWorkerIndex()
	if ok {
		t.Fatal("expected ok=false with no ES client configured")
	}
}

func TestCampaignsDataPrefersWorkerIndexOverStaleSnapshot(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")
	seedCampaignDoc(t, es, campaignWorkerDoc{CIDR: "203.0.113.0/24", Score: 10, Events: 3, UniqueIPs: 1})

	s := &store{es: es}
	s.snap.Campaigns = []campaignRow{{CIDR: "198.51.100.0/24", Events: 999, UniqueIPs: 42}}

	got := s.campaignsData(httptest.NewRequest("GET", "/campaigns", nil))
	if len(got.Campaigns) != 1 || got.Campaigns[0].CIDR != "203.0.113.0/24" {
		t.Fatalf("expected the worker index to win over the stale local snapshot, got %+v", got.Campaigns)
	}
}

func TestCampaignsDataFallsBackToSnapshotWhenWorkerIndexEmpty(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	s := &store{es: es}
	s.snap.Campaigns = []campaignRow{{CIDR: "198.51.100.0/24", Events: 999, UniqueIPs: 42}}

	got := s.campaignsData(httptest.NewRequest("GET", "/campaigns", nil))
	if len(got.Campaigns) != 1 || got.Campaigns[0].CIDR != "198.51.100.0/24" {
		t.Fatalf("expected a fallback to the local snapshot when campaigns-v1 has no docs yet, got %+v", got.Campaigns)
	}
}

func TestReadClustersFromWorkerIndexMapsKindLabelsAndLinks(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	seedClusterDoc(t, es, "fp1", clusterWorkerDoc{Kind: "fingerprint", Value: "shared-fp", Events: 10, Sources: 3, Sensors: []string{"cowrie"}})
	seedClusterDoc(t, es, "asn1", clusterWorkerDoc{Kind: "asn", Value: "AS64512 Example ISP", Events: 4, Sources: 2, Sensors: []string{"dionaea"}})

	s := &store{es: es}
	rows, ok := s.readClustersFromWorkerIndex()
	if !ok || len(rows) != 2 {
		t.Fatalf("ok=%v rows=%+v", ok, rows)
	}
	var fp, asn *clusterRow
	for i := range rows {
		switch rows[i].Kind {
		case "Fingerprint":
			fp = &rows[i]
		case "Autonomous system":
			asn = &rows[i]
		}
	}
	if fp == nil || fp.Value != "shared-fp" || fp.Sources != 3 {
		t.Fatalf("fingerprint row = %+v", fp)
	}
	if fp.Link != "/events?fingerprint=shared-fp" {
		t.Fatalf("fingerprint link = %q", fp.Link)
	}
	if asn == nil || asn.Value != "AS64512 Example ISP" {
		t.Fatalf("asn row = %+v", asn)
	}
	if asn.Link != "/events?asn=64512" {
		t.Fatalf("expected the AS prefix stripped for the link, got %q", asn.Link)
	}
}

func TestClustersDataDefaultViewPrefersWorkerIndex(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")
	seedClusterDoc(t, es, "fp1", clusterWorkerDoc{Kind: "fingerprint", Value: "from-worker", Events: 5, Sources: 2, Sensors: []string{"cowrie"}})

	s := &store{es: es, events: []storedEvent{
		{when: time.Now(), SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "from-live-recompute"},
		{when: time.Now(), SrcIP: "198.51.100.1", Sensor: "cowrie", Fingerprint: "from-live-recompute"},
	}}

	got := s.clustersData(clustersRequestFilter(httptest.NewRequest("GET", "/clusters", nil)))
	if len(got.Rows) != 1 || got.Rows[0].Value != "from-worker" {
		t.Fatalf("expected the default view to prefer the worker index over a live recompute, got %+v", got.Rows)
	}
}

func TestClustersDataFilteredStillRecomputesLive(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")
	seedClusterDoc(t, es, "fp1", clusterWorkerDoc{Kind: "fingerprint", Value: "from-worker", Events: 5, Sources: 2, Sensors: []string{"cowrie"}})

	now := time.Now()
	s := &store{es: es, events: []storedEvent{
		{when: now, SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "from-live-recompute"},
		{when: now, SrcIP: "198.51.100.1", Sensor: "cowrie", Fingerprint: "from-live-recompute"},
	}}

	f := clustersRequestFilter(httptest.NewRequest("GET", "/clusters?sensor=cowrie", nil))
	got := s.clustersData(f)
	if len(got.Rows) != 1 || got.Rows[0].Value != "from-live-recompute" {
		t.Fatalf("expected a filtered request to recompute live, not read the worker index, got %+v", got.Rows)
	}
}
