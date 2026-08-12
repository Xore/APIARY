package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsRoutableNetworkExcludesPrivateAndTunnelPeerRange(t *testing.T) {
	for _, ip := range []string{"10.8.0.0", "10.0.0.0", "192.168.1.0", "127.0.0.0", "169.254.0.0", "not-an-ip", ""} {
		if isRoutableNetwork(ip) {
			t.Errorf("isRoutableNetwork(%q) = true, want false", ip)
		}
	}
	if !isRoutableNetwork("203.0.113.0") {
		t.Fatal("expected a public network address to be routable")
	}
}

func TestCutCredPairSplitsOnSeparator(t *testing.T) {
	user, pass, found := cutCredPair("root / toor")
	if !found || user != "root" || pass != "toor" {
		t.Fatalf("got user=%q pass=%q found=%v", user, pass, found)
	}
}

func TestToBucketCountsOnlyValidCredentialPairs(t *testing.T) {
	raw := campaignAggBucket{
		Key: "203.0.113.0", PrefixLength: 24, DocCount: 10,
		CredPairs: aggTerms{Buckets: []aggTermsBucket{
			{Key: " / ", DocCount: 8},                   // empty pair, must not count
			{Key: "root / toor", DocCount: 1},           // valid
			{Key: "root / ; /bin/busybox", DocCount: 1}, // invalid (matches dashboard's own reject list)
		}},
	}
	b := toBucket(raw)
	if b.Creds != 1 {
		t.Fatalf("expected exactly 1 valid credential pair, got %d: %+v", b.Creds, b)
	}
	if b.CIDR != "203.0.113.0/24" {
		t.Fatalf("cidr = %q", b.CIDR)
	}
}

func TestToBucketCapsSensorsAndProviders(t *testing.T) {
	raw := campaignAggBucket{Key: "203.0.113.0", PrefixLength: 24}
	for i := 0; i < 10; i++ {
		raw.Sensors.Buckets = append(raw.Sensors.Buckets, aggTermsBucket{Key: "s", DocCount: 1})
		raw.Providers.Buckets = append(raw.Providers.Buckets, aggTermsBucket{Key: "p", DocCount: 1})
	}
	b := toBucket(raw)
	if len(b.Sensors) != 6 {
		t.Fatalf("expected sensors capped at 6, got %d", len(b.Sensors))
	}
	if len(b.Providers) != 4 {
		t.Fatalf("expected providers capped at 4, got %d", len(b.Providers))
	}
}

func TestPortTermsHandlesNumericKeys(t *testing.T) {
	terms := aggTerms{Buckets: []aggTermsBucket{{Key: float64(22), DocCount: 5}, {Key: float64(2222), DocCount: 1}}}
	got := portTerms(terms)
	if len(got) != 2 || got[0] != "22" || got[1] != "2222" {
		t.Fatalf("got %+v", got)
	}
}

func TestFetchCampaignAggregatesParsesAndFiltersUnroutable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"aggregations":{
			"cidrs_v4":{"buckets":[
				{"key":"203.0.113.0","prefix_length":24,"doc_count":5,"unique_ips":{"value":2},
				 "sensors":{"buckets":[{"key":"cowrie","doc_count":5}]},
				 "ports":{"buckets":[{"key":22,"doc_count":5}]},
				 "cred_pairs":{"buckets":[{"key":"root / toor","doc_count":1}]},
				 "payloads":{"value":0},"fingerprints":{"value":0},
				 "providers":{"buckets":[]},
				 "first":{"value_as_string":"2026-08-05T00:00:00Z"},"last":{"value_as_string":"2026-08-11T00:00:00Z"}},
				{"key":"10.8.0.0","prefix_length":24,"doc_count":50,"unique_ips":{"value":1},
				 "sensors":{"buckets":[]},"ports":{"buckets":[]},"cred_pairs":{"buckets":[]},
				 "payloads":{"value":0},"fingerprints":{"value":0},"providers":{"buckets":[]},
				 "first":{"value_as_string":"2026-08-05T00:00:00Z"},"last":{"value_as_string":"2026-08-11T00:00:00Z"}}
			]},
			"cidrs_v6":{"buckets":[]}
		}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	buckets, ok := fetchCampaignAggregates(es, time.Now().Add(-time.Hour))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(buckets) != 1 {
		t.Fatalf("expected the tunnel-peer network (10.8.0.0/24) to be filtered out, got %d buckets: %+v", len(buckets), buckets)
	}
	b := buckets[0]
	if b.CIDR != "203.0.113.0/24" || b.Events != 5 || b.UniqueIPs != 2 || b.Creds != 1 {
		t.Fatalf("got %+v", b)
	}
	if b.First != "2026-08-05T00:00:00Z" || b.Last != "2026-08-11T00:00:00Z" {
		t.Fatalf("got first=%q last=%q", b.First, b.Last)
	}
}

func TestFetchClusterAggregatesEnforcesTwoUniqueIPThreshold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"aggregations":{
			"fingerprints":{"buckets":[
				{"key":"shared-fp","doc_count":10,"unique_ips":{"value":3},"sensors":{"buckets":[{"key":"cowrie","doc_count":10}]}},
				{"key":"single-ip-fp","doc_count":10,"unique_ips":{"value":1},"sensors":{"buckets":[]}}
			]},
			"payloads":{"buckets":[]},
			"asns":{"buckets":[
				{"key":64512,"doc_count":4,"unique_ips":{"value":2},"sensors":{"buckets":[]},"org":{"buckets":[{"key":"Example ISP","doc_count":4}]}}
			]},
			"providers":{"buckets":[]}
		}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	buckets, ok := fetchClusterAggregates(es, time.Now().Add(-time.Hour))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(buckets) != 2 {
		t.Fatalf("expected 2 clusters (single-ip-fp excluded), got %d: %+v", len(buckets), buckets)
	}
	var fp, asn *clusterBucket
	for i := range buckets {
		switch buckets[i].Kind {
		case "fingerprint":
			fp = &buckets[i]
		case "asn":
			asn = &buckets[i]
		}
	}
	if fp == nil || fp.Value != "shared-fp" || fp.UniqueIPs != 3 {
		t.Fatalf("fingerprint cluster = %+v", fp)
	}
	if asn == nil || asn.Value != "AS64512 Example ISP" {
		t.Fatalf("asn cluster = %+v", asn)
	}
}

func TestFetchSuricataAlertCountsParsesBuckets(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"aggregations":{"by_ip":{"buckets":[
			{"key":"203.0.113.1","doc_count":5},
			{"key":"198.51.100.1","doc_count":2}
		]}}}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	counts, ok := fetchSuricataAlertCounts(es, time.Now().Add(-time.Hour))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if gotPath != "/"+suricataAlertIndexPattern+"/_search" {
		t.Fatalf("path = %q", gotPath)
	}
	if counts["203.0.113.1"] != 5 || counts["198.51.100.1"] != 2 {
		t.Fatalf("got %+v", counts)
	}
}

func TestFetchSuricataAlertCountsTreats404AsEmptyNotFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	counts, ok := fetchSuricataAlertCounts(es, time.Now().Add(-time.Hour))
	if !ok {
		t.Fatal("a missing suricata-v2-alert-* index should not be a failure")
	}
	if len(counts) != 0 {
		t.Fatalf("expected an empty map, got %+v", counts)
	}
}

func TestFetchSuricataAlertCountsReturnsFalseOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, ok := fetchSuricataAlertCounts(es, time.Now().Add(-time.Hour))
	if ok {
		t.Fatal("a genuine 500 must not be conflated with a missing-index 404")
	}
}
