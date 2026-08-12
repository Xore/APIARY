package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// #1277: /api/os-distribution reads the same snapshot.OSDistribution field
// aggregate.go's rebuild() already populates -- no new aggregation pass, so
// this only needs to verify the HTTP handler's own JSON reshaping into
// ECharts' native pie-series {name, value} points.
func TestServeOSDistributionReshapesKVIntoNameValuePoints(t *testing.T) {
	s := &store{snap: snapshot{OSDistribution: []kv{
		{Key: "Linux 3.11 and newer", Count: 42},
		{Key: "Windows 10/11", Count: 7},
	}}}
	rec := httptest.NewRecorder()
	s.serveOSDistribution(rec, httptest.NewRequest("GET", "/api/os-distribution", nil))

	var points []osDistributionPoint
	if err := json.Unmarshal(rec.Body.Bytes(), &points); err != nil {
		t.Fatalf("response was not valid JSON: %v (body: %s)", err, rec.Body.String())
	}
	if len(points) != 2 {
		t.Fatalf("expected 2 points, got %+v", points)
	}
	if points[0].Name != "Linux 3.11 and newer" || points[0].Value != 42 {
		t.Fatalf("got %+v", points[0])
	}
	if points[1].Name != "Windows 10/11" || points[1].Value != 7 {
		t.Fatalf("got %+v", points[1])
	}
}

func TestServeOSDistributionEmptyIsAnEmptyArrayNotNull(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveOSDistribution(rec, httptest.NewRequest("GET", "/api/os-distribution", nil))
	if rec.Body.String() != "[]\n" {
		t.Fatalf("expected an empty JSON array (not null), got %q", rec.Body.String())
	}
}
