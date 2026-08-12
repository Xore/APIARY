package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// #1294: /api/endlessh-held-histogram reads the already-bucketed
// snapshot.EndlesshHeldBuckets map -- verify it reshapes into the fixed,
// ordered {categories, values} arrays the bar chart expects, same pattern
// os_distribution_test.go established for the pie chart.
func TestServeEndlesshHeldHistogramOrdersBucketsShortestToLongest(t *testing.T) {
	s := &store{snap: snapshot{EndlesshHeldBuckets: map[string]int{
		"5min+": 2,
		"<1s":   9,
		"1-5s":  4,
	}}}
	rec := httptest.NewRecorder()
	s.serveEndlesshHeldHistogram(rec, httptest.NewRequest("GET", "/api/endlessh-held-histogram", nil))

	var got struct {
		Categories []string `json:"categories"`
		Values     []int    `json:"values"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response was not valid JSON: %v (body: %s)", err, rec.Body.String())
	}
	wantCategories := []string{"<1s", "1-5s", "5-15s", "15-60s", "1-5min", "5min+"}
	if len(got.Categories) != len(wantCategories) {
		t.Fatalf("got %d categories, want %d: %+v", len(got.Categories), len(wantCategories), got.Categories)
	}
	for i, c := range wantCategories {
		if got.Categories[i] != c {
			t.Fatalf("category[%d] = %q, want %q (bucket order must be short-to-long, not map iteration order)", i, got.Categories[i], c)
		}
	}
	wantValues := []int{9, 4, 0, 0, 0, 2}
	for i, v := range wantValues {
		if got.Values[i] != v {
			t.Fatalf("values[%d] = %d, want %d (%+v)", i, got.Values[i], v, got.Values)
		}
	}
}

func TestServeEndlesshHeldHistogramEmptySnapshotIsZeroedNotNull(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveEndlesshHeldHistogram(rec, httptest.NewRequest("GET", "/api/endlessh-held-histogram", nil))

	var got struct {
		Categories []string `json:"categories"`
		Values     []int    `json:"values"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response was not valid JSON: %v (body: %s)", err, rec.Body.String())
	}
	if len(got.Categories) != 6 {
		t.Fatalf("expected all 6 buckets present with zero counts, got %+v", got.Categories)
	}
	for i, v := range got.Values {
		if v != 0 {
			t.Fatalf("values[%d] = %d, want 0 for an empty snapshot", i, v)
		}
	}
}

func TestHeldMsBucketBoundaries(t *testing.T) {
	cases := []struct {
		ms   int
		want string
	}{
		{0, "<1s"},
		{999, "<1s"},
		{1000, "1-5s"},
		{4999, "1-5s"},
		{5000, "5-15s"},
		{14999, "5-15s"},
		{15000, "15-60s"},
		{59999, "15-60s"},
		{60000, "1-5min"},
		{299999, "1-5min"},
		{300000, "5min+"},
		{3600000, "5min+"},
	}
	for _, c := range cases {
		if got := heldMsBucket(c.ms); got != c.want {
			t.Errorf("heldMsBucket(%d) = %q, want %q", c.ms, got, c.want)
		}
	}
}

func TestEndlesshHeldHumanDuration(t *testing.T) {
	cases := []struct {
		totalMs int64
		want    string
	}{
		{0, "0m"},
		{500, "<1m"},
		{59999, "<1m"},
		{60000, "1m"},
		{90000, "1m"},
		{5 * 60000, "5m"},
		{3600000, "1h 0m"},
		{3600000 + 5*60000, "1h 5m"},
		{2*3600000 + 59*60000, "2h 59m"},
	}
	for _, c := range cases {
		if got := endlesshHeldHumanDuration(c.totalMs); got != c.want {
			t.Errorf("endlesshHeldHumanDuration(%d) = %q, want %q", c.totalMs, got, c.want)
		}
	}
}
