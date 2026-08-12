package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchDionaeaCVEsReturnsFalseWithoutAnESClient(t *testing.T) {
	s := &store{}
	if _, ok := s.fetchDionaeaCVEs(); ok {
		t.Fatal("expected ok=false when no ES client is configured")
	}
}

func TestFetchDionaeaCVEsReturnsFalseOnQueryFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}
	if _, ok := s.fetchDionaeaCVEs(); ok {
		t.Fatal("expected ok=false on a query failure")
	}
}

// TestFetchDionaeaCVEsLabelsBucketsWithCVEWhenKnown pins the live-shaped
// response (#1276's own confirmed sample: "DoublePulsar connection
// attempt" / "CVE-2017-0144..CVE-2017-0148", "MS17-010 SMB RCE exploit
// scanning" / "CVE-2017-0143..CVE-2017-0148") reshapes into the
// {categories, values} bar shape, appending each bucket's CVE sub-
// aggregation result in parens when one exists.
func TestFetchDionaeaCVEsLabelsBucketsWithCVEWhenKnown(t *testing.T) {
	body := `{
	  "aggregations": {
	    "names": {
	      "buckets": [
	        {"key": "DoublePulsar connection attempt", "doc_count": 5827214,
	         "cve": {"buckets": [{"key": "CVE-2017-0144..CVE-2017-0148"}]}},
	        {"key": "MS17-010 SMB RCE exploit scanning", "doc_count": 32,
	         "cve": {"buckets": [{"key": "CVE-2017-0143..CVE-2017-0148"}]}}
	      ]
	    }
	  }
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	bar, ok := s.fetchDionaeaCVEs()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(bar.Categories) != 2 || len(bar.Values) != 2 {
		t.Fatalf("unexpected bar: %+v", bar)
	}
	if bar.Categories[0] != "DoublePulsar connection attempt (CVE-2017-0144..CVE-2017-0148)" {
		t.Fatalf("categories[0] = %q", bar.Categories[0])
	}
	if bar.Values[0] != 5827214 {
		t.Fatalf("values[0] = %d, want 5827214", bar.Values[0])
	}
	if bar.Categories[1] != "MS17-010 SMB RCE exploit scanning (CVE-2017-0143..CVE-2017-0148)" {
		t.Fatalf("categories[1] = %q", bar.Categories[1])
	}
}

// TestFetchDionaeaCVEsLeavesUnknownNameBare covers a named bucket with no
// CVE sub-aggregation hit (e.g. a future incident kind that sets data.name
// but never data.cve) -- must not fabricate a parenthetical.
func TestFetchDionaeaCVEsLeavesUnknownNameBare(t *testing.T) {
	var resp dionaeaCVEResponse
	resp.Aggregations.Names.Buckets = []struct {
		Key      string `json:"key"`
		DocCount int    `json:"doc_count"`
		CVE      struct {
			Buckets []struct {
				Key string `json:"key"`
			} `json:"buckets"`
		} `json:"cve"`
	}{
		{Key: "some future incident", DocCount: 3},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	bar, ok := s.fetchDionaeaCVEs()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(bar.Categories) != 1 || bar.Categories[0] != "some future incident" {
		t.Fatalf("categories = %+v, want the bare name with no parenthetical", bar.Categories)
	}
}

func TestServeDionaeaCVEsReturns503WhenESUnavailable(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveDionaeaCVEs(rec, httptest.NewRequest("GET", "/api/dionaea-cves", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}
