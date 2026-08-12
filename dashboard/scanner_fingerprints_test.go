package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchScannerFingerprintsReturnsFalseWithoutAnESClient(t *testing.T) {
	s := &store{}
	if _, ok := s.fetchScannerFingerprints("suricata-v2-tls-*", "ja4", []byte(tlsFingerprintQuery)); ok {
		t.Fatal("expected ok=false when no ES client is configured")
	}
}

func TestFetchScannerFingerprintsReturnsFalseOnQueryFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}
	if _, ok := s.fetchScannerFingerprints("suricata-v2-tls-*", "ja4", []byte(tlsFingerprintQuery)); ok {
		t.Fatal("expected ok=false on a query failure")
	}
}

// TestFetchScannerFingerprintsReshapesNamedAggregation pins the reshape
// from a live-shaped terms-aggregation response into {categories, values},
// keyed by the caller-supplied aggregation name -- one function serves
// both /api/tls-fingerprints ("ja4") and /api/ssh-fingerprints
// ("software") this way.
func TestFetchScannerFingerprintsReshapesNamedAggregation(t *testing.T) {
	body := `{
	  "aggregations": {
	    "ja4": {
	      "buckets": [
	        {"key": "t13i191000_9dc949149365_e5728521abd4", "doc_count": 285},
	        {"key": "t12i130500_2d7513195f68_e51b7354d87f", "doc_count": 218}
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

	bar, ok := s.fetchScannerFingerprints("suricata-v2-tls-*", "ja4", []byte(tlsFingerprintQuery))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(bar.Categories) != 2 || bar.Categories[0] != "t13i191000_9dc949149365_e5728521abd4" || bar.Values[0] != 285 {
		t.Fatalf("unexpected bar: %+v", bar)
	}
}

// TestFetchScannerFingerprintsMissingAggNameReturnsFalse covers a response
// that parses as valid JSON but doesn't contain the aggregation name this
// call asked for (e.g. a stub/misconfigured cluster) -- must not panic on
// a nil buckets slice or silently report an empty chart as ok=true.
func TestFetchScannerFingerprintsMissingAggNameReturnsFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"aggregations":{}}`))
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	if _, ok := s.fetchScannerFingerprints("suricata-v2-tls-*", "ja4", []byte(tlsFingerprintQuery)); ok {
		t.Fatal("expected ok=false when the named aggregation is absent from the response")
	}
}

func TestServeTLSFingerprintsReturns503WhenESUnavailable(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveTLSFingerprints(rec, httptest.NewRequest("GET", "/api/tls-fingerprints", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestServeSSHFingerprintsReturns503WhenESUnavailable(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveSSHFingerprints(rec, httptest.NewRequest("GET", "/api/ssh-fingerprints", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// TestServeTLSFingerprintsWritesValidJSONBar is an end-to-end sanity check
// (query construction -> ES round trip -> handler JSON encoding) that the
// dest_port-443 exclusion in tlsFingerprintQuery doesn't break request
// construction against a real (stubbed) cluster.
func TestServeTLSFingerprintsWritesValidJSONBar(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"aggregations":{"ja4":{"buckets":[{"key":"abc","doc_count":5}]}}}`))
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	rec := httptest.NewRecorder()
	s.serveTLSFingerprints(rec, httptest.NewRequest("GET", "/api/tls-fingerprints", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var bar scannerFingerprintBar
	if err := json.Unmarshal(rec.Body.Bytes(), &bar); err != nil {
		t.Fatalf("invalid JSON: %v (body: %s)", err, rec.Body.String())
	}
	if len(bar.Categories) != 1 || bar.Categories[0] != "abc" || bar.Values[0] != 5 {
		t.Fatalf("unexpected bar: %+v", bar)
	}
}
