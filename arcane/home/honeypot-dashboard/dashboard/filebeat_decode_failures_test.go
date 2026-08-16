package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestESClientRefreshCountsFilebeatDecodeFailures (#1298): filebeat-* is
// Filebeat's own fallback index for log lines its json.decode processor
// couldn't parse at all -- a distinct, earlier failure layer from
// dead-letter-honeypot* (which only ever holds documents Elasticsearch
// itself rejected after Filebeat successfully decoded and shipped them).
// No dashboard code path read this index before; refresh() must now count
// it the same way it already counts dead-letter-honeypot*.
func TestESClientRefreshCountsFilebeatDecodeFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/_cluster/health":
			w.Write([]byte(`{"status":"green"}`))
		case strings.HasPrefix(r.URL.Path, "/filebeat-*/_count"):
			w.Write([]byte(`{"count":2}`))
		case strings.HasPrefix(r.URL.Path, "/dead-letter-honeypot*/_count"):
			w.Write([]byte(`{"count":0}`))
		case strings.HasPrefix(r.URL.Path, "/honeypot-v2-*"):
			w.Write([]byte(`{"count":0,"hits":{"hits":[]}}`))
		case strings.HasPrefix(r.URL.Path, "/suricata-*/_count"):
			w.Write([]byte(`{"count":0}`))
		default:
			w.Write([]byte(`{"count":0,"hits":{"hits":[]}}`))
		}
	}))
	defer srv.Close()

	es := newESClient(srv.URL, "")
	es.refresh()

	st := es.get()
	if st.FilebeatDecodeFailures != 2 {
		t.Fatalf("FilebeatDecodeFailures = %d, want 2", st.FilebeatDecodeFailures)
	}
}

// TestServeMetricsExportsFilebeatDecodeFailures pins the new Prometheus
// gauge alongside the existing dead-letter ones.
func TestServeMetricsExportsFilebeatDecodeFailures(t *testing.T) {
	s := &store{snap: snapshot{ES: esStatus{FilebeatDecodeFailures: 3}}}
	rec := httptest.NewRecorder()
	s.serveMetrics(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "honeypot_filebeat_decode_failures_total 3") {
		t.Fatalf("missing honeypot_filebeat_decode_failures_total in metrics output:\n%s", rec.Body.String())
	}
}
