package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// singleSensorVectorsStub answers the POST ports/protocols terms-agg query
// fetchSensorAttackVectors sends.
func singleSensorVectorsStub(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "not stubbed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var resp esSingleSensorVectorsResponse
		resp.Aggregations.Ports.Buckets = []esBucket{{Key: json.RawMessage(`22`), DocCount: 12}}
		resp.Aggregations.Protocols.Buckets = []esBucket{
			{Key: json.RawMessage(`"smbd"`), DocCount: 5},
			{Key: json.RawMessage(`"smb"`), DocCount: 2},
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func TestFetchSensorAttackVectorsReturnsFalseWithoutAnESClient(t *testing.T) {
	s := &store{}
	if _, _, ok := s.fetchSensorAttackVectors("cowrie", time.Now()); ok {
		t.Fatal("expected ok=false when no ES client is configured")
	}
}

func TestFetchSensorAttackVectorsReturnsFalseForEmptySensor(t *testing.T) {
	srv := httptest.NewServer(singleSensorVectorsStub(t))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}
	if _, _, ok := s.fetchSensorAttackVectors("", time.Now()); ok {
		t.Fatal("expected ok=false for an empty sensor")
	}
}

// TestFetchSensorAttackVectorsParsesAndNormalizesProtocols proves ports come
// through as-is and protocols get the same normalizeProtocol collapsing
// (smbd->smb) fetchESOverview's own Protocols aggregation already applies.
func TestFetchSensorAttackVectorsParsesAndNormalizesProtocols(t *testing.T) {
	srv := httptest.NewServer(singleSensorVectorsStub(t))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	ports, protocols, ok := s.fetchSensorAttackVectors("cowrie", time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(ports) != 1 || ports[0].Key != "22" || ports[0].Count != 12 {
		t.Fatalf("unexpected ports: %+v", ports)
	}
	if len(protocols) != 1 || protocols[0].Key != "smb" || protocols[0].Count != 7 {
		t.Fatalf("expected smbd/smb folded into one normalized \"smb\" bucket (5+2), got: %+v", protocols)
	}
}

// TestServeAttackVectorsRejectsMissingSuricataAndPortbridgeSensors mirrors
// serveHeatmap's own guard: suricata/portbridge ship to their own index
// families, and no sensor at all has no "attack vectors for what" meaning.
func TestServeAttackVectorsRejectsMissingSuricataAndPortbridgeSensors(t *testing.T) {
	srv := httptest.NewServer(singleSensorVectorsStub(t))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	for _, sensor := range []string{"", "suricata", "portbridge"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/attack-vectors?sensor="+url.QueryEscape(sensor), nil)
		s.serveAttackVectors(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("sensor=%q: expected 400, got %d", sensor, rr.Code)
		}
	}
}

func TestServeAttackVectorsSingleSensorQueriesES(t *testing.T) {
	srv := httptest.NewServer(singleSensorVectorsStub(t))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/attack-vectors?sensor=cowrie", nil)
	s.serveAttackVectors(rr, req)

	var out struct {
		Sensor    string
		Ports     []kv
		Protocols []kv
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad JSON: %v (%s)", err, rr.Body.String())
	}
	if out.Sensor != "cowrie" || len(out.Ports) != 1 || out.Ports[0].Link == "" {
		t.Fatalf("unexpected response: %+v", out)
	}
}

func TestServeAttackVectorsFailsWithoutESClient(t *testing.T) {
	s := &store{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/attack-vectors?sensor=cowrie", nil)
	s.serveAttackVectors(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}
