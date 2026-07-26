package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIPlatformPersona(t *testing.T) {
	var output bytes.Buffer
	s := &server{log: &logger{out: &output}, sensor: "api-honeypot", serverHdr: "nginx", persona: "nexusai-platform", site: "nexusai-eu-cloud", asset: "platform-gw-03", org: "NexusAI Research GmbH"}
	r := httptest.NewRequest(http.MethodGet, "http://api.example/version", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"gitVersion":"v1.29.6-gke.1326000"`) {
		t.Fatalf("unexpected API response: %d %s", w.Code, w.Body.String())
	}
	var got event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Persona != "nexusai-platform" || got.Site != "nexusai-eu-cloud" || got.Asset != "platform-gw-03" {
		t.Fatalf("unexpected persona metadata: %+v", got)
	}
}
