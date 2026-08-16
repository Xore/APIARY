package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #1233: a real Elasticsearch response larger than esResponseBodyCap used
// to get silently truncated by a bare io.LimitReader, then handed to
// json.Unmarshal, which failed with a confusing "unterminated string in
// JSON" error instead of anything actionable. readCappedBody must instead
// error clearly, and a response at (not over) the cap must still work.
func TestReadCappedBodyErrorsClearlyOnOversizedResponse(t *testing.T) {
	oversized := strings.Repeat("a", esResponseBodyCap+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"x":"` + oversized + `"}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL, "")
	_, err := es.request("/x")
	if err == nil {
		t.Fatal("expected an error for an oversized response")
	}
	if strings.Contains(err.Error(), "unterminated") || strings.Contains(err.Error(), "unexpected end of JSON") {
		t.Fatalf("expected a clear truncation error, got the old confusing parse error: %v", err)
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("expected the error to explain the response exceeded the cap, got: %v", err)
	}
}

func TestReadCappedBodyAllowsResponseExactlyAtTheCap(t *testing.T) {
	// esResponseBodyCap bytes of payload, plus minimal JSON wrapper -- the
	// point is a response AT the cap (not over it) must not be rejected as
	// truncated.
	value := strings.Repeat("a", esResponseBodyCap-len(`{"x":""}`))
	body := []byte(`{"x":"` + value + `"}`)
	if len(body) != esResponseBodyCap {
		t.Fatalf("test setup: body is %d bytes, want exactly %d", len(body), esResponseBodyCap)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	es := newESClient(srv.URL, "")
	b, err := es.request("/x")
	if err != nil {
		t.Fatalf("a response exactly at the cap must not error: %v", err)
	}
	if len(b) != esResponseBodyCap {
		t.Fatalf("got %d bytes, want %d", len(b), esResponseBodyCap)
	}
}
