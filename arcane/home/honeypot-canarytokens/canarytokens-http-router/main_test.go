package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestExtractToken(t *testing.T) {
	valid := "abcdefghijklmnopqrstuvwx0" // 25 chars, 0-9a-z
	if len(valid) != 25 {
		t.Fatalf("test fixture itself is %d chars, want 25", len(valid))
	}

	cases := []struct {
		host      string
		wantToken string
		wantOK    bool
	}{
		{valid + ".xore.rocks", valid, true},
		{valid + ".xore.rocks:443", valid, true},                                    // port must be stripped before matching
		{"XORE." + valid, "", false},                                                // wrong order: label isn't the leading one
		{"dashboard.xore.rocks", "", false},                                         // real named subdomain, not token-shaped
		{"xore.rocks", "", false},                                                   // bare apex, no leading label to check
		{valid[:24] + ".xore.rocks", "", false},                                     // one char short
		{valid + "x.xore.rocks", "", false},                                         // one char long
		{"UPPERCASE1234567890ABCDEF.xore.rocks", "uppercase1234567890abcdef", true}, // lowercased before matching (25 chars)
		{"has-a-dash-in-it-1234567.xore.rocks", "", false},                          // dash isn't in CANARYTOKEN_ALPHABET
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := extractToken(c.host)
		if ok != c.wantOK || (ok && got != c.wantToken) {
			t.Errorf("extractToken(%q) = (%q, %v), want (%q, %v)", c.host, got, ok, c.wantToken, c.wantOK)
		}
	}
}

func TestServeHTTPRewritesPathForTokenShapedHost(t *testing.T) {
	token := "abcdefghijklmnopqrstuvwx0"
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rt := newTestRouter(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "http://"+token+".xore.rocks/RANDOMPADDING", nil)
	req.Host = token + ".xore.rocks"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	wantPath := "/" + token + "/RANDOMPADDING"
	if gotPath != wantPath {
		t.Errorf("backend saw path %q, want %q", gotPath, wantPath)
	}
}

func TestServeHTTPLeavesPathAloneForNonTokenHost(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rt := newTestRouter(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "http://dashboard.xore.rocks/some/path", nil)
	req.Host = "dashboard.xore.rocks"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if gotPath != "/some/path" {
		t.Errorf("backend saw path %q, want unmodified /some/path", gotPath)
	}
}

// fakeRedis speaks just enough RESP to answer one HGETALL with a fixed
// field set, mirroring canarytokens' own real canarydrop:<token> hash
// shape (confirmed live against a real drop, see main.go's package doc).
func fakeRedis(t *testing.T, fields map[string]string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// drain the request line, don't bother parsing it -- this fake only
		// ever serves one canned reply per test.
		bufio.NewReader(conn).ReadString('\n')

		flat := make([]string, 0, len(fields)*2)
		for k, v := range fields {
			flat = append(flat, k, v)
		}
		fmt.Fprintf(conn, "*%d\r\n", len(flat))
		for _, s := range flat {
			fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(s), s)
		}
	}()
	return ln.Addr().String()
}

func TestRedisHGetAll(t *testing.T) {
	want := map[string]string{"type": "adobe_pdf", "memo": "test memo"}
	addr := fakeRedis(t, want)

	got, err := redisHGetAll(addr, "canarydrop:whatever")
	if err != nil {
		t.Fatalf("redisHGetAll: %v", err)
	}
	if got["type"] != want["type"] || got["memo"] != want["memo"] {
		t.Errorf("redisHGetAll = %v, want %v", got, want)
	}
}

func TestRedisHGetAllEmptyReply(t *testing.T) {
	addr := fakeRedis(t, map[string]string{})

	got, err := redisHGetAll(addr, "canarydrop:doesnotexist")
	if err != nil {
		t.Fatalf("redisHGetAll: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("redisHGetAll = %v, want empty map for a not-found drop", got)
	}
}

func newTestRouter(t *testing.T, backendURL string) *router {
	t.Helper()
	target, err := url.Parse(backendURL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	return &router{
		proxy:      httputil.NewSingleHostReverseProxy(target),
		redisAddr:  "127.0.0.1:0", // unused by these tests; ServeHTTP's Redis call is async and best-effort
		adapterURL: "http://127.0.0.1:0/",
		httpClient: &http.Client{},
	}
}
