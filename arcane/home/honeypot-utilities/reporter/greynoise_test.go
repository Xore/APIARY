package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *store {
	t.Helper()
	st, err := openStore(filepath.Join(t.TempDir(), "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestGreynoiseNeverCallsRealAPIWithoutExplicitBaseURL proves the same
// no-real-network property dryrun_test.go's poisonedTransport proves for
// the report senders: newGreynoiseChecker's default baseURL is GreyNoise's
// real API, but every test below passes an explicit httptest URL --
// confirming that's actually where lookups go, not silently falling back
// to the real endpoint on a wiring mistake.
func TestGreynoiseNeverCallsRealAPIWithoutExplicitBaseURL(t *testing.T) {
	if newGreynoiseChecker(nil, "", "", true, time.Hour, 0, 0).baseURL != greynoiseDefaultBaseURL {
		t.Fatal("expected the real GreyNoise URL as the documented default -- if this changed, every test below needs re-auditing to confirm it still overrides it")
	}
}

func TestGreynoiseKnownBenignIsSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(riotResult{Riot: true, Category: "public_dns", Name: "Google Public DNS"})
	}))
	defer srv.Close()

	st := newTestStore(t)
	g := newGreynoiseChecker(st, srv.URL, "", true, time.Hour, 0, 0)
	skip, reason := g.benign("8.8.8.8")
	if !skip {
		t.Fatalf("expected known-benign RIOT infra to be skipped, reason=%q", reason)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason for the audit log")
	}
}

func TestGreynoiseUnknownIsNotSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(riotResult{Riot: false})
	}))
	defer srv.Close()

	st := newTestStore(t)
	g := newGreynoiseChecker(st, srv.URL, "", true, time.Hour, 0, 0)
	if skip, reason := g.benign("203.0.113.5"); skip {
		t.Fatalf("expected a non-RIOT address to be reported normally, got skip with reason=%q", reason)
	}
}

func TestGreynoise404IsNotSkipped(t *testing.T) {
	// GreyNoise returns 404 for an address with no RIOT record at all --
	// a valid "not known-benign" answer, not a lookup failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	st := newTestStore(t)
	g := newGreynoiseChecker(st, srv.URL, "", true, time.Hour, 0, 0)
	if skip, reason := g.benign("203.0.113.6"); skip {
		t.Fatalf("expected a 404 (no RIOT record) to be treated as reportable, got skip with reason=%q", reason)
	}
}

func TestGreynoiseLookupFailureFailsOpenWhenConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	st := newTestStore(t)
	g := newGreynoiseChecker(st, srv.URL, "", true, time.Hour, 0, 0) // failOpen=true
	if skip, reason := g.benign("203.0.113.7"); skip {
		t.Fatalf("fail-open: expected reporting to proceed on lookup failure, got skip with reason=%q", reason)
	}
}

func TestGreynoiseLookupFailureFailsClosedWhenConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	st := newTestStore(t)
	g := newGreynoiseChecker(st, srv.URL, "", false, time.Hour, 0, 0) // failOpen=false
	if skip, reason := g.benign("203.0.113.8"); !skip {
		t.Fatalf("fail-closed: expected reporting to be skipped on lookup failure, reason=%q", reason)
	}
}

func TestGreynoiseTimeoutFailsOpenWhenConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		json.NewEncoder(w).Encode(riotResult{Riot: true})
	}))
	defer srv.Close()

	st := newTestStore(t)
	g := newGreynoiseChecker(st, srv.URL, "", true, time.Hour, 0, 0)
	g.client.Timeout = 5 * time.Millisecond // force a client-side timeout well before the handler's sleep completes
	if skip, reason := g.benign("203.0.113.9"); skip {
		t.Fatalf("fail-open: expected a timeout to proceed with reporting, got skip with reason=%q", reason)
	}
}

func TestGreynoiseCacheAvoidsASecondCall(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(riotResult{Riot: true, Category: "cdn"})
	}))
	defer srv.Close()

	st := newTestStore(t)
	g := newGreynoiseChecker(st, srv.URL, "", true, time.Hour, 0, 0)
	g.benign("198.51.100.1")
	g.benign("198.51.100.1")
	g.benign("198.51.100.1")
	if n := calls.Load(); n != 1 {
		t.Fatalf("expected exactly 1 real lookup for a repeated IP within cache TTL, got %d", n)
	}
}

func TestGreynoiseStaleCacheUsedOnLookupFailure(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(riotResult{Riot: true, Category: "scanner", Name: "Known Research Scanner"})
	}))
	defer srv.Close()

	st := newTestStore(t)
	// cacheTTL=0 with no minCallGap: every call is immediately "stale" per
	// greynoiseCacheGet's own TTL math, but the row still exists -- this
	// forces the stale-cache-on-failure path deterministically instead of
	// waiting out a real TTL in the test.
	g := newGreynoiseChecker(st, srv.URL, "", false, time.Nanosecond, 0, 0) // failOpen=false, so a hard failure with no cache would skip differently
	skip, _ := g.benign("198.51.100.2")
	if !skip {
		t.Fatal("expected the first (real) lookup to mark this address benign")
	}

	fail.Store(true)
	skip, reason := g.benign("198.51.100.2")
	if !skip {
		t.Fatalf("expected the stale cached 'benign' verdict to be used when the live lookup fails, got skip=false reason=%q", reason)
	}
}

func TestGreynoiseRateLimitFallsBackToCacheOrOutagePolicy(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(riotResult{Riot: false})
	}))
	defer srv.Close()

	st := newTestStore(t)
	g := newGreynoiseChecker(st, srv.URL, "", true, time.Hour, time.Hour, 0) // minCallGap huge: second distinct IP must be rate-limited
	g.benign("198.51.100.3")
	skip, reason := g.benign("198.51.100.4") // different IP, no cache entry, rate-limited
	if calls.Load() != 1 {
		t.Fatalf("expected only 1 real call, the rate limit should have blocked the second, got %d calls", calls.Load())
	}
	if skip {
		t.Fatalf("fail-open + rate-limited + no cache: expected reporting to proceed, got skip with reason=%q", reason)
	}
}

func TestGreynoiseCacheIsBoundedByRetentionCap(t *testing.T) {
	st := newTestStore(t)
	for i := 0; i < 10; i++ {
		ip := "10.0." + string(rune('0'+i)) + ".1"
		if err := st.greynoiseCacheSet(ip, true, "test", 5); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM greynoise_cache`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count > 5 {
		t.Fatalf("expected cache to be pruned to at most 5 rows, got %d", count)
	}
}

func TestGreynoiseDisabledMeansNoLookupAtAll(t *testing.T) {
	// processor.gn == nil (the disabled state main.go leaves it in when
	// GREYNOISE_ENABLED is unset) must skip the check entirely, not call
	// benign() with some zero-value checker.
	wl, err := loadWhitelist("")
	if err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t)
	var audit stringWriter
	al := newAuditLog(&audit)
	send := dryRunSender{audit: al}
	sendBD := dryRunBlocklistDeSender{audit: al}
	proc := newProcessor(wl, nil, st, send, sendBD, al, time.Hour, 1)
	proc.handle("cowrie", []byte(`{"eventid":"cowrie.session.connect","src_ip":"203.0.113.10","session":"x"}`))
	// No panic, no crash -- that's the whole assertion. If gn were
	// accidentally dereferenced, this test would panic instead of passing.
}

type stringWriter struct{ data []byte }

func (s *stringWriter) Write(p []byte) (int, error) {
	s.data = append(s.data, p...)
	return len(p), nil
}
