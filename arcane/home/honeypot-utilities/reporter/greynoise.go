package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// riotResult is the subset of GreyNoise's RIOT response this reporter acts
// on. RIOT ("Rule It Out") answers one narrow question -- is this address
// known-benign business-service infrastructure (a DNS resolver, a CDN edge,
// a SaaS provider's outbound scanner) -- which is exactly the false-positive
// class docs/ip-reporting-plan.md's Phase 3 asks to guard against. It is
// deliberately not a general threat-intel verdict: RIOT says nothing about
// malicious activity, only "is this the kind of address that generates
// legitimate automated traffic and should not be reported as an attacker."
type riotResult struct {
	Riot     bool   `json:"riot"`
	Category string `json:"category"`
	Name     string `json:"name"`
}

// greynoiseChecker decides whether an IP is known-benign RIOT infrastructure
// and should be skipped rather than reported. Every lookup is cached in the
// same SQLite store the dedup/cooldown state already lives in -- one more
// reason not to add a second persistence mechanism to this binary.
type greynoiseChecker struct {
	client   *http.Client
	baseURL  string // overridable for tests; real default is GreyNoise's API
	apiKey   string // empty is valid -- RIOT's community tier works unauthenticated, just rate-limited harder
	st       *store
	cacheTTL time.Duration
	failOpen bool // outage/timeout behavior: true = proceed with reporting, false = skip (treat as benign) until the lookup succeeds again

	mu         sync.Mutex
	lastCallAt time.Time
	minCallGap time.Duration // outbound rate limit: never call GreyNoise more than once per this interval
	cacheMax   int
}

const greynoiseDefaultBaseURL = "https://api.greynoise.io/v3/riot"

func newGreynoiseChecker(st *store, baseURL, apiKey string, failOpen bool, cacheTTL, minCallGap time.Duration, cacheMax int) *greynoiseChecker {
	if baseURL == "" {
		baseURL = greynoiseDefaultBaseURL
	}
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}
	if cacheMax <= 0 {
		cacheMax = 50_000
	}
	return &greynoiseChecker{
		client:     &http.Client{Timeout: 5 * time.Second},
		baseURL:    baseURL,
		apiKey:     apiKey,
		st:         st,
		cacheTTL:   cacheTTL,
		failOpen:   failOpen,
		minCallGap: minCallGap,
		cacheMax:   cacheMax,
	}
}

// benign reports whether ip is known-benign RIOT infrastructure and the
// reason for the decision (for the audit log). ok is always true: this
// function never fails the caller, it only ever decides skip-or-not,
// applying failOpen/stale-cache fallback internally so process.go's
// pipeline has one simple bool to act on.
func (g *greynoiseChecker) benign(ip string) (skip bool, reason string) {
	cached, found, stale, err := g.st.greynoiseCacheGet(ip, g.cacheTTL)
	if err == nil && found && !stale {
		return cached.benign, cached.reason + " (cached)"
	}

	if !g.rateLimitOK() {
		if err == nil && found {
			return cached.benign, cached.reason + " (cached, rate-limited)"
		}
		return g.outageFallback("rate-limited, no cache entry")
	}

	result, lookupErr := g.lookup(ip)
	if lookupErr != nil {
		// A stale-but-present cache entry beats a hard fail-open/fail-closed
		// default: it is real, if aging, signal about this specific address,
		// not a blanket policy applied to every address during an outage.
		if err == nil && found {
			return cached.benign, fmt.Sprintf("%s (stale cache, lookup failed: %v)", cached.reason, lookupErr)
		}
		return g.outageFallback(lookupErr.Error())
	}

	skip = result.Riot
	if skip {
		reason = fmt.Sprintf("GreyNoise RIOT: %s (%s)", result.Name, result.Category)
	} else {
		reason = "GreyNoise RIOT: not known-benign infrastructure"
	}
	_ = g.st.greynoiseCacheSet(ip, skip, reason, g.cacheMax)
	return skip, reason
}

func (g *greynoiseChecker) outageFallback(detail string) (bool, string) {
	if g.failOpen {
		return false, "GreyNoise unavailable (" + detail + "), fail-open: reporting proceeds"
	}
	return true, "GreyNoise unavailable (" + detail + "), fail-closed: skipping until it recovers"
}

// rateLimitOK enforces minCallGap between real outbound GreyNoise calls --
// independent of cache TTL, this bounds worst-case call rate even if many
// distinct, never-before-seen IPs arrive in a burst.
func (g *greynoiseChecker) rateLimitOK() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Sub(g.lastCallAt) < g.minCallGap {
		return false
	}
	g.lastCallAt = now
	return true
}

func (g *greynoiseChecker) lookup(ip string) (riotResult, error) {
	req, err := http.NewRequest(http.MethodGet, g.baseURL+"/"+ip, nil)
	if err != nil {
		return riotResult{}, err
	}
	if g.apiKey != "" {
		req.Header.Set("key", g.apiKey)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return riotResult{}, err
	}
	defer resp.Body.Close()
	// GreyNoise returns 404 for an address it has no RIOT record for at
	// all -- that is a real, valid answer ("not known-benign"), not a
	// failure to report or fail-open/closed over.
	if resp.StatusCode == http.StatusNotFound {
		return riotResult{Riot: false}, nil
	}
	if resp.StatusCode >= 300 {
		return riotResult{}, fmt.Errorf("greynoise: HTTP %d", resp.StatusCode)
	}
	var out riotResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return riotResult{}, err
	}
	return out, nil
}

type greynoiseCacheRow struct {
	benign bool
	reason string
}

func (s *store) ensureGreynoiseTable() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS greynoise_cache (
			ip TEXT NOT NULL PRIMARY KEY,
			benign INTEGER NOT NULL,
			reason TEXT NOT NULL,
			checked_at INTEGER NOT NULL
		)`)
	return err
}

// greynoiseCacheGet returns the cached row for ip, whether one was found at
// all, and whether it's past cacheTTL (a stale-but-present row is still
// returned -- benign() decides what to do with staleness, this just reports
// it).
func (s *store) greynoiseCacheGet(ip string, cacheTTL time.Duration) (row greynoiseCacheRow, found bool, stale bool, err error) {
	var benignInt int
	var checkedAt int64
	err = s.db.QueryRow(
		`SELECT benign, reason, checked_at FROM greynoise_cache WHERE ip = ?`, ip,
	).Scan(&benignInt, &row.reason, &checkedAt)
	if err == sql.ErrNoRows {
		return greynoiseCacheRow{}, false, false, nil
	}
	if err != nil {
		return greynoiseCacheRow{}, false, false, err
	}
	row.benign = benignInt != 0
	stale = time.Since(time.Unix(checkedAt, 0)) >= cacheTTL
	return row, true, stale, nil
}

func (s *store) greynoiseCacheSet(ip string, benign bool, reason string, cacheMax int) error {
	benignInt := 0
	if benign {
		benignInt = 1
	}
	if _, err := s.db.Exec(`
		INSERT INTO greynoise_cache (ip, benign, reason, checked_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (ip) DO UPDATE SET benign = excluded.benign, reason = excluded.reason, checked_at = excluded.checked_at`,
		ip, benignInt, reason, time.Now().Unix(),
	); err != nil {
		return err
	}
	return s.pruneGreynoiseCache(cacheMax)
}

// pruneGreynoiseCache bounds total cache rows (the plan doc's "bounded
// retention"): once over cacheMax, delete the oldest rows down to the cap.
// Cheap to run on every write since it only fires the DELETE when actually
// over the limit.
func (s *store) pruneGreynoiseCache(cacheMax int) error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM greynoise_cache`).Scan(&count); err != nil {
		return err
	}
	if count <= cacheMax {
		return nil
	}
	_, err := s.db.Exec(`
		DELETE FROM greynoise_cache WHERE ip IN (
			SELECT ip FROM greynoise_cache ORDER BY checked_at ASC LIMIT ?
		)`, count-cacheMax)
	return err
}
