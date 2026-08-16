package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ip_block.go closes #914: no dashboard action existed to manually block an
// IP despite confirmed-malicious IPs being surfaced (ioc_correlation.go's
// ConfirmedAtRuntime). See docs/dashboard-manual-ip-block-design.md for the
// full design decision this implements -- summarized in the comments below.

// ipBlockIndex is the dashboard-owned Elasticsearch index storing manual
// block state, keyed by the IP address itself (already a stable, unique
// key -- unlike ml_anomaly_ack.go's mlAnomalyAckIndex, no derived document
// ID is needed here). Same no-local-file-fallback posture as alertIndex
// (#494) and mlAnomalyAckIndex (#913): two dashboard instances must agree.
const ipBlockIndex = "dashboard-ip-block-v1"

type ipBlockRecord struct {
	IP        string
	Blocked   bool
	BlockedBy string    `json:",omitempty"`
	BlockedAt time.Time `json:",omitempty"`
	// ExpiresAt is optional (zero = no expiry, blocked until explicitly
	// unblocked). Set per-block, not a global policy -- an operator decides
	// case by case whether a given IP warrants a permanent block or a
	// time-boxed one.
	ExpiresAt time.Time `json:",omitempty"`
}

// Active accounts for expiry without a background sweep: an
// expired block is treated as not-blocked everywhere it's read (export,
// page display), computed fresh each time, the same "computed fresh on
// every call" approach ioc_correlation.go already uses. The record itself
// is left untouched until an operator acts on it again (re-block or
// explicit unblock) -- nothing silently rewrites Blocked to false.
func (r ipBlockRecord) Active() bool {
	return r.Blocked && (r.ExpiresAt.IsZero() || time.Now().Before(r.ExpiresAt))
}

// ipBlockManager is a direct structural copy of mlAnomalyAckManager (#913):
// thin, stateless, every method a live Elasticsearch round-trip, optimistic
// concurrency against errESConflict since two requests can race to toggle
// the same IP.
type ipBlockManager struct {
	es *esClient
}

// newIPBlockManager returns nil when es is nil (Elasticsearch not
// configured) -- every call site already treats a nil manager as "manual
// blocking disabled."
func newIPBlockManager(es *esClient) *ipBlockManager {
	if es == nil {
		return nil
	}
	return &ipBlockManager{es: es}
}

const ipBlockWriteRetries = 5

// block flips one IP's Blocked flag, retrying on a concurrent-write
// conflict. A never-seen IP is not a failure -- blocking it for the first
// time creates the record, mirroring mlAnomalyAckManager.acknowledge.
// expiresAt is only meaningful when blocked is true; zero means no expiry.
// Re-blocking an IP (already Blocked) still applies, so an operator can
// shorten/extend/clear an existing block's expiry without unblocking first
// -- that path does not early-return on r.Blocked == blocked the way a
// plain ack toggle would, since the expiry itself may be changing.
func (m *ipBlockManager) block(ip string, blocked bool, actor string, expiresAt time.Time) bool {
	for attempt := 0; attempt < ipBlockWriteRetries; attempt++ {
		hit, found, err := m.es.docGet(ipBlockIndex, ip)
		if err != nil {
			return false
		}
		var r ipBlockRecord
		create := !found
		seqNo, primaryTerm := int64(0), int64(0)
		if found {
			if json.Unmarshal(hit.Source, &r) != nil {
				return false
			}
			seqNo, primaryTerm = hit.SeqNo, hit.PrimaryTerm
		} else {
			r = ipBlockRecord{IP: ip}
		}
		if r.Blocked == blocked && r.ExpiresAt.Equal(expiresAt) {
			return true
		}
		r.Blocked = blocked
		if blocked {
			r.BlockedBy, r.BlockedAt, r.ExpiresAt = actor, time.Now(), expiresAt
		} else {
			r.BlockedBy, r.BlockedAt, r.ExpiresAt = "", time.Time{}, time.Time{}
		}
		body, err := json.Marshal(r)
		if err != nil {
			return false
		}
		err = m.es.docIndex(ipBlockIndex, ip, body, create, seqNo, primaryTerm)
		if err == nil {
			return true
		}
		if err != errESConflict {
			return false
		}
	}
	return false
}

// get returns the current record for ip, or a zero-value (Blocked: false)
// record when none exists yet.
func (m *ipBlockManager) get(ip string) ipBlockRecord {
	hit, found, err := m.es.docGet(ipBlockIndex, ip)
	if err != nil || !found {
		return ipBlockRecord{IP: ip}
	}
	var r ipBlockRecord
	if json.Unmarshal(hit.Source, &r) != nil {
		return ipBlockRecord{IP: ip}
	}
	return r
}

// blockedIPs returns every currently-blocked address, sorted, for
// serveManualBlackholeExport to render as the plain-text list
// portbridge-manual-blackhole-refresh.sh pulls. A non-nil error means the
// query itself failed (transport/ES error) -- distinct from a nil slice
// with a nil error, which means the index genuinely has zero active blocks
// right now (#1342): the caller must be able to tell an outage apart from
// "nothing is blocked".
func (m *ipBlockManager) blockedIPs() ([]string, error) {
	hits, err := m.es.docSearchAll(ipBlockIndex, 10000)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, hit := range hits {
		var r ipBlockRecord
		if json.Unmarshal(hit.Source, &r) == nil && r.Active() && net.ParseIP(r.IP) != nil {
			out = append(out, r.IP)
		}
	}
	sort.Strings(out)
	return out, nil
}

// serveManualBlackholeExport is GET /export/portbridge-manual-blackhole.txt
// -- the pull source for vps/portbridge-manual-blackhole-refresh.sh
// (docs/dashboard-manual-ip-block-design.md, decision 4). No admin auth on
// this handler, the same posture every other /export/*.csv GET already
// takes: access control is the network boundary (WireGuard-only
// reachability from the VPS at 10.8.0.2), not a second app-layer secret,
// and the data itself is no more sensitive than the maltrail feed it sits
// alongside on the VPS.
func (s *store) serveManualBlackholeExport(w http.ResponseWriter, r *http.Request) {
	if s.ipBlocks == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		return
	}
	ips, err := s.ipBlocks.blockedIPs()
	if err != nil {
		// A transient ES hiccup must not read as "operator cleared every
		// block" to the puller (#1342): distinguish an outage (5xx, keep
		// the existing rules) from a legitimately empty block list (200,
		// empty body) below.
		http.Error(w, "manual blackhole export unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, ip := range ips {
		fmt.Fprintln(w, ip)
	}
}

// serveIPBlockAction handles the form POST from ips.html's attacker-page
// block/unblock button -- a plain redirect-back form, matching
// serveMLAnomalyAck's own shape (#913): this page is otherwise fully
// server-rendered, so a JSON API plus client-side fetch would be new
// complexity this page doesn't otherwise have.
func (s *store) serveIPBlockAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	if !sameOriginRequest(r) {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	if s.ipBlocks == nil {
		http.Error(w, "manual IP blocking is not configured on this host", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxActionFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(r.FormValue("ip"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "invalid IP address", http.StatusBadRequest)
		return
	}
	// Any IP on /investigate/ip/{ip} may be blocked, not just IPs IOC
	// correlation has flagged confirmed-malicious -- decided explicitly
	// (docs/dashboard-manual-ip-block-design.md decision 1) rather than
	// gating on that signal: an operator investigating a specific attacker
	// is the actual judgment call here, not a proxy for it.
	blocked := r.FormValue("blocked") != "false"
	var expiresAt time.Time
	if blocked {
		if days := strings.TrimSpace(r.FormValue("expires_days")); days != "" {
			n, err := strconv.Atoi(days)
			if err != nil || n <= 0 {
				http.Error(w, "expires_days must be a positive integer, or omitted for no expiry", http.StatusBadRequest)
				return
			}
			expiresAt = time.Now().Add(time.Duration(n) * 24 * time.Hour)
		}
	}
	identity, _ := resolveIdentity(r)
	actor := identity.Username
	if actor == "" {
		actor = identity.Subject
	}
	if !s.ipBlocks.block(ip, blocked, actor, expiresAt) {
		http.Error(w, "block update failed", http.StatusInternalServerError)
		return
	}
	fallback := "/investigate/ip/" + ip
	target := fallback
	if parsed, ok := safeReturnPath(r.FormValue("return"), []string{"/investigate/ip/"}); ok {
		target = parsed.String()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
