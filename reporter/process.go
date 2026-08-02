package main

import "time"

// processor is the decision pipeline every log line runs through: parse,
// whitelist, categorize, cooldown, then (dry-run or real) send. Every exit
// point before send() writes a "skipped" audit entry with why -- see
// auditLog's doc comment for why skips are logged, not just successes.
//
// AbuseIPDB and Blocklist.de (#69) are reported to independently: each has
// its own category/service mapping, its own cooldown/dedup row (keyed by
// service in the store), and its own sender. Both share the same whitelist
// check and the same in-memory min-hits counter -- the threshold exists to
// smooth out a single stray probe regardless of where it might get
// reported, not to gate one destination differently from the other.
type processor struct {
	wl       *whitelist
	st       *store
	send     sender
	sendBD   blocklistDeSender
	audit    *auditLog
	cooldown time.Duration
	minHits  int            // #ip-reporting-plan.md's false-positive mitigation: require >=N events before reporting
	hits     map[string]int // in-memory count of events seen this run, keyed by ip -- resets on restart, which is fine: the threshold exists to smooth out a single stray probe, not to survive restarts
}

func newProcessor(wl *whitelist, st *store, send sender, sendBD blocklistDeSender, audit *auditLog, cooldown time.Duration, minHits int) *processor {
	if minHits < 1 {
		minHits = 1
	}
	return &processor{wl: wl, st: st, send: send, sendBD: sendBD, audit: audit, cooldown: cooldown, minHits: minHits, hits: map[string]int{}}
}

func (p *processor) handle(sensor string, line []byte) {
	ev, ok := parseEvent(sensor, line)
	if !ok {
		return // no IP in this line at all -- not an audit-worthy skip, just noise (e.g. a lifecycle log line)
	}

	if blocked, reason := p.wl.blocked(ev.IP); blocked {
		p.audit.log(auditEntry{Action: "skipped", IP: ev.IP, Sensor: sensor, Reason: reason, At: ev.When})
		return
	}

	cats := categories(sensor, ev.Kind)
	bdService := blocklistDeService(sensor, ev.Kind)
	if len(cats) == 0 && bdService == "" {
		p.audit.log(auditEntry{Action: "skipped", IP: ev.IP, Sensor: sensor, Kind: ev.Kind, Reason: "uncategorized event", At: ev.When})
		return
	}

	p.hits[ev.IP]++
	if p.hits[ev.IP] < p.minHits {
		p.audit.log(auditEntry{Action: "skipped", IP: ev.IP, Sensor: sensor, Kind: ev.Kind, Reason: "below minimum event threshold", At: ev.When})
		return
	}

	if len(cats) > 0 {
		p.reportAbuseIPDB(ev, sensor, cats)
	}
	if bdService != "" {
		p.reportBlocklistDe(ev, sensor, bdService, line)
	}
}

func (p *processor) reportAbuseIPDB(ev event, sensor string, cats []int) {
	recent, err := p.st.recentlyReported(ev.IP, "abuseipdb", p.cooldown)
	if err != nil {
		p.audit.log(auditEntry{Action: "skipped", Service: "abuseipdb", IP: ev.IP, Sensor: sensor, Reason: "dedup lookup failed: " + err.Error(), At: ev.When})
		return
	}
	if recent {
		p.audit.log(auditEntry{Action: "skipped", Service: "abuseipdb", IP: ev.IP, Sensor: sensor, Kind: ev.Kind, Reason: "within cooldown window", At: ev.When})
		return
	}

	r := report{IP: ev.IP, Categories: cats, Sensor: sensor, Kind: ev.Kind, At: ev.When,
		Comment: "Honeypot detection: " + sensor + " " + ev.Kind}
	if _, err := p.send.send(r); err != nil {
		return // liveSender already audited the error itself
	}
	// Cooldown bookkeeping uses wall-clock now, not ev.When. recentlyReported
	// answers "did *this reporter* act on this IP within the window" -- a
	// question about when the report happened, not when the underlying
	// attack did. Storing ev.When here broke cooldown suppression on the
	// very first live run: a fresh reporter's first poll reads the entire
	// existing log backlog (days old), and "time since a 3-day-old
	// timestamp" is never less than a 24h window, so every event past the
	// minimum-hits threshold kept re-triggering would_report throughout the
	// whole backfill instead of deduping after the first one. Confirmed
	// live: 49,105 would_report entries out of ~330k processed lines on
	// first deploy, including exact-duplicate IP+event-time pairs.
	if err := p.st.markReported(ev.IP, "abuseipdb", ev.Kind, time.Now().UTC()); err != nil {
		p.audit.log(auditEntry{Action: "skipped", Service: "abuseipdb", IP: ev.IP, Sensor: sensor, Reason: "failed to record dedup state: " + err.Error(), At: ev.When})
	}
}

// reportBlocklistDe mirrors reportAbuseIPDB's shape exactly, against a
// separate "blocklistde" row in the same dedup store -- an IP inside its
// AbuseIPDB cooldown can still be reported to Blocklist.de (and vice versa),
// since they're independent services with independent rate limits.
func (p *processor) reportBlocklistDe(ev event, sensor, service string, rawLine []byte) {
	recent, err := p.st.recentlyReported(ev.IP, "blocklistde", p.cooldown)
	if err != nil {
		p.audit.log(auditEntry{Action: "skipped", Service: "blocklistde", IP: ev.IP, Sensor: sensor, Reason: "dedup lookup failed: " + err.Error(), At: ev.When})
		return
	}
	if recent {
		p.audit.log(auditEntry{Action: "skipped", Service: "blocklistde", IP: ev.IP, Sensor: sensor, Kind: ev.Kind, Reason: "within cooldown window", At: ev.When})
		return
	}

	r := blocklistDeReport{IP: ev.IP, Service: service, Sensor: sensor, Kind: ev.Kind, Logs: string(rawLine), At: ev.When}
	if _, err := p.sendBD.send(r); err != nil {
		return // liveBlocklistDeSender already audited the error itself
	}
	if err := p.st.markReported(ev.IP, "blocklistde", ev.Kind, time.Now().UTC()); err != nil {
		p.audit.log(auditEntry{Action: "skipped", Service: "blocklistde", IP: ev.IP, Sensor: sensor, Reason: "failed to record dedup state: " + err.Error(), At: ev.When})
	}
}
