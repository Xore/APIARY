// ip-enrichment-worker (#38): moves the portbridge via_port -> real attacker
// IP join from dashboard read-time to ingest time, so every dashboard
// instance reading the same Elasticsearch store sees an already-correct
// src_ip with no per-instance join of its own -- the design task (#37)
// decided ingest-time enrichment + live ES aggregations, and this is the
// enrichment half.
//
// Scope: cowrie, dionaea, every conpot persona, dns-honeypot, and
// cisco-asa-honeypot's IKE side -- the sensors that aren't PROXY-protocol
// wrapped and so only ever see the tunnel peer address (10.8.0.1), never
// the real attacker IP, in their own raw log. cisco-asa-honeypot's own
// WebVPN/HTTPS side, dnp3-honeypot, and dicompot already get the real IP
// directly via PROXY protocol and need no rewriting; neither do
// multipot/tanner/http-honeypot/citrix-honeypot/rdp-honeypot, but #1217
// watches those five anyway, purely for canonical.go's field normalization
// (creds/commands/fingerprints) -- see canonical.go's own doc comment.
//
// dionaea_incident.json (#623) is also enriched, but differently: it
// carries no top-level src_ip at all, so enrichDionaeaIncidentLine walks
// the whole record looking for any embedded {remote_ip, remote_port, ...}
// object -- confirmed live that every incident origin nests this exact
// shape somewhere in "data", under a key that varies by origin ("connection"
// for most, "child"/"parent" for dionaea.connection.link) -- and rewrites
// each one independently rather than a single flat field.
//
// Design: tails each affected sensor's raw log file, and for any line whose
// src_ip is the tunnel peer address, looks up the real IP by that
// connection's src_port against portbridge's own connection log (via_port),
// exactly the join dashboard/classify.go's buildViaMap/viaLookup already do
// -- ported here, not shared, since dashboard and this worker are separate
// Go modules with no shared package today. A resolved line's src_ip is
// rewritten in place; everything else (already-correct traffic, a
// genuinely unattributable connection, an unresolved line still within its
// retry window) passes through unchanged. The rewritten stream is written
// to its own file under OUT_DIR, which Filebeat is configured to tail
// *instead of* the raw file for these five sensors -- see
// analysis/filebeat.yml's honeypot-json input.
package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func getenvDuration(k string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// source is one raw sensor log file this worker watches, plus where its
// rewritten output and its own persisted read-offset live.
type source struct {
	name      string
	input     string
	output    string
	statePath string
	queue     pendingQueue
	enrich    enrichFunc
	stats     sourceStats
}

// sourceStats is a DEBUG-temporary (#1206) per-source resolution counter,
// logged periodically so a live miss-rate regression like #1206's
// near-100% cowrie/dns-honeypot failure is visible without guessing from
// Elasticsearch after the fact. Counts reset each log interval, not
// cumulative -- a snapshot of "what happened in the last N seconds", which
// is what matters for spotting a live regression.
type sourceStats struct {
	attempted     atomic.Int64 // lines whose src_ip was the tunnel peer (join was attempted at all)
	resolvedFirst atomic.Int64 // resolved on the first attempt
	resolvedRetry atomic.Int64 // resolved on a pendingQueue retry
	timedOut      atomic.Int64 // never resolved within PENDING_TIMEOUT
}

// discoverSources finds every input file this worker is responsible for.
// cowrie/dionaea/dns-honeypot/cisco-asa-honeypot each write exactly one
// well-known file; conpot's every persona writes to its own subdirectory
// but always under the literal filename "conpot.json", so those are
// discovered by glob and namespaced by subdirectory in the output.
func discoverSources(logsDir, outDir, stateDir string) []*source {
	var out []*source
	add := func(name, input string, enrich enrichFunc) {
		out = append(out, &source{
			name:      name,
			input:     input,
			output:    filepath.Join(outDir, name+".json"),
			statePath: filepath.Join(stateDir, name+".offset"),
			enrich:    enrich,
		})
	}

	add("cowrie", filepath.Join(logsDir, "cowrie", "cowrie.json"), enrichLine)
	add("dionaea", filepath.Join(logsDir, "dionaea", "dionaea.json"), enrichLine)
	add("dns-honeypot", filepath.Join(logsDir, "dns-honeypot", "dns-honeypot.json"), enrichLine)
	add("cisco-asa-honeypot", filepath.Join(logsDir, "cisco-asa-honeypot", "cisco-asa-honeypot.json"), enrichLine)
	// #623: dionaea_incident.json carries no top-level src_ip at all (the
	// real signal is buried in "data", under a key that varies by incident
	// origin) -- this needed its own enrich function (enrichDionaeaIncidentLine),
	// not enrichLine's flat single-field rewrite. See analysis/filebeat.yml's
	// dionaea-incidents-raw-v1 input, which now tails this enriched output
	// instead of the raw file, the same "enriched supersedes raw" pattern
	// the other five sources already established.
	add("dionaea-incident", filepath.Join(logsDir, "dionaea", "dionaea_incident.json"), enrichDionaeaIncidentLine)

	// #1217: field-normalization-only sources -- these five already carry
	// the real attacker IP via PROXY protocol (never the tunnel peer
	// address), so enrichLine's src_ip join is always a no-op for them;
	// they're watched solely so canonical.go's per-sensor promotion runs
	// on their lines too. Filenames confirmed live against the homeserver
	// (2026-08-12), not just each sensor's own docker-compose LOG_FILE/
	// volume declaration -- http-honeypot's container is named
	// "http-honeypot" but its own log file is "http.json", not
	// "http-honeypot.json".
	add("multipot", filepath.Join(logsDir, "multipot", "multipot.json"), enrichLine)
	add("tanner", filepath.Join(logsDir, "tanner", "tanner_report.json"), enrichLine)
	add("http-honeypot", filepath.Join(logsDir, "http-honeypot", "http.json"), enrichLine)
	add("citrix-honeypot", filepath.Join(logsDir, "citrix-honeypot", "citrix-honeypot.json"), enrichLine)
	add("rdp-honeypot", filepath.Join(logsDir, "rdp-honeypot", "rdp-honeypot.json"), enrichLine)

	conpotFiles, _ := filepath.Glob(filepath.Join(logsDir, "conpot*", "conpot.json"))
	for _, f := range conpotFiles {
		persona := filepath.Base(filepath.Dir(f)) // "conpot", "conpot-s7-1200", ...
		add(persona, f, enrichLine)
	}

	return out
}

func main() {
	logsDir := getenv("LOGS_DIR", "/logs")
	outDir := getenv("OUT_DIR", "/logs/enriched")
	stateDir := getenv("STATE_DIR", "/state/ip-enrichment-worker")
	refresh := getenvDuration("REFRESH_INTERVAL", 2*time.Second)
	pendingTimeout := getenvDuration("PENDING_TIMEOUT", 5*time.Second)

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		log.Fatalf("ip-enrichment-worker: create OUT_DIR %s: %v", outDir, err)
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		log.Fatalf("ip-enrichment-worker: create STATE_DIR %s: %v", stateDir, err)
	}

	sources := discoverSources(logsDir, outDir, stateDir)
	if len(sources) == 0 {
		log.Fatalf("ip-enrichment-worker: no input sources found under %s", logsDir)
	}
	for _, s := range sources {
		log.Printf("ip-enrichment-worker: watching %s -> %s", s.input, s.output)
		if _, ok := loadOffset(s.statePath); !ok {
			// First run for this source: start at EOF rather than walking
			// its full history -- see the package doc comment for why.
			if st, err := os.Stat(s.input); err == nil {
				saveOffset(s.statePath, st.Size())
			}
		}
	}

	viaBuilder := newViaMapBuilder(filepath.Join(logsDir, "portbridge"))
	var vm atomic.Pointer[viaMap]
	initial := viaBuilder.refresh()
	vm.Store(&initial)

	var tftpVM atomic.Pointer[viaMap]
	initialTftp := buildTftpSessionMap(logsDir)
	tftpVM.Store(&initialTftp)

	go func() {
		for range time.Tick(refresh) {
			m := viaBuilder.refresh()
			vm.Store(&m)
			t := buildTftpSessionMap(logsDir)
			tftpVM.Store(&t)
		}
	}()

	go logStats(sources, 30*time.Second)

	done := make(chan struct{})
	for _, s := range sources {
		go runSource(s, &vm, &tftpVM, refresh, pendingTimeout)
	}
	<-done // runs forever; process supervision (docker restart policy) handles crashes
}

// logStats prints each source's tunnel-peer-join resolution counts once per
// interval, then resets them -- a snapshot of the last interval, not a
// cumulative total (see sourceStats). #1206 debug instrumentation: the
// worker previously logged nothing after startup, making a live resolution-
// rate regression invisible short of querying Elasticsearch after the fact.
func logStats(sources []*source, interval time.Duration) {
	for range time.Tick(interval) {
		for _, s := range sources {
			attempted := s.stats.attempted.Swap(0)
			first := s.stats.resolvedFirst.Swap(0)
			retry := s.stats.resolvedRetry.Swap(0)
			timedOut := s.stats.timedOut.Swap(0)
			if attempted == 0 && first == 0 {
				continue // nothing seen for this source this interval
			}
			log.Printf("ip-enrichment-worker: %s: tunnel-peer joins attempted=%d resolved_first=%d resolved_retry=%d timed_out=%d",
				s.name, attempted, first, retry, timedOut)
		}
	}
}

func runSource(s *source, vm, tftpVM *atomic.Pointer[viaMap], refresh, pendingTimeout time.Duration) {
	out, err := os.OpenFile(s.output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("ip-enrichment-worker: %s: open output %s: %v", s.name, s.output, err)
		return
	}
	defer out.Close()

	tunnelPeerMarker := []byte(`"src_ip":"` + tunnelPeerIP + `"`)

	// offset is tracked in memory across ticks rather than reloaded from
	// disk every time: reloading from disk on every tick means a single
	// transient saveOffset failure is invisible, and the very next tick
	// re-reads (and re-enriches, re-appends) the same already-written
	// range from disk again -- and keeps doing so on every subsequent tick
	// until the state write happens to succeed again.
	offset, _ := loadOffset(s.statePath)

	for range time.Tick(refresh) {
		offset = processSourceTick(s, vm, tftpVM, pendingTimeout, out, tunnelPeerMarker, offset, time.Now())
	}
}

// processSourceTick runs one read/enrich/write cycle for a source and
// returns the offset that should be used on the next tick: newOffset on
// success, or the offset passed in, unchanged, if either the write or the
// offset persist failed -- so the same input range is retried next tick
// instead of being silently skipped (a failed write) or repeatedly
// re-written (a failed persist with the in-memory offset already moved on).
func processSourceTick(s *source, vm, tftpVM *atomic.Pointer[viaMap], pendingTimeout time.Duration, out *os.File, tunnelPeerMarker []byte, offset int64, now time.Time) int64 {
	lines, newOffset, err := readNewLines(s.input, offset)
	if err != nil {
		return offset // sensor container restarting, file briefly absent, etc. -- retry next tick
	}
	var ready [][]byte
	for _, line := range lines {
		isTunnelPeer := bytes.Contains(line, tunnelPeerMarker) // #1206 debug stat only
		enriched, resolved := s.enrich(line, *vm.Load(), *tftpVM.Load(), s.name)
		if resolved {
			if isTunnelPeer {
				s.stats.resolvedFirst.Add(1)
			}
			ready = append(ready, enriched)
		} else {
			s.stats.attempted.Add(1)
			s.queue.add(line, pendingTimeout, now)
		}
	}
	drained := s.queue.drain(*vm.Load(), *tftpVM.Load(), now, s.name, s.enrich)
	for _, out := range drained {
		if bytes.Contains(out, tunnelPeerMarker) {
			s.stats.timedOut.Add(1)
		} else {
			s.stats.resolvedRetry.Add(1)
		}
	}
	ready = append(ready, drained...)
	if !writeLines(out, s.name, s.output, ready) {
		return offset // don't advance/persist offset over a batch that failed to write
	}
	if newOffset == offset {
		return offset
	}
	if err := saveOffset(s.statePath, newOffset); err != nil {
		log.Printf("ip-enrichment-worker: %s: save offset %s: %v", s.name, s.statePath, err)
		return offset // keep the in-memory offset unchanged; retry the same range next tick
	}
	return newOffset
}

// writeLines reports whether every line was written successfully. On a
// partial/failed write the caller must not advance/persist the input
// offset, or the unwritten lines are gone for good -- readNewLines would
// resume past them on the next tick.
func writeLines(out *os.File, name, path string, lines [][]byte) bool {
	for _, line := range lines {
		if _, err := out.Write(line); err != nil {
			log.Printf("ip-enrichment-worker: %s: write output %s: %v", name, path, err)
			return false
		}
		if _, err := out.Write([]byte("\n")); err != nil {
			log.Printf("ip-enrichment-worker: %s: write output %s: %v", name, path, err)
			return false
		}
	}
	return true
}
