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
// the real attacker IP, in their own raw log. Every other sensor (multipot,
// http-honeypot, tanner, dnp3-honeypot, dicompot, citrix-honeypot,
// cisco-asa-honeypot's own WebVPN/HTTPS side, rdp-honeypot) already gets
// the real IP directly via PROXY protocol and needs no rewriting here.
//
// NOT in this version's scope, deliberately: dionaea_incident.json (raw,
// unparsed message text per filebeat.yml's own comment on why -- rewriting
// an IP buried in free-text JSON would need real parsing, not a
// map[string]any field swap, and is a reasonable follow-up rather than
// something to rush into this pass).
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
}

// discoverSources finds every input file this worker is responsible for.
// cowrie/dionaea/dns-honeypot/cisco-asa-honeypot each write exactly one
// well-known file; conpot's every persona writes to its own subdirectory
// but always under the literal filename "conpot.json", so those are
// discovered by glob and namespaced by subdirectory in the output.
func discoverSources(logsDir, outDir, stateDir string) []*source {
	var out []*source
	add := func(name, input string) {
		out = append(out, &source{
			name:      name,
			input:     input,
			output:    filepath.Join(outDir, name+".json"),
			statePath: filepath.Join(stateDir, name+".offset"),
		})
	}

	add("cowrie", filepath.Join(logsDir, "cowrie", "cowrie.json"))
	add("dionaea", filepath.Join(logsDir, "dionaea", "dionaea.json"))
	add("dns-honeypot", filepath.Join(logsDir, "dns-honeypot", "dns-honeypot.json"))
	add("cisco-asa-honeypot", filepath.Join(logsDir, "cisco-asa-honeypot", "cisco-asa-honeypot.json"))

	conpotFiles, _ := filepath.Glob(filepath.Join(logsDir, "conpot*", "conpot.json"))
	for _, f := range conpotFiles {
		persona := filepath.Base(filepath.Dir(f)) // "conpot", "conpot-s7-1200", ...
		add(persona, f)
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

	var vm atomic.Pointer[viaMap]
	initial := buildViaMap(filepath.Join(logsDir, "portbridge"))
	vm.Store(&initial)

	go func() {
		for range time.Tick(refresh) {
			m := buildViaMap(filepath.Join(logsDir, "portbridge"))
			vm.Store(&m)
		}
	}()

	done := make(chan struct{})
	for _, s := range sources {
		go runSource(s, &vm, refresh, pendingTimeout)
	}
	<-done // runs forever; process supervision (docker restart policy) handles crashes
}

func runSource(s *source, vm *atomic.Pointer[viaMap], refresh, pendingTimeout time.Duration) {
	out, err := os.OpenFile(s.output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("ip-enrichment-worker: %s: open output %s: %v", s.name, s.output, err)
		return
	}
	defer out.Close()

	write := func(lines [][]byte) {
		for _, line := range lines {
			out.Write(line)
			out.Write([]byte("\n"))
		}
	}

	for range time.Tick(refresh) {
		offset, _ := loadOffset(s.statePath)
		lines, newOffset, err := readNewLines(s.input, offset)
		if err != nil {
			continue // sensor container restarting, file briefly absent, etc. -- retry next tick
		}
		now := time.Now()
		var ready [][]byte
		for _, line := range lines {
			enriched, resolved := enrichLine(line, *vm.Load())
			if resolved {
				ready = append(ready, enriched)
			} else {
				s.queue.add(line, pendingTimeout, now)
			}
		}
		ready = append(ready, s.queue.drain(*vm.Load(), now)...)
		write(ready)
		if newOffset != offset {
			saveOffset(s.statePath, newOffset)
		}
	}
}
