// reporter — tails this stack's honeypot sensor logs (and Suricata's
// eve.json, #69) and reports attacker IPs to AbuseIPDB and Blocklist.de.
// Phase 1 of docs/ip-reporting-plan.md (#68): file tailing, whitelist/CIDR
// filtering, SQLite dedup + cooldowns, structured audit logs, dry-run by
// default.
//
// Reporting is outbound and irreversible -- an abuse report cannot be
// unsent, and it names a third party's address from this stack. Per
// WORK-LEDGER.md rule 7, production reporting requires separate explicit
// authorization after a sampled false-positive review of dry-run output;
// this binary ships dry-run by default and stays that way until an
// operator explicitly sets REPORTER_LIVE=1 with a real API key. See
// report.go's newSender for the exact gate, and dryrun_test.go for the
// no-network proof that the gate actually holds.
package main

import (
	"log"
	"os"
	"strconv"
	"time"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getenvBool(k string) bool {
	return os.Getenv(k) == "1" || os.Getenv(k) == "true"
}

func main() {
	logPaths := map[string]string{
		"cowrie":        getenv("COWRIE_LOG", "/logs/cowrie/cowrie.json"),
		"dionaea":       getenv("DIONAEA_LOG", "/logs/dionaea/dionaea.json"),
		"multipot":      getenv("MULTIPOT_LOG", "/logs/multipot/multipot.json"),
		"http-honeypot": getenv("HTTP_HONEYPOT_LOG", "/logs/http-honeypot/http.json"),
		"api-honeypot":  getenv("API_HONEYPOT_LOG", "/logs/api-honeypot/api.json"),
		"conpot":        getenv("CONPOT_LOG", "/logs/conpot/conpot.json"),
		"dnp3":          getenv("DNP3_LOG", "/logs/dnp3/dnp3.json"),
	}
	// Suricata's eve.json is not a fixed path: it rotates hourly into a new
	// eve-<timestamp>.json file (vps/suricata/suricata.yaml), so it needs
	// tailer.pollGlob rather than a plain poll (#69).
	suricataGlob := getenv("SURICATA_LOG_GLOB", "/logs/suricata/eve-*.json")

	dataDir := getenv("REPORTER_DATA_DIR", "/data")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		log.Fatalf("reporter: creating data dir: %v", err)
	}

	st, err := openStore(dataDir + "/reported.db")
	if err != nil {
		log.Fatalf("reporter: opening store: %v", err)
	}
	defer st.Close()

	wl, err := loadWhitelist(getenv("REPORTER_WHITELIST", "/config/whitelist.txt"))
	if err != nil {
		log.Fatalf("reporter: loading whitelist: %v", err)
	}

	auditPath := getenv("REPORTER_AUDIT_LOG", dataDir+"/audit.json")
	auditFile, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		log.Fatalf("reporter: opening audit log: %v", err)
	}
	defer auditFile.Close()
	audit := newAuditLog(auditFile)

	live := getenvBool("REPORTER_LIVE")
	apiKey := os.Getenv("ABUSEIPDB_API_KEY")
	send := newSender(live, apiKey, audit)
	if live && apiKey == "" {
		log.Print("reporter: REPORTER_LIVE=1 but ABUSEIPDB_API_KEY is empty -- staying in dry-run")
	}
	log.Printf("reporter: live=%v (effective abuseipdb sender is live=%v)", live, live && apiKey != "")

	bdEmail := os.Getenv("BLOCKLISTDE_SENDER")
	bdAPIKey := os.Getenv("BLOCKLISTDE_API_KEY")
	sendBD := newBlocklistDeSender(live, bdEmail, bdAPIKey, audit)
	if live && (bdEmail == "" || bdAPIKey == "") {
		log.Print("reporter: REPORTER_LIVE=1 but BLOCKLISTDE_SENDER/BLOCKLISTDE_API_KEY is incomplete -- staying in dry-run for blocklistde")
	}
	log.Printf("reporter: live=%v (effective blocklistde sender is live=%v)", live, live && bdEmail != "" && bdAPIKey != "")

	cooldown := time.Duration(getenvInt("REPORTER_COOLDOWN_HOURS", 24)) * time.Hour
	minHits := getenvInt("REPORTER_MIN_EVENTS", 3)

	// GreyNoise RIOT reputation guard (#153, Phase 3) -- optional. Unset
	// GREYNOISE_ENABLED (or leaving it at its default "0") disables the
	// check entirely rather than running it half-configured: a checker
	// with no API key still works against RIOT's community tier, but an
	// operator who hasn't thought about it yet gets the old Phase 1/2
	// behavior, not a silently-degraded new one.
	var gn *greynoiseChecker
	if getenvBool("GREYNOISE_ENABLED") {
		failOpen := getenv("GREYNOISE_FAIL_MODE", "open") != "closed"
		cacheTTL := time.Duration(getenvInt("GREYNOISE_CACHE_HOURS", 24)) * time.Hour
		minCallGap := time.Duration(getenvInt("GREYNOISE_MIN_CALL_MS", 200)) * time.Millisecond
		cacheMax := getenvInt("GREYNOISE_CACHE_MAX", 50_000)
		gn = newGreynoiseChecker(st, getenv("GREYNOISE_BASE_URL", ""), os.Getenv("GREYNOISE_API_KEY"), failOpen, cacheTTL, minCallGap, cacheMax)
		log.Printf("reporter: GreyNoise RIOT check enabled (fail_open=%v, cache_ttl=%s)", failOpen, cacheTTL)
	}

	proc := newProcessor(wl, gn, st, send, sendBD, audit, cooldown, minHits)

	go writeMetricsLoop(dataDir, time.Duration(getenvInt("REPORTER_METRICS_SECONDS", 60))*time.Second)

	tailer := newTailer(st)
	interval := time.Duration(getenvInt("REPORTER_POLL_SECONDS", 30)) * time.Second

	// #1980: a panic anywhere in the poll pass (hostile log line, ES shape
	// drift) is logged with its stack and retried next poll; it no longer
	// stops abuse reporting or freezes dedup state.
	runLoop("reporter", interval, func() {
		for sensor, path := range logPaths {
			sensor := sensor
			if err := tailer.poll(path, func(line []byte) { proc.handle(sensor, line) }); err != nil {
				log.Printf("reporter: polling %s (%s): %v", sensor, path, err)
			}
		}
		if err := tailer.pollGlob(suricataGlob, func(line []byte) { proc.handle("suricata", line) }); err != nil {
			log.Printf("reporter: polling suricata (%s): %v", suricataGlob, err)
		}
	})
}
