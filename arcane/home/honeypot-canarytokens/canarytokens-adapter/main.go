// canarytokens-adapter receives Canarytokens' own webhook alert (POSTed to
// whatever URL a token was created with) and writes it as a standard
// sensor JSON line under this repo's shared honeypot log convention, the
// same shape Filebeat already tails for every other sensor.
//
// This exists because Canarytokens itself never writes alert data to a
// file Filebeat can tail -- alerts only ever go out as webhook/Slack/email
// (confirmed directly against canarytokens/channel_output_webhook.py, see
// #1426's PR description). A webhook_url that doesn't match Slack/Discord/
// Google Chat/MS Teams's own URL shape (canarytokens/webhook_formatting.py's
// get_webhook_type) gets the "generic" payload format: a flat JSON object
// (TokenAlertDetailGeneric in canarytokens/models/common.py) with channel,
// token_type, src_ip, src_data, token, time, memo, manage_url,
// additional_data, public_domain. Every token this stack creates sets its
// webhook_url to this adapter, so every alert arrives in that shape.
//
// No ip-enrichment-worker wiring: unlike the portbridge-tunneled sensors,
// most Canarytokens alerts either carry the real toucher's IP directly
// (switchboard's own HTTP/DNS channels see real requests once #1427
// exposes them) or come from a third party's own report (e.g. AWS
// reporting who used an exposed key) -- there's no tunnel-peer address to
// join against a via_port map, so this adapter writes already-correct
// fields straight through.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// waitForMarker blocks until markerPath exists, polling every 3s. See #128.
func waitForMarker(markerPath string) {
	for {
		if _, err := os.Stat(markerPath); err == nil {
			return
		}
		time.Sleep(3 * time.Second)
	}
}

// canarytokensTimeLayout matches TokenAlertDetails.Config.json_encoders'
// own "%Y-%m-%d %H:%M:%S (UTC)" strftime format (canarytokens/models/common.py).
const canarytokensTimeLayout = "2006-01-02 15:04:05 (MST)"

type alertPayload struct {
	Channel        string         `json:"channel"`
	TokenType      string         `json:"token_type"`
	SrcIP          string         `json:"src_ip"`
	SrcData        map[string]any `json:"src_data"`
	Token          string         `json:"token"`
	Time           string         `json:"time"`
	Memo           string         `json:"memo"`
	ManageURL      string         `json:"manage_url"`
	AdditionalData map[string]any `json:"additional_data"`
	PublicDomain   string         `json:"public_domain"`
}

var (
	logMu   sync.Mutex
	logFile *os.File
	logPath string
	logSize int64
	logMax  int64
)

// rotateLog closes the current log file, renames it aside with a timestamp
// suffix, and reopens a fresh file at the original path -- #120's contract,
// ported from multipot's logger (see that package's rotate() for the full
// reasoning: Filebeat tracks by inode so a rename-then-reopen never loses a
// harvester). Callers must hold logMu.
func rotateLog() {
	if logFile == nil || logPath == "" {
		return
	}
	logFile.Close()
	target := logPath + "." + time.Now().UTC().Format("20060102-150405")
	if _, err := os.Stat(target); err == nil {
		for n := 2; ; n++ {
			candidate := fmt.Sprintf("%s.%d", target, n)
			if _, err := os.Stat(candidate); err != nil {
				target = candidate
				break
			}
		}
	}
	os.Rename(logPath, target)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		logFile = nil
		log.Printf("canarytokens-adapter: log file %q unavailable after rotation: %v", logPath, err)
		return
	}
	logFile = f
	logSize = 0
}

func getenvInt64(k string, def int64) int64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// buildEvent maps a webhook payload to this repo's shared sensor-log
// shape. now is the fallback timestamp used when p.Time doesn't parse
// against canarytokensTimeLayout (e.g. a malformed or absent value) --
// passed in rather than called internally so this stays a pure function.
func buildEvent(p alertPayload, now time.Time) map[string]any {
	ts := now.Format(time.RFC3339)
	if p.Time != "" {
		if parsed, err := time.Parse(canarytokensTimeLayout, p.Time); err == nil {
			ts = parsed.UTC().Format(time.RFC3339)
		}
	}
	return map[string]any{
		"sensor":          "canarytokens",
		"timestamp":       ts,
		"channel":         p.Channel,
		"token_type":      p.TokenType,
		"src_ip":          p.SrcIP,
		"src_data":        p.SrcData,
		"token":           p.Token,
		"memo":            p.Memo,
		"manage_url":      p.ManageURL,
		"additional_data": p.AdditionalData,
		"public_domain":   p.PublicDomain,
	}
}

func writeEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MiB cap
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var p alertPayload
	if err := json.Unmarshal(body, &p); err != nil {
		log.Printf("malformed webhook payload: %v", err)
		http.Error(w, "malformed json", http.StatusBadRequest)
		return
	}

	line, err := json.Marshal(buildEvent(p, time.Now().UTC()))
	if err != nil {
		log.Printf("marshal error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	logMu.Lock()
	if logMax > 0 && logSize >= logMax {
		rotateLog()
	}
	var werr error
	if logFile != nil {
		var n int
		n, werr = logFile.Write(append(line, '\n'))
		logSize += int64(n)
	}
	logMu.Unlock()
	if werr != nil {
		log.Printf("log write error: %v", werr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// %q, not %s, for every field below: all three ultimately trace back to
	// whoever tripped the token (Canarytokens' own webhook payload, not
	// validated before this point) -- a newline/control character in
	// token_type or src_ip could otherwise forge fake log lines. %q quotes
	// and escapes them the same way it already (correctly) did for memo.
	log.Printf("token fired: type=%q memo=%q src_ip=%q", p.TokenType, p.Memo, p.SrcIP)
	w.WriteHeader(http.StatusOK)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8090", 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		conn.Close()
		return
	}

	waitForMarker("/markers/log-init.done")

	path := getenv("LOG_PATH", "/var/log/honeypot/canarytokens.json")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("cannot open log file %s: %v", path, err)
	}
	logFile = f
	logPath = path
	logMax = getenvInt64("LOG_MAX_BYTES", 67108864)
	if st, err := f.Stat(); err == nil {
		logSize = st.Size()
	}

	addr := getenv("LISTEN_ADDR", ":8090")
	http.HandleFunc("/", writeEvent)
	log.Printf("canarytokens-adapter listening on %s, writing to %s", addr, logPath)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
