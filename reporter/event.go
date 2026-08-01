package main

import (
	"encoding/json"
	"strings"
	"time"
)

// event is one normalized hit read from a sensor's JSON log line. Only the
// fields the reporter actually needs -- this is not a general-purpose event
// model like dashboard/classify.go's storedEvent, it exists to answer one
// question per line: "is there a reportable source IP here, and what kind of
// abuse does it look like."
type event struct {
	IP     string
	Sensor string
	Kind   string // "login", "command", "download", "scan" -- feeds category mapping
	When   time.Time
}

// ipOf hunts for a source address across the field names honeypot sensors
// actually use. Mirrors dashboard/classify.go's ipOf -- same sensors, same
// inconsistent field naming, kept as a separate copy rather than a shared
// import because this module is standalone by the same convention every
// other Go service in this repo already follows (multipot, http-honeypot,
// portbridge each vendor their own small normalizer rather than sharing one).
func ipOf(e map[string]any) string {
	for _, k := range []string{"src_ip", "remote_ip", "peer_ip", "client_ip", "ip"} {
		if v, _ := e[k].(string); v != "" {
			return v
		}
	}
	// conpot: "remote": ["1.2.3.4", 51234]
	if r, ok := e["remote"].([]any); ok && len(r) > 0 {
		if v, _ := r[0].(string); v != "" {
			return v
		}
	}
	return ""
}

// kindOf classifies a raw event line into the coarse categories categorize.go
// maps to AbuseIPDB codes. Deliberately conservative: an event that doesn't
// match anything recognizable comes back "" and is skipped by the caller
// rather than guessed at -- an unreported real attacker is recoverable, a
// wrongly-categorized report is not.
func kindOf(e map[string]any) string {
	eventid, _ := e["eventid"].(string)
	switch {
	case eventid != "":
		switch {
		case strings.Contains(eventid, "login"):
			return "login"
		case strings.Contains(eventid, "command") || strings.Contains(eventid, "session.input"):
			return "command"
		case strings.Contains(eventid, "file_download") || strings.Contains(eventid, "file_upload"):
			return "download"
		}
	}
	if _, ok := e["shasum"]; ok {
		return "download"
	}
	if _, ok := e["username"]; ok {
		return "login"
	}
	if _, ok := e["path"]; ok {
		return "scan"
	}
	return ""
}

// timeOf parses a sensor's own timestamp field, falling back to "now" (the
// moment this reporter observed the line) rather than a zero time -- a
// missing/unparseable timestamp is not a reason to drop an otherwise valid
// report, just a reason not to trust the sensor's own clock for it.
func timeOf(e map[string]any) time.Time {
	for _, k := range []string{"time", "timestamp"} {
		v, _ := e[k].(string)
		if v == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, v); err == nil {
				return t
			}
		}
	}
	return time.Now().UTC()
}

// parseEvent turns one raw JSON log line into an event, or ok=false if the
// line has no reportable source IP at all.
func parseEvent(sensor string, line []byte) (event, bool) {
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return event{}, false
	}
	ip := ipOf(raw)
	if ip == "" {
		return event{}, false
	}
	return event{IP: ip, Sensor: sensor, Kind: kindOf(raw), When: timeOf(raw)}, true
}
