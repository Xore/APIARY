package main

import (
	"regexp"
	"strings"
)

// attack_sequences.go (#1291): classify.go's multipot handler is fully
// protocol-generic -- every command rides in as an equally-weighted event
// row, tied together only by ev.session. Some short command sequences are,
// together, a well-known, severe attack technique that no single command in
// isolation reveals -- a live session issuing CONFIG SET dir/dbfilename,
// then SET-ing an SSH public key, then BGSAVE is the textbook unauthenticated-
// Redis-to-SSH-RCE technique (redirect the RDB save path into ~/.ssh, name
// the save file authorized_keys, write the attacker's own key as a value,
// force a save), but shows as four unremarkable Redis commands. Deliberately
// a small, curated, high-confidence pattern list (starting with the two
// found live in the issue's own investigation) rather than an ambitious
// general-purpose sequence classifier -- see the issue's own scope note.

// attackSequence is one recognized multi-step pattern match on a session.
type attackSequence struct {
	Name     string
	Severity string // "critical" or "high" -- same badge vocabulary #1290 established
	Summary  string
}

var (
	redisConfigDirRe        = regexp.MustCompile(`(?i)^config\s+set\s+dir\b`)
	redisConfigDBFilenameRe = regexp.MustCompile(`(?i)^config\s+set\s+dbfilename\b`)
	redisSSHKeyValueRe      = regexp.MustCompile(`(?i)ssh-(rsa|dss|ed25519|ecdsa-[a-z0-9-]+)\s`)
	redisBGSaveRe           = regexp.MustCompile(`(?i)^bgsave\b`)
)

// detectRedisSSHKeyInjection looks for the four-step sequence as an ordered
// subsequence (not necessarily contiguous, "reasonable reordering/
// interleaving" per the issue) across every redis command in the session,
// in session order. cmds is already chronological (sessionData reverses
// s.getEvents()'s newest-first order before building Events).
func detectRedisSSHKeyInjection(cmds []string) bool {
	step := 0
	matchers := []*regexp.Regexp{redisConfigDirRe, redisConfigDBFilenameRe, redisSSHKeyValueRe, redisBGSaveRe}
	for _, cmd := range cmds {
		if step >= len(matchers) {
			break
		}
		if matchers[step].MatchString(cmd) {
			step++
		}
	}
	return step == len(matchers)
}

// adbReconIndicators are the recon commands a botnet-recruitment scanner
// chains in one shell: invocation to decide whether a device is worth
// infecting (architecture, CPU count, memory, privilege level, device
// model) -- confirmed live: "shell:uname -m; nproc; cat /proc/meminfo |
// grep MemTotal; id -u; getprop ro.product.model;". Requiring 3+ of 5
// guards against a single legitimate-looking `uname` probe alone counting
// as a full recon fingerprint.
var adbReconIndicators = []string{"uname", "nproc", "meminfo", "id -u", "getprop"}

const adbReconMinIndicators = 3

func detectADBReconFingerprint(cmds []string) bool {
	for _, cmd := range cmds {
		lower := strings.ToLower(cmd)
		hits := 0
		for _, indicator := range adbReconIndicators {
			if strings.Contains(lower, indicator) {
				hits++
			}
		}
		if hits >= adbReconMinIndicators {
			return true
		}
	}
	return false
}

// detectAttackSequences runs every curated pattern against one session's
// chronological events and returns every match. events must already be in
// chronological (oldest-first) order.
func detectAttackSequences(events []storedEvent) []attackSequence {
	var redisCmds, adbCmds []string
	for _, ev := range events {
		if ev.Sensor != "multipot" || ev.Command == "" {
			continue
		}
		switch ev.Proto {
		case "redis":
			redisCmds = append(redisCmds, ev.Command)
		case "adb":
			adbCmds = append(adbCmds, ev.Command)
		}
	}

	var out []attackSequence
	if detectRedisSSHKeyInjection(redisCmds) {
		out = append(out, attackSequence{
			Name:     "Unauthenticated Redis-to-SSH RCE (SSH key injection)",
			Severity: "critical",
			Summary:  "CONFIG SET dir/dbfilename redirected the RDB save path into ~/.ssh, an attacker SSH public key was written as a value, then BGSAVE forced the save -- the result is passwordless SSH access on any real Redis instance configured this permissively.",
		})
	}
	if detectADBReconFingerprint(adbCmds) {
		out = append(out, attackSequence{
			Name:     "ADB botnet-recruitment device fingerprinting",
			Severity: "high",
			Summary:  "A single shell invocation chained architecture, CPU count, memory, privilege level, and device model checks -- the recon pattern Mirai-family and cryptomining botnet scanners run before deciding whether a device is worth infecting.",
		})
	}
	return out
}
