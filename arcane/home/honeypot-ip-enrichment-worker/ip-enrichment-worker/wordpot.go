package main

import (
	"encoding/json"
	"net"
	"regexp"
	"strconv"
)

// enrichWordpotLine handles wordpot.json. Two gaps, both closed by
// wordpot_patch.py (see that file's own doc comment) plus one closed
// here:
//
//  1. wordpot_patch.py's _JsonFormatter wraps every LOGGER call in
//     {"time","level","message"} -- "message" is whatever wordpot itself
//     already formatted (a fixed, known set of Python %-format templates
//     across views.py and its plugins, confirmed by actually running the
//     patched binary and inspecting real output, not assumed from source
//     alone). wordpotMessageRE below extracts the leading "ip:port"
//     wordpot_patch.py's port-preserving middleware adds, and the
//     per-template regexes below extract whatever structured fields that
//     specific message carries -- deterministic parsing of a fixed,
//     already-known template set, not new detection logic.
//  2. Nothing in the line names this repo's sensors at all -- upstream
//     doesn't know about that convention.
//
// Startup lines ("Loading conf file...", "Honeypot started on...", etc.)
// don't match wordpotMessageRE (no leading "ip:port") and pass through
// unresolved-but-unchanged, same as hellpot.go's non-per-request lines.
//
// Every wordpot event is HTTP by definition (it's a single-purpose WP/CMS
// decoy), so "protocol" is a constant, same reasoning as hellpot.go's own.
// No destination-port field: wordpot logs no listen-port of its own
// (confirmed directly -- every plugin/view only ever logs request.remote_addr
// plus request-specific detail), so like beelzebub/hellpot a wordpot
// event's dst_port cannot be recovered from the log line alone.
var wordpotMessageRE = regexp.MustCompile(`^(\S+):(\d+) (.+)$`)

var (
	wordpotLoginAttemptRE = regexp.MustCompile(`^tried to login with username (.*) and password (.*)$`)
	wordpotLoginProbeRE   = regexp.MustCompile(`^probed for the login page$`)
	wordpotAdminProbeRE   = regexp.MustCompile(`^probed for the admin panel with path: (.*)$`)
	wordpotPluginProbeRE  = regexp.MustCompile(`^probed for plugin "(.*)" with path: (.*)$`)
	wordpotThemeProbeRE   = regexp.MustCompile(`^probed for theme "(.*)" with path: (.*)$`)
	wordpotCommonFileRE   = regexp.MustCompile(`^probed for: (.*)$`)
	wordpotTimthumbRE     = regexp.MustCompile(`^probed for timthumb: (.*)$`)
	wordpotBackupsRE      = regexp.MustCompile(`^probed for recent-backups: (.*)$`)
	wordpotAuthorRE       = regexp.MustCompile(`^probed author page for user: (.*)$`)
)

// classifyWordpotMessage sets structured fields on e from a known wordpot
// message template, returning whether it actually changed anything (so
// callers processing an already-classified retry don't mark the line
// dirty over identical values).
func classifyWordpotMessage(e map[string]any, msg string) bool {
	set := func(k, v string) bool {
		if e[k] == v {
			return false
		}
		e[k] = v
		return true
	}
	switch {
	case wordpotLoginProbeRE.MatchString(msg):
		return set("path", "/wp-login.php")
	case wordpotLoginAttemptRE.MatchString(msg):
		m := wordpotLoginAttemptRE.FindStringSubmatch(msg)
		c1 := set("path", "/wp-login.php")
		c2 := set("username", m[1])
		c3 := set("password", m[2])
		return c1 || c2 || c3
	case wordpotAdminProbeRE.MatchString(msg):
		m := wordpotAdminProbeRE.FindStringSubmatch(msg)
		return set("path", "/wp-admin"+m[1])
	case wordpotPluginProbeRE.MatchString(msg):
		m := wordpotPluginProbeRE.FindStringSubmatch(msg)
		c1 := set("plugin", m[1])
		c2 := set("path", "/wp-content/plugins/"+m[1]+m[2])
		return c1 || c2
	case wordpotThemeProbeRE.MatchString(msg):
		m := wordpotThemeProbeRE.FindStringSubmatch(msg)
		c1 := set("theme", m[1])
		c2 := set("path", "/wp-content/themes/"+m[1]+m[2])
		return c1 || c2
	case wordpotTimthumbRE.MatchString(msg):
		return set("path", wordpotTimthumbRE.FindStringSubmatch(msg)[1])
	case wordpotBackupsRE.MatchString(msg):
		return set("path", wordpotBackupsRE.FindStringSubmatch(msg)[1])
	case wordpotAuthorRE.MatchString(msg):
		return set("username", wordpotAuthorRE.FindStringSubmatch(msg)[1])
	case wordpotCommonFileRE.MatchString(msg):
		return set("path", "/"+wordpotCommonFileRE.FindStringSubmatch(msg)[1])
	}
	return false
}

func enrichWordpotLine(line []byte, vm viaMap, tftpVM viaMap, persona string) (out []byte, resolved bool) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return line, true // unparseable: nothing to retry, pass through as-is
	}
	msg, ok := e["message"].(string)
	if !ok || msg == "" {
		return line, true // not a message-carrying line
	}
	m := wordpotMessageRE.FindStringSubmatch(msg)
	if m == nil {
		return line, true // a startup log ("Loading conf file...", etc.) -- no ip:port prefix, nothing to enrich
	}
	ip, portStr, rest := m[1], m[2], m[3]

	changed := false
	if e["sensor"] != "wordpot" {
		e["sensor"] = "wordpot"
		changed = true
	}
	if e["protocol"] != "HTTP" {
		e["protocol"] = "HTTP"
		changed = true
	}
	changed = classifyWordpotMessage(e, rest) || changed

	if ip != tunnelPeerIP {
		if e["src_ip"] != ip {
			e["src_ip"] = ip
			changed = true
		}
		return marshalIfChanged(line, e, changed), true // already correct (or genuinely unknown) -- not ours to touch further
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port == 0 {
		if e["src_ip"] != ip {
			e["src_ip"] = ip
			changed = true
		}
		return marshalIfChanged(line, e, changed), true // no src_port to join on -- nothing further to try
	}

	real, ok := vm[port]
	if !ok {
		if e["src_ip"] != ip {
			e["src_ip"] = ip
			changed = true
		}
		return marshalIfChanged(line, e, changed), false // via_port miss -- caller retries later
	}

	e["message"] = net.JoinHostPort(real, portStr) + " " + rest
	e["src_ip"] = real
	e["src_port"] = port
	return marshalIfChanged(line, e, true), true
}
