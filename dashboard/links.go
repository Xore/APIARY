package main

import (
	"net/url"
	"strings"
	"time"
)

func eventsURL(v url.Values) string { return "/events?" + v.Encode() }

func investigationURL(base, kind, ip string, when time.Time) string {
	if base == "" || ip == "" {
		return ""
	}
	base = strings.TrimRight(base, "/")
	switch kind {
	case "arkime":
		return base + "/sessions?date=-1&expression=" + url.QueryEscape("ip == "+ip)
	case "evebox":
		// EveBox's SPA reads inbox searches from the URL fragment. A normal
		// server-side query path opens the shell but does not populate its
		// alert search field.
		return base + "/#/inbox?q=" + url.QueryEscape(ip)
	default:
		from, to := when.Add(-5*time.Minute).UTC().Format(time.RFC3339), when.Add(5*time.Minute).UTC().Format(time.RFC3339)
		return base + "/app/discover#/?_g=" + url.QueryEscape("(time:(from:'"+from+"',to:'"+to+"'))") + "&_a=" + url.QueryEscape("(query:(language:kuery,query:'"+ip+"'))")
	}
}

// linkRows attaches a single-param /events drill-down link to each row.
func linkRows(rows []kv, param string) []kv {
	for i := range rows {
		rows[i].Link = eventsURL(url.Values{param: {rows[i].Key}})
	}
	return rows
}

// credentialRows preserves the exact raw pair in the drill-down URL while
// making empty values explicit in the table instead of rendering a dangling
// separator that can be mistaken for a display bug.
func credentialRows(rows []kv) []kv {
	for i := range rows {
		raw := rows[i].Key
		rows[i].Link = eventsURL(url.Values{"cred": {raw}})
		user, pass, ok := strings.Cut(raw, " / ")
		if !ok {
			continue
		}
		if user == "" {
			user = "(empty)"
		}
		if pass == "" {
			pass = "(empty)"
		}
		rows[i].Key = user + " / " + pass
	}
	return rows
}

// validCredentialPair prevents protocol fields and command payloads from
// leaking into the login ranking when a sensor reuses username/password keys
// for non-authentication incident data.
func validCredentialPair(user, pass string) bool {
	if user == "" && pass == "" || len(user) > 128 || len(pass) > 512 {
		return false
	}
	for _, value := range []string{user, pass} {
		lower := strings.ToLower(value)
		if strings.ContainsAny(value, "\x00\r\n") || strings.Contains(lower, `\x00`) || strings.Contains(lower, `\u0000`) {
			return false
		}
	}
	if strings.ContainsAny(user, " \t/;|&<>") {
		return false
	}
	lowerPass := strings.ToLower(strings.TrimSpace(pass))
	for _, marker := range []string{"/bin/", "busybox", "linuxshell", "powershell", "cmd.exe"} {
		if strings.Contains(lowerPass, marker) {
			return false
		}
	}
	return true
}

// normalizeProtocol collapses implementation-specific service names into the
// protocol labels an operator expects. This also prevents one protocol from
// appearing as several separate rows.
func normalizeProtocol(proto string) string {
	p := strings.ToLower(strings.TrimSpace(proto))
	switch p {
	case "smbd":
		return "smb"
	case "mssqld", "tds":
		return "mssql"
	case "mysqld":
		return "mysql"
	case "mongod":
		return "mongodb"
	case "pptpd":
		return "pptp"
	case "sipcall", "sipsession":
		return "sip"
	case "httpd":
		return "http"
	case "ftpd":
		return "ftp"
	default:
		return p
	}
}

// isOperationalAlert identifies sensor/capture health findings that are useful
// in the event explorer but misleading in an attacker-focused alert ranking.
func isOperationalAlert(signature string) bool {
	s := strings.ToLower(strings.TrimSpace(signature))
	return strings.Contains(s, "truncated packet") || strings.HasPrefix(s, "suricata af-packet")
}

// asnRows keeps the human-readable organization while filtering on the exact
// numeric ASN embedded at the beginning of each aggregate key.
func asnRows(rows []kv) []kv {
	for i := range rows {
		asn := strings.TrimPrefix(strings.Fields(rows[i].Key)[0], "AS")
		rows[i].Link = eventsURL(url.Values{"asn": {asn}})
	}
	return rows
}

func fingerprintRows(counts map[string]int, n int) []kv {
	rows := topN(counts, n)
	for i := range rows {
		kind, value, ok := strings.Cut(rows[i].Key, "\x00")
		if !ok {
			value = rows[i].Key
		}
		if kind == "" {
			kind = "fingerprint"
		}
		rows[i].Key = kind + ": " + compactText(value, 76)
		rows[i].Title = value
		rows[i].Link = eventsURL(url.Values{"fingerprint": {value}})
	}
	return rows
}

func compactText(value string, limit int) string {
	runes := []rune(strings.TrimSpace(value))
	if limit < 2 || len(runes) <= limit {
		return string(runes)
	}
	return string(runes[:limit-1]) + "…"
}
