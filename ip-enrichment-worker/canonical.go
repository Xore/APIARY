package main

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// promoteCanonicalFields mirrors dashboard/classify.go's per-sensor field
// mapping for the aggregates dashboard/aggregate.go's rebuild() still
// computes in its own process every cycle (TopCreds, TopCommands,
// fingerprints, client version, payload hash) -- promoting them as flat
// canonical_* top-level keys at ingest time so a live Elasticsearch terms
// aggregation can eventually replace that in-process work. Wiring the
// dashboard to actually read these fields is #1202, not this (#1197): this
// only makes the data available.
//
// Scope: cowrie, dionaea (+ dionaea_incident.json), and cisco-asa-honeypot
// -- the sensor families this worker originally watched for IP resolution
// that also have a creds/command/fingerprint/client-version field in
// classify.go -- plus, as of #1217, multipot/tanner/http-honeypot/
// citrix-honeypot/rdp-honeypot, watched purely for field normalization (no
// IP-resolution role: they get the real attacker IP directly via PROXY
// protocol already, see main.go's discoverSources). dns-honeypot and every
// conpot persona are also watched here but classify.go sets none of these
// fields for them (conpot's own "request" field is deliberately excluded
// from commands -- see classify.go's #41 comment, ported as the same
// omission here, not an oversight), so there is nothing to promote for
// those two.
//
// Returns whether e was mutated, the same "did this change anything"
// signal fixConpotDestPort already returns, so callers can fold it into
// the same marshalIfChanged decision.
func promoteCanonicalFields(persona string, e map[string]any) bool {
	switch persona {
	case "cowrie":
		return promoteCowrieFields(e)
	case "dionaea":
		return promoteDionaeaFields(e)
	case "dionaea-incident":
		return promoteDionaeaIncidentFields(e)
	case "multipot":
		return promoteMultipotFields(e)
	case "citrix-honeypot":
		return promoteCitrixFields(e)
	case "rdp-honeypot":
		return promoteRDPFields(e)
	case "tanner", "http-honeypot":
		return promoteWebRequestFields(persona, e)
	case "cisco-asa-honeypot":
		return promoteCiscoAsaFields(e)
	}
	return false
}

// hashName matches a bare md5/sha1/sha256 hex hash -- ported from
// dashboard/util.go's own hashName, used identically here as a fallback
// when a download URL/path's basename is itself the hash (dionaea's
// capture-file naming convention).
var hashName = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)

// validCredentialPair prevents protocol fields and command payloads from
// leaking into the login ranking when a sensor reuses username/password
// keys for non-authentication incident data -- ported verbatim from
// dashboard/links.go so canonical_user/canonical_pass are only ever
// promoted when they'd actually count toward TopCreds today, keeping this
// worker's output in parity with what the dashboard currently computes.
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

func str(v any) string {
	s, _ := v.(string)
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// setCreds writes canonical_user/canonical_pass only when they'd pass
// dashboard/aggregate.go's own validCredentialPair gate -- matching
// TopCreds' exact semantics rather than promoting every raw
// username/password field regardless of shape.
func setCreds(e map[string]any, user, pass string) (changed bool) {
	if !validCredentialPair(user, pass) {
		return false
	}
	e["canonical_user"], e["canonical_pass"] = user, pass
	return true
}

func setFingerprint(e map[string]any, fingerprint, kind string) (changed bool) {
	if fingerprint == "" {
		return false
	}
	e["canonical_fingerprint"], e["canonical_fingerprint_kind"] = fingerprint, kind
	return true
}

// promoteCowrieFields mirrors classify.go's cowrie branch (dashboard/
// classify.go ~line 187) for exactly the fields TopCreds/TopCommands/
// fingerprints/client-version/payloads read: username/password on a login
// event (plus a pubkey fingerprint riding along on the same event),
// command text, SSH client version, HASSH/JA4/JA4H/pubkey fingerprints,
// and a download's payload hash.
func promoteCowrieFields(e map[string]any) bool {
	eid := str(e["eventid"])
	if !strings.HasPrefix(eid, "cowrie.") {
		return false
	}
	changed := false
	switch eid {
	case "cowrie.login.success", "cowrie.login.failed":
		if setCreds(e, str(e["username"]), str(e["password"])) {
			changed = true
		}
		if fp := str(e["fingerprint"]); fp != "" && setFingerprint(e, fp, "SSH pubkey") {
			changed = true
		}
	case "cowrie.command.input", "cowrie.command.failed", "cowrie.command.success", "cowrie.session.input":
		if cmd := str(e["input"]); cmd != "" {
			e["canonical_command"] = cmd
			changed = true
		}
	case "cowrie.client.version":
		if v := str(e["version"]); v != "" {
			e["canonical_client_version"] = v
			if setFingerprint(e, v, "SSH client") {
				changed = true
			}
			changed = true
		}
	case "cowrie.client.kex":
		if setFingerprint(e, str(e["hassh"]), "HASSH") {
			changed = true
		}
	case "cowrie.direct-tcpip.ja4":
		if setFingerprint(e, str(e["ja4"]), "JA4") {
			changed = true
		}
	case "cowrie.direct-tcpip.ja4h":
		if setFingerprint(e, str(e["ja4h"]), "JA4H") {
			changed = true
		}
	case "cowrie.client.fingerprint":
		if setFingerprint(e, str(e["fingerprint"]), "SSH pubkey") {
			changed = true
		}
	case "cowrie.session.file_download", "cowrie.session.file_upload", "cowrie.log.closed":
		if sha := str(e["shasum"]); sha != "" {
			e["canonical_shasum"] = sha
			changed = true
		}
	}
	return changed
}

// promoteDionaeaFields mirrors classify.go's flat dionaea (log_json)
// branch: credentials[0], when present, is the only field that feeds
// TopCreds for this shape.
func promoteDionaeaFields(e map[string]any) bool {
	credsAny, ok := e["credentials"].([]any)
	if !ok || len(credsAny) == 0 {
		return false
	}
	c, ok := credsAny[0].(map[string]any)
	if !ok {
		return false
	}
	return setCreds(e, str(c["username"]), str(c["password"]))
}

// promoteDionaeaIncidentFields mirrors classify.go's dionaea_incident.json
// branch: user/pass (gated the same way classify.go gates ev.isLogin --
// present, and the incident kind mentions login/auth) and a payload hash,
// read straight from any {sha256,sha1,md5,...}/download-basename shape
// under "data".
func promoteDionaeaIncidentFields(e map[string]any) bool {
	origin := str(e["origin"])
	if !strings.HasPrefix(origin, "dionaea.") {
		return false
	}
	kind := strings.TrimPrefix(origin, "dionaea.")
	data, _ := e["data"].(map[string]any)
	if data == nil {
		return false
	}
	changed := false

	user := firstNonEmpty(str(data["username"]), str(data["user"]), str(data["login"]))
	pass := firstNonEmpty(str(data["password"]), str(data["pass"]))
	if (user != "" || pass != "") && (strings.Contains(kind, "login") || strings.Contains(kind, "auth")) {
		if setCreds(e, user, pass) {
			changed = true
		}
	}

	shasum := firstNonEmpty(str(data["sha256"]), str(data["sha256hash"]),
		str(data["sha1"]), str(data["md5"]), str(data["md5hash"]))
	if shasum == "" {
		download := firstNonEmpty(str(data["url"]), str(data["path"]), str(data["file"]), str(data["filename"]))
		if download != "" {
			if base := filepath.Base(download); hashName.MatchString(base) {
				shasum = base
			}
		}
	}
	if shasum != "" {
		e["canonical_shasum"] = shasum
		changed = true
	}

	return changed
}

// headerMap coerces a JSON headers object into a lowercased-key string
// map -- ported from dashboard/classify.go's own helper of the same name,
// used identically here for JA3/JA4/User-Agent fingerprint extraction.
func headerMap(v any) map[string]string {
	m := map[string]string{}
	if raw, ok := v.(map[string]any); ok {
		for k, val := range raw {
			m[strings.ToLower(k)] = str(val)
		}
	}
	return m
}

// promoteCiscoAsaFields mirrors classify.go's cisco-asa-honeypot branch:
// the CVE-2018-0101/generic POST payload as canonical_command, and a
// JA4/JA3/User-Agent fingerprint from the request's own headers.
func promoteCiscoAsaFields(e map[string]any) bool {
	changed := false
	kind := str(e["event"])
	if kind == "cve_2018_0101_payload" || kind == "post" {
		if body := str(e["data"]); body != "" {
			e["canonical_command"] = body
			changed = true
		}
	}
	if hdr := headerMap(e["headers"]); len(hdr) > 0 {
		switch {
		case hdr["x-ja4"] != "":
			changed = setFingerprint(e, hdr["x-ja4"], "JA4") || changed
		case hdr["x-ja3"] != "":
			changed = setFingerprint(e, hdr["x-ja3"], "JA3") || changed
		case hdr["user-agent"] != "":
			changed = setFingerprint(e, hdr["user-agent"], "User-Agent") || changed
		}
	}
	return changed
}

// headerVal ported from dashboard/classify.go's own helper of the same
// name -- headerMap already lowercases keys, this just saves callers from
// lowercasing the lookup key too.
func headerVal(m map[string]string, key string) string { return m[strings.ToLower(key)] }

// promoteMultipotFields mirrors classify.go's multipot branch (~line 318):
// per-protocol login credentials, a "command" field carried by every
// handler except http_request (whose own "command" is an HTTP request
// line, not an attacker command -- see classify.go's #41 comment, same
// omission ported here), and the client banner as a fingerprint.
func promoteMultipotFields(e map[string]any) bool {
	if s, ok := e["sensor"].(string); !ok || s != "multipot" {
		return false
	}
	kind := str(e["event"])
	if kind == "listening" || kind == "multipot_started" || kind == "listen_error" {
		return false
	}
	changed := false
	if kind == "login" {
		if setCreds(e, str(e["username"]), str(e["password"])) {
			changed = true
		}
	}
	if kind != "http_request" {
		if cmd := str(e["command"]); cmd != "" {
			e["canonical_command"] = cmd
			changed = true
		}
	}
	if client := str(e["client"]); client != "" && setFingerprint(e, client, "client banner") {
		changed = true
	}
	return changed
}

// promoteCitrixFields mirrors classify.go's citrix-honeypot branch
// (~line 485): the CVE-2019-19781 payload as canonical_command, and a
// JA4/JA3/User-Agent fingerprint from the request's own headers -- the
// same shape promoteCiscoAsaFields already promotes for cisco-asa-honeypot.
func promoteCitrixFields(e map[string]any) bool {
	changed := false
	if str(e["event"]) == "cve_2019_19781_payload" {
		if body := str(e["data"]); body != "" {
			e["canonical_command"] = body
			changed = true
		}
	}
	if hdr := headerMap(e["headers"]); len(hdr) > 0 {
		switch {
		case hdr["x-ja4"] != "":
			changed = setFingerprint(e, hdr["x-ja4"], "JA4") || changed
		case hdr["x-ja3"] != "":
			changed = setFingerprint(e, hdr["x-ja3"], "JA3") || changed
		case hdr["user-agent"] != "":
			changed = setFingerprint(e, hdr["user-agent"], "User-Agent") || changed
		}
	}
	return changed
}

// promoteRDPFields mirrors classify.go's rdp-honeypot branch (~line 558):
// the offered username (rdp-honeypot's own "mstshash" value, no separate
// password field exists for RDP's pre-auth handshake) as canonical_user --
// setCreds still gates it through validCredentialPair so an oversized or
// control-character-laden value never gets promoted.
func promoteRDPFields(e map[string]any) bool {
	if str(e["event"]) == "listening" {
		return false
	}
	user := str(e["username"])
	if user == "" {
		return false
	}
	return setCreds(e, user, "")
}

// promoteWebRequestFields mirrors classify.go's shared tanner_report.json/
// http-honeypot branch (~line 766): username/password on any request that
// carries them, a JA4/JA3/User-Agent fingerprint from headers, and (tanner
// only, matching classify.go's own "ev.sensor == tanner" gate --
// http-honeypot's own POST body is captured separately under e["body"] but
// was never promoted into TopCommands by classify.go either, so parity
// means leaving it alone here too) tanner's own emulator-matched
// post_data as canonical_command. The legacy tanner "peer" shape
// (classify.go ~line 730, no method/category field) carries none of these
// fields and is silently skipped by the guard below, same as
// classify.go's own dashboard row for that shape has nothing to show
// here either.
func promoteWebRequestFields(persona string, e map[string]any) bool {
	if str(e["method"]) == "" && str(e["category"]) == "" {
		return false
	}
	if str(e["category"]) == "startup" {
		return false
	}
	changed := false
	if setCreds(e, str(e["username"]), str(e["password"])) {
		changed = true
	}
	hdr := headerMap(e["headers"])
	switch {
	case headerVal(hdr, "x-ja4") != "":
		changed = setFingerprint(e, headerVal(hdr, "x-ja4"), "JA4") || changed
	case headerVal(hdr, "x-ja3") != "":
		changed = setFingerprint(e, headerVal(hdr, "x-ja3"), "JA3") || changed
	case headerVal(hdr, "user-agent") != "":
		changed = setFingerprint(e, headerVal(hdr, "user-agent"), "User-Agent") || changed
	}
	if persona == "tanner" {
		if postData, ok := e["post_data"].(map[string]any); ok && len(postData) > 0 {
			parts := make([]string, 0, len(postData))
			for k, v := range postData {
				parts = append(parts, k+"="+str(v))
			}
			sort.Strings(parts) // deterministic field order
			e["canonical_command"] = strings.Join(parts, "&")
			changed = true
		}
	}
	return changed
}
