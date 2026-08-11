package main

import (
	"path/filepath"
	"regexp"
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
// Scope: cowrie, dionaea (+ dionaea_incident.json), and
// cisco-asa-honeypot -- the sensor families this worker already watches
// for IP resolution that also have a creds/command/fingerprint/client-
// version field in classify.go. dns-honeypot and every conpot persona are
// also watched here but classify.go sets none of those fields for them
// (conpot's own "request" field is deliberately excluded from commands --
// see classify.go's #41 comment, ported as the same omission here, not an
// oversight), so there is nothing to promote for those two.
//
// Every other sensor with its own creds/commands/fingerprints
// (multipot/tanner/http-honeypot/citrix-honeypot/rdp-honeypot) isn't
// watched by this worker at all today -- they get the real attacker IP
// directly via PROXY protocol, so never needed the via_port join that
// brought them into this worker's scope. Extending discoverSources to
// also watch those purely for field normalization (no IP-resolution role)
// is explicit follow-up work, not done here.
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
