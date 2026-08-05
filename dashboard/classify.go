package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// event is one normalised log record, whatever sensor it came from.
type event struct {
	sensor      string
	persona     string
	site        string
	asset       string
	personaOrg  string
	detail      string
	ip          string
	proto       string
	user        string
	pass        string
	command     string
	port        string // public port the attacker targeted, where the sensor knows it
	path        string // HTTP path probed (http-honeypot / tanner)
	alert       string // suricata alert signature
	session     string // cowrie session id — correlates every event in one login
	shasum      string // sha-256 of a captured payload (cowrie downloads)
	download    string // where the attacker tried to write the payload
	clientVer   string // ssh/telnet client banner (cowrie) — cheap fingerprint
	fingerprint string // user-agent/client identity reused across sensors
	fingerKind  string // HASSH / JA3 / JA4 / User-Agent / client banner
	category    string // suricata alert category / http probe class
	country     string // ISO country code, from a cf-ipcountry header when present
	severity    int    // suricata alert severity (1 = most severe)
	isLogin     bool
	skip        bool
	when        time.Time
	whenStr     string
}

// viaEntry is one portbridge connection indexed by its tunnel-side local port.
type viaEntry struct {
	ip   string
	port string // portbridge listen port (22/23/…) — a sanity check on the join
}

// buildViaMap indexes the portbridge connection log by via_port: the tunnel
// ephemeral port portbridge dialed the honeypot from, which equals the src_port
// the honeypot observes for that same connection. Entries are kept as a
// chronological list per port because an ephemeral port is reused over time —
// possibly across different honeypot ports — so the lookup can pick the most
// recent entry whose listen port matches the event (see viaLookup).
//
// It also returns a source-IP → p0f OS-guess map (#241). portbridge sits
// ahead of everything else on the VPS and already sees every real attacker
// IP, and p0f sniffs the same public interface — so rather than shipping and
// correlating a second, independently-rotated p0f.json log by IP after the
// fact, portbridge queries p0f directly per connection (vps/portbridge/p0f.go)
// and folds the answer into the same JSON line this function already reads.
// One file, one pass, two maps.
func (s *store) buildViaMap() (map[int][]viaEntry, map[string]string) {
	m := map[int][]viaEntry{}
	osByIP := map[string]string{}
	// The VPS rotator copytruncates the live log to portbridge.json.1, so the
	// previous generation is read first — oldest entries first, because
	// viaLookup takes the newest match. Reading only the live file means a
	// rotation empties the map, and every tunnelled event whose connection was
	// recorded before it goes unattributed until the file refills. The same
	// old-file-first order makes plain last-write-wins correct for osByIP too:
	// the live file's entries are processed last, so they win.
	for _, name := range []string{"portbridge.json.1", "portbridge.json"} {
		data := readTail(filepath.Join(s.dir, "portbridge", name))
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var e map[string]any
			if json.Unmarshal([]byte(line), &e) != nil {
				continue
			}
			if str(e["sensor"]) != "portbridge" {
				continue
			}
			if ip := str(e["src_ip"]); ip != "" {
				if os := str(e["os"]); os != "" {
					osByIP[ip] = os
				}
			}
			vp := int(numFloat(e["via_port"]))
			if vp == 0 {
				continue
			}
			m[vp] = append(m[vp], viaEntry{ip: str(e["src_ip"]), port: num(e["port"])})
		}
	}
	return m, osByIP
}

// viaLookup returns the real attacker IP for a tunnel-peer connection: the most
// recent portbridge entry for this via_port whose listen port matches the
// honeypot port the event hit (port="" matches anything). Empty if none.
func viaLookup(m map[int][]viaEntry, srcPort int, port string) string {
	cands := m[srcPort]
	for i := len(cands) - 1; i >= 0; i-- { // newest first
		if port == "" || cands[i].port == "" || cands[i].port == port {
			return cands[i].ip
		}
	}
	return ""
}

// classify normalises one raw JSON record. dirSensor is the name of the
// subdirectory the log file lives in — used as the sensor name for formats we
// don't specifically recognise, so every log under /logs shows up.
func classify(e map[string]any, dirSensor string) event {
	ev := event{
		sensor: dirSensor, persona: str(e["persona_id"]), site: str(e["site_id"]),
		asset: str(e["asset_id"]), personaOrg: str(e["organization"]),
	}
	ev.when, ev.whenStr = when(e)
	ev.ip = ipOf(e)

	// Drop loopback healthchecks: multipot's -healthcheck dials 127.0.0.1:6379
	// and http-honeypot's Docker HEALTHCHECK GETs http://127.0.0.1:8080/. A real
	// external attacker never appears as loopback, so unless a trusted forwarded
	// header carries a real client IP this is pure noise.
	if (ev.ip == "127.0.0.1" || ev.ip == "::1") && !hasForwardedIP(e) {
		ev.skip = true
		return ev
	}

	// ---- cowrie -----------------------------------------------------------
	if eid, ok := e["eventid"].(string); ok && strings.HasPrefix(eid, "cowrie.") {
		ev.sensor = "cowrie"
		ev.persona, ev.site, ev.asset, ev.personaOrg = "nexusai-gpu01", "nexusai-berlin-ml", "gpu01", "NexusAI Research GmbH"
		ev.user, ev.pass = str(e["username"]), str(e["password"])
		ev.session = str(e["session"]) // ties every event in one login together
		if p := str(e["protocol"]); p != "" {
			ev.proto = p // ssh / telnet
		}
		// cowrie sees its container port (2222/2223) — report the public one on
		// every event so port drill-downs are complete, not just on connect.
		switch num(e["dst_port"]) {
		case "2222":
			ev.port = "22"
		case "2223":
			ev.port = "23"
		}
		switch {
		case eid == "cowrie.login.success", eid == "cowrie.login.failed":
			ev.isLogin = true
			ev.detail = eid[len("cowrie."):] + ": " + ev.user + " / " + ev.pass
			// Public-key auth attempts carry no password but do carry a key
			// fingerprint (docs/OUTPUT.rst: fingerprint/key/type) -- surface
			// it the same way client.kex's HASSH already is, rather than
			// showing a login row with an empty-looking user/pass pair.
			if fp := str(e["fingerprint"]); fp != "" {
				ev.fingerprint, ev.fingerKind = fp, "SSH pubkey"
				ev.detail += " (key " + shortHash(fp) + ")"
			}
		case eid == "cowrie.command.input", eid == "cowrie.command.failed",
			eid == "cowrie.command.success", eid == "cowrie.session.input":
			ev.command = str(e["input"])
			ev.detail = "cmd: " + ev.command
		case eid == "cowrie.command.chpasswd":
			ev.detail = "chpasswd attempt: " + str(e["username"])
		case eid == "cowrie.session.file_download", eid == "cowrie.session.file_upload":
			ev.shasum = str(e["shasum"])
			ev.download = firstNonEmpty(str(e["destfile"]), str(e["url"]), str(e["filename"]))
			ev.detail = "payload " + shortHash(ev.shasum)
			if ev.download != "" {
				ev.detail += " -> " + ev.download
			}
		case eid == "cowrie.session.file_download.failed":
			ev.download = str(e["url"])
			ev.detail = "download failed: " + ev.download
			if reason := str(e["error"]); reason != "" {
				ev.detail += " (" + reason + ")"
			}
		case eid == "cowrie.client.version":
			ev.clientVer = str(e["version"])
			ev.fingerprint = ev.clientVer
			ev.fingerKind = "SSH client"
			ev.detail = "client: " + ev.clientVer
		case eid == "cowrie.client.kex":
			ev.fingerprint = str(e["hassh"])
			ev.fingerKind = "HASSH"
			ev.detail = "SSH HASSH: " + ev.fingerprint
		case eid == "cowrie.client.size":
			ev.detail = "terminal " + num(e["width"]) + "x" + num(e["height"])
		case eid == "cowrie.direct-tcpip.request":
			// A port-forward request is the attacker trying to proxy
			// traffic through the honeypot -- worth its own detail line,
			// not just the bare eventid.
			ev.detail = "port-forward request -> " + str(e["dst_ip"]) + ":" + num(e["dst_port"])
		case eid == "cowrie.telnet.exploit_attempt":
			ev.detail = "CVE " + str(e["cve"]) + " attempt: " + str(e["name"]) + "=" + str(e["value"])
		case eid == "cowrie.telnet.exploit_success":
			ev.isLogin = true
			ev.user = str(e["username"])
			ev.detail = "CVE " + str(e["cve"]) + " succeeded, logged in as " + ev.user
		case eid == "cowrie.log.closed":
			// A replayable TTY session recording -- arguably the single
			// most useful artifact cowrie produces, and it was previously
			// only ever shown as the bare word "closed" (the eventid
			// suffix), with no indication a recording exists at all.
			ev.download = str(e["ttylog"])
			ev.shasum = str(e["shasum"])
			ev.detail = "TTY session recorded"
			if ev.download != "" {
				ev.detail += ": " + ev.download
			}
		case eid == "cowrie.session.connect":
			ev.detail = "connect"
		case eid == "cowrie.session.closed":
			ev.detail = "closed"
			// duration_ms, not duration -- e["duration"] never matched any
			// real cowrie field (confirmed live against the deployed
			// cluster), so this line silently never fired.
			if d := num(e["duration_ms"]); d != "" {
				ev.detail = "closed after " + d + "ms"
			}
		default:
			// Every cowrie event carries a human-readable "message" per its
			// own docs (confirmed live) -- falling back to the bare eventid
			// suffix here discarded it for every eventid without its own
			// case above (there are 30+; only a handful are cased).
			ev.detail = firstNonEmpty(str(e["message"]), eid[len("cowrie."):])
		}
		return ev
	}

	// ---- multipot ---------------------------------------------------------
	if s, ok := e["sensor"].(string); ok && s == "multipot" {
		kind := str(e["event"])
		if kind == "listening" || kind == "multipot_started" || kind == "listen_error" {
			ev.skip = true
			return ev
		}
		ev.sensor = "multipot"
		ev.proto = str(e["proto"])
		ev.port = num(e["port"])
		// #608: ties every event from one TCP connection together, same
		// role as cowrie's own "session" field -- lets filters.go/
		// investigate.go/intelligence.go/search.go group a multi-step
		// interaction (e.g. FTP USER -> PASS -> command loop) with no
		// further plumbing needed here.
		ev.session = str(e["session"])
		ev.user, ev.pass = str(e["username"]), str(e["password"])
		switch kind {
		case "login":
			ev.isLogin = true
			ev.detail = ev.proto + " login: " + ev.user + " / " + ev.pass
		case "command":
			ev.command = str(e["command"])
			ev.detail = ev.proto + ": " + ev.command
		default:
			ev.detail = ev.proto + " " + kind
		}
		// Every other multipot handler's payload rides in "command"
		// (e.g. ADB's OPEN destination) or "data" (SOCKS5's offered
		// methods/connect target, Postgres's database param, HL7's
		// message, Elasticsearch/Docker's HTTP body) -- neither ever
		// reached the dashboard row for any event kind besides the
		// literal "command" case above.
		//
		// #41: "http_request" is excluded here -- its own "command" field
		// (handleElastic/handleDocker's Command: reqLine) is an HTTP
		// request line ("GET /_search HTTP/1.1"), not an attacker-issued
		// command, and copying it into ev.command was polluting the
		// Attacker Behavior tab's Top Commands leaderboard with GET/POST
		// requests. It's still shown in ev.detail below either way --
		// only the commands aggregate (aggregate.go's
		// commands[sensor+cmd]++, keyed off ev.command) is affected.
		if kind != "command" && kind != "http_request" {
			if cmd := str(e["command"]); cmd != "" {
				ev.command = cmd
				ev.detail += ": " + cmd
			}
		} else if kind == "http_request" {
			if cmd := str(e["command"]); cmd != "" {
				ev.detail += ": " + cmd
			}
		}
		if data := str(e["data"]); data != "" {
			ev.detail += "  " + data
		}
		if client := str(e["client"]); client != "" {
			ev.fingerprint, ev.fingerKind = client, "client banner"
			ev.detail += "  client: " + client
		}
		return ev
	}

	// ---- dicompot (#413) ---------------------------------------------------
	if s, ok := e["sensor"].(string); ok && s == "dicompot" {
		kind := str(e["event"])
		if kind == "listening" {
			ev.skip = true
			return ev
		}
		ev.sensor = "dicompot"
		ev.proto = "dicom"
		ev.port = num(e["port"])
		ev.detail = dicomEventLabels[kind]
		if ev.detail == "" {
			ev.detail = kind
		}
		if data := str(e["data"]); data != "" {
			ev.detail += " " + data
		}
		if b := num(e["bytes"]); b != "" {
			ev.detail += " (" + b + " bytes)"
		}
		return ev
	}

	// ---- dns-honeypot (#415) ------------------------------------------------
	// query is the actual domain asked for -- deliberately not confused with
	// the "event" field (also sometimes literally the string "query"): a
	// prior version of this function fell through to the generic fallback
	// below, which only ever surfaced e["event"] and made every query look
	// identically blank regardless of what was actually asked.
	if s, ok := e["sensor"].(string); ok && s == "dns-honeypot" {
		kind := str(e["event"])
		if kind == "listening" {
			ev.skip = true
			return ev
		}
		ev.sensor = "dns-honeypot"
		ev.proto = "dns"
		ev.port = num(e["port"])
		ev.path = str(e["query"])
		ev.detail = kind
		if ev.path != "" {
			ev.detail = "query " + ev.path
			if qt := dnsQTypeName(int(numFloat(e["qtype"]))); qt != "" {
				ev.detail += " (" + qt + ")"
			}
		}
		// A non-zero opcode (IQUERY/STATUS/NOTIFY/UPDATE) is a non-standard
		// probe worth flagging -- 0 (QUERY) is virtually all real traffic,
		// so only surface it when it deviates from that default.
		if op := opcodeName[int(numFloat(e["opcode"]))]; op != "" {
			ev.detail += " [opcode " + op + "]"
		}
		return ev
	}

	// ---- citrix-honeypot (#414, CVE-2019-19781) ----------------------------
	if s, ok := e["sensor"].(string); ok && s == "citrix-honeypot" {
		kind := str(e["event"])
		if kind == "listening" {
			ev.skip = true
			return ev
		}
		ev.sensor = "citrix-honeypot"
		ev.proto = "https"
		ev.port = num(e["port"])
		ev.path = str(e["path"])
		ev.detail = strings.TrimSpace(kind + " " + ev.path)
		if kind == "cve_2019_19781_payload" {
			ev.command = str(e["data"])
			ev.detail += "  payload: " + ev.command
		}
		if hdr := headerMap(e["headers"]); len(hdr) > 0 {
			if ev.fingerprint = headerVal(hdr, "x-ja4"); ev.fingerprint != "" {
				ev.fingerKind = "JA4"
			} else if ev.fingerprint = headerVal(hdr, "x-ja3"); ev.fingerprint != "" {
				ev.fingerKind = "JA3"
			} else if ev.fingerprint = headerVal(hdr, "user-agent"); ev.fingerprint != "" {
				ev.fingerKind = "User-Agent"
			}
		}
		return ev
	}

	// ---- cisco-asa-honeypot (#414, CVE-2018-0101 + IKE) --------------------
	if s, ok := e["sensor"].(string); ok && s == "cisco-asa-honeypot" {
		kind := str(e["event"])
		if kind == "https_listening" || kind == "ike_listening" {
			ev.skip = true
			return ev
		}
		ev.sensor = "cisco-asa-honeypot"
		ev.proto = str(e["proto"])
		ev.port = num(e["port"])
		ev.path = str(e["path"])
		ev.detail = strings.TrimSpace(kind + " " + ev.path)
		if kind == "cve_2018_0101_payload" {
			ev.command = str(e["data"])
			ev.detail += "  payload: " + ev.command
		}
		if kind == "ike_unexpected_exchange" {
			if d := str(e["data"]); d != "" {
				ev.detail += " (type " + d + ")"
			}
		}
		if hdr := headerMap(e["headers"]); len(hdr) > 0 {
			if ev.fingerprint = headerVal(hdr, "x-ja4"); ev.fingerprint != "" {
				ev.fingerKind = "JA4"
			} else if ev.fingerprint = headerVal(hdr, "x-ja3"); ev.fingerprint != "" {
				ev.fingerKind = "JA3"
			} else if ev.fingerprint = headerVal(hdr, "user-agent"); ev.fingerprint != "" {
				ev.fingerKind = "User-Agent"
			}
		}
		return ev
	}

	// ---- rdp-honeypot (#412) -----------------------------------------------
	if s, ok := e["sensor"].(string); ok && s == "rdp-honeypot" {
		if str(e["event"]) == "listening" {
			ev.skip = true
			return ev
		}
		ev.sensor = "rdp-honeypot"
		ev.proto = "rdp"
		ev.port = num(e["port"])
		ev.user = str(e["username"])
		ev.isLogin = ev.user != ""
		ev.detail = "connect"
		if ev.user != "" {
			ev.detail += "  mstshash: " + ev.user
		}
		if p := str(e["requested_protocols"]); p != "" {
			ev.detail += "  security: " + p
		}
		return ev
	}

	// ---- endlessh (#246) ---------------------------------------------------
	// A "connect" and a later "disconnect" are logged per held connection;
	// the disconnect carries the actual investigative value (how long/how
	// much this tarpit cost the requester), so it drives the detail line --
	// surfacing it here rather than leaving the pair to fall through to the
	// generic "anything else under /logs" bucket, which would only ever
	// show the bare event name (the exact gap #550's dnp3-honeypot audit
	// found for a different sensor this same session).
	if s, ok := e["sensor"].(string); ok && s == "endlessh" {
		if str(e["event"]) == "listening" {
			ev.skip = true
			return ev
		}
		ev.sensor = "endlessh"
		ev.proto = "ssh"
		ev.port = num(e["port"])
		switch str(e["event"]) {
		case "connect":
			ev.detail = "tarpit connect"
		case "disconnect":
			ms := int(numFloat(e["held_ms"]))
			lines := int(numFloat(e["lines"]))
			ev.detail = fmt.Sprintf("tarpit held %dms, %d banner lines sent", ms, lines)
		default:
			ev.detail = str(e["event"])
		}
		return ev
	}

	// ---- dionaea incident handler ----------------------------------------
	// log_incident records every lifecycle and payload incident as
	// {origin:"dionaea.*", data:{connection:{...}, ...}}. Keep these richer
	// records in addition to log_json's one-record-per-connection summary.
	if origin := str(e["origin"]); strings.HasPrefix(origin, "dionaea.") {
		ev.sensor = "dionaea"
		ev.persona, ev.site, ev.asset, ev.personaOrg = "meridian-legacy", "meridian-hamburg-dc1", "legacy-svc-02", "Meridian Retail Systems Ltd."
		kind := strings.TrimPrefix(origin, "dionaea.")
		data, _ := e["data"].(map[string]any)
		conn, _ := data["connection"].(map[string]any)
		ev.proto = str(conn["protocol"])
		ev.ip = firstNonEmpty(str(conn["remote_ip"]), ev.ip)
		ev.port = num(conn["local_port"])
		ev.user = firstNonEmpty(str(data["username"]), str(data["user"]), str(data["login"]))
		ev.pass = firstNonEmpty(str(data["password"]), str(data["pass"]))
		ev.download = firstNonEmpty(str(data["url"]), str(data["path"]), str(data["file"]), str(data["filename"]))
		ev.shasum = firstNonEmpty(str(data["sha256"]), str(data["sha256hash"]),
			str(data["sha1"]), str(data["md5"]), str(data["md5hash"]))
		if ev.shasum == "" && ev.download != "" {
			base := filepath.Base(ev.download)
			if hashName.MatchString(base) {
				ev.shasum = base
			}
		}
		ev.isLogin = (ev.user != "" || ev.pass != "") &&
			(strings.Contains(kind, "login") || strings.Contains(kind, "auth"))
		ev.detail = kind
		if ev.download != "" {
			ev.detail += " " + ev.download
		}
		if ev.shasum != "" && !strings.Contains(ev.detail, ev.shasum) {
			ev.detail += " [" + shortHash(ev.shasum) + "]"
		}
		return ev
	}

	// ---- dionaea (log_json: one record per connection) --------------------
	// The dtagdevsec image puts addresses at the top level (src_ip/src_port/
	// dst_port, already read into ev.ip via ipOf); older builds nest them under
	// connection.remote_ip/local_port. Support both. The tunnel-peer IP is
	// rewritten to the real attacker below via the portbridge via_port join.
	if conn, ok := e["connection"].(map[string]any); ok {
		ev.sensor = "dionaea"
		ev.persona, ev.site, ev.asset, ev.personaOrg = "meridian-legacy", "meridian-hamburg-dc1", "legacy-svc-02", "Meridian Retail Systems Ltd."
		ev.proto = str(conn["protocol"])
		if rip := str(conn["remote_ip"]); rip != "" {
			ev.ip = rip
		}
		ev.port = firstNonEmpty(num(e["dst_port"]), num(conn["local_port"]))
		ev.detail = strings.TrimSpace(ev.proto + "/" + str(conn["transport"]) + " " + str(conn["type"]))
		if ev.port != "" {
			ev.detail += " -> :" + ev.port
		}
		// credential capture (e.g. ftp/mysql logins) rides along on the record
		if credsAny, ok := e["credentials"].([]any); ok && len(credsAny) > 0 {
			if c, ok := credsAny[0].(map[string]any); ok {
				ev.user, ev.pass = str(c["username"]), str(c["password"])
				ev.isLogin = true
			}
		}
		return ev
	}

	// ---- conpot -----------------------------------------------------------
	if strings.HasPrefix(dirSensor, "conpot") || e["data_type"] != nil || e["sensorid"] != nil {
		ev.sensor = "conpot"
		if strings.HasPrefix(dirSensor, "conpot-") {
			ev.sensor = dirSensor
		}
		ev.persona, ev.site, ev.asset, ev.personaOrg = personaForSensor(ev.sensor)
		ev.proto = str(e["data_type"])
		ev.port = num(e["dst_port"]) // tunnel-peer IP rewritten via via_port below
		// The extra PLCs listen on canonical ports inside their containers but
		// are published on distinct VPS ports. Normalize before the portbridge
		// join so its listen-port sanity check can recover the attacker IP.
		switch dirSensor + ":" + ev.port {
		case "conpot-s7-1200:102":
			ev.port = "1102"
		case "conpot-s7-1200:502":
			ev.port = "1502"
		case "conpot-s7-1500:102":
			ev.port = "2102"
		case "conpot-s7-1500:502":
			ev.port = "2502"
		}
		req := firstNonEmpty(str(e["request"]), str(e["event_type"]))
		// #41: ev.command deliberately NOT set here. "request" is raw
		// industrial-protocol bytes (Modbus/S7comm/Kamstrup) or whatever
		// arbitrary garbage a scanner sent to the wrong port -- not an
		// attacker-issued command. Confirmed live: this was polluting the
		// Attacker Behavior tab's Top Commands leaderboard with raw hex
		// blobs and even a PROXY-protocol preamble + full HTTP request that
		// happened to land on a conpot port. Still shown in detail below,
		// same as before -- only the commands aggregate is affected.
		ev.detail = strings.TrimSpace(ev.proto + " " + req)
		if ev.detail == "" {
			ev.detail = "probe"
		}
		// response is the fake device's own reply bytes -- what was actually
		// disclosed to the attacker (e.g. a Kamstrup meter's canned readout).
		// request/event_type were already read above; response never was.
		if resp := str(e["response"]); resp != "" {
			ev.detail += "  -> " + resp
		}
		return ev
	}

	// ---- tanner session report (legacy "peer" shape) ----------------------
	if peer, ok := e["peer"].(map[string]any); ok {
		ev.sensor = "tanner"
		ev.persona, ev.site, ev.asset, ev.personaOrg = "meridian-customer-portal", "meridian-public-web", "customer-portal-02", "Meridian Retail Systems Ltd."
		ev.proto = "http"
		ev.ip = firstNonEmpty(str(peer["ip"]), ev.ip)
		var paths []string
		if ps, ok := e["paths"].([]any); ok {
			for _, p := range ps {
				if pm, ok := p.(map[string]any); ok {
					paths = append(paths, str(pm["path"]))
				}
				if len(paths) >= 3 {
					break
				}
			}
		}
		if len(paths) == 0 && str(e["path"]) != "" {
			paths = append(paths, str(e["path"]))
		}
		if len(paths) > 0 {
			ev.path = paths[0]
		}
		ev.detail = strings.Join(paths, " ")
		if at, ok := e["attack_types"].([]any); ok && len(at) > 0 {
			var kinds []string
			for _, a := range at {
				kinds = append(kinds, str(a))
			}
			ev.detail += "  [" + strings.Join(kinds, ",") + "]"
		}
		if ev.detail == "" {
			ev.detail = "web session"
		}
		return ev
	}

	// ---- tanner_report.json (method/path/headers shape) + http-honeypot ----
	// Both share the request-log shape. tanner reports come from the tanner
	// dir; http-honeypot sets a "sensor"/"category" field. Real client IP and
	// country ride in Cloudflare headers when fronted by CF.
	if str(e["method"]) != "" || str(e["category"]) != "" {
		if str(e["category"]) == "startup" {
			ev.skip = true
			return ev
		}
		hdr := headerMap(e["headers"])
		ev.sensor = "http"
		if rawSensor := str(e["sensor"]); rawSensor != "" && rawSensor != "http-honeypot" {
			ev.sensor = rawSensor
		}
		if dirSensor == "tanner" || headerVal(hdr, "cf-ray") != "" && str(e["sensor"]) == "" {
			ev.sensor = "tanner"
		}
		if ev.sensor == "tanner" && ev.persona == "" {
			ev.persona, ev.site, ev.asset, ev.personaOrg = "meridian-customer-portal", "meridian-public-web", "customer-portal-02", "Meridian Retail Systems Ltd."
		}
		ev.proto = "http"
		ev.user, ev.pass = str(e["username"]), str(e["password"])
		ev.path = str(e["path"])
		ev.category = str(e["category"])
		if ev.fingerprint = headerVal(hdr, "x-ja4"); ev.fingerprint != "" {
			ev.fingerKind = "JA4"
		} else if ev.fingerprint = headerVal(hdr, "x-ja3"); ev.fingerprint != "" {
			ev.fingerKind = "JA3"
		} else if ev.fingerprint = headerVal(hdr, "user-agent"); ev.fingerprint != "" {
			ev.fingerKind = "User-Agent"
		}
		// Prefer the trustworthy CF/Traefik forwarded IP over the transport peer.
		ev.ip = firstNonEmpty(headerVal(hdr, "cf-connecting-ip"), headerVal(hdr, "x-real-ip"),
			firstHop(headerVal(hdr, "x-forwarded-for")), ev.ip, str(e["src_ip"]))
		ev.country = headerVal(hdr, "cf-ipcountry")
		ev.detail = strings.TrimSpace(str(e["method"]) + " " + ev.path)
		if ev.user != "" || ev.pass != "" {
			ev.isLogin = true
			ev.detail += "  (" + ev.user + " / " + ev.pass + ")"
		}
		// #246: http-honeypot/api-honeypot tarpit unrecognized scan/rce-probe
		// requests with a slow Markov-garbage stream instead of a fast reply
		// -- surface how long/how much, not just that it happened, since
		// that's the actual point of the technique (cost the requester real
		// time/bandwidth).
		if tarpitted, ok := e["tarpitted"].(bool); ok && tarpitted {
			ms := int(numFloat(e["tarpit_ms"]))
			kb := numFloat(e["tarpit_bytes"]) / 1024
			ev.detail += fmt.Sprintf("  [tarpitted %dms, %.1fKB]", ms, kb)
		}
		// tanner's own emulator classifies every request against a detection
		// name ("index" for benign/unmatched traffic, or an attack signature
		// like a known scanner/exploit pattern otherwise) -- present in the
		// stored ES document but never read here at all.
		if name := tannerDetectionName(e); name != "" && name != "index" {
			ev.category = firstNonEmpty(ev.category, "tanner: "+name)
			ev.detail += "  [" + name + "]"
		}
		return ev
	}

	// ---- suricata eve.json (VPS logs mounted at /logs/suricata) -----------
	if et := str(e["event_type"]); et != "" && dirSensor == "suricata" {
		if et != "alert" {
			ev.skip = true // flow/dns/netflow/stats records would swamp the counts
			return ev
		}
		ev.sensor = "suricata"
		ev.proto = strings.ToLower(str(e["proto"]))
		ev.port = num(e["dest_port"])
		if tls, ok := e["tls"].(map[string]any); ok {
			if ev.fingerprint = str(tls["ja4"]); ev.fingerprint != "" {
				ev.fingerKind = "JA4"
			} else if ja3, ok := tls["ja3"].(map[string]any); ok {
				ev.fingerprint, ev.fingerKind = str(ja3["hash"]), "JA3"
			}
		}
		if httpData, ok := e["http"].(map[string]any); ok && ev.fingerprint == "" {
			ev.fingerprint, ev.fingerKind = str(httpData["http_user_agent"]), "User-Agent"
		}
		if sshData, ok := e["ssh"].(map[string]any); ok && ev.fingerprint == "" {
			if client, ok := sshData["client"].(map[string]any); ok {
				ev.fingerprint, ev.fingerKind = str(client["software_version"]), "SSH client"
			}
		}
		if a, ok := e["alert"].(map[string]any); ok {
			ev.alert = str(a["signature"])
			ev.category = str(a["category"])
			ev.severity = int(numFloat(a["severity"]))
			ev.detail = ev.alert
			if ev.category != "" {
				ev.detail += "  [" + ev.category + "]"
			}
		}
		if ev.detail == "" {
			ev.detail = "alert"
		}
		// #576: vps/suricata/suricata.yaml enables payload-printable/
		// http-body-printable -- safe, already-sanitized (printable-only)
		// capture of the actual bytes that triggered the signature match.
		// Reaches Elasticsearch intact but was never read here: an operator
		// saw which signature matched, not what actually matched it.
		//
		// ev.command deliberately NOT used, same reasoning as #41's conpot
		// fix above: this is arbitrary matched network content, not an
		// attacker-issued shell command, and would pollute the Attacker
		// Behavior tab's Top Commands leaderboard the same way conpot's raw
		// request bytes once did.
		if pp := str(e["payload_printable"]); pp != "" {
			ev.detail += "  payload: " + pp
		} else if httpData, ok := e["http"].(map[string]any); ok {
			if body := str(httpData["http_body_printable"]); body != "" {
				ev.detail += "  body: " + body
			}
		}
		return ev
	}

	// ---- portbridge connection log (real attacker IP for every port) ------
	if s := str(e["sensor"]); s == "portbridge" {
		// buildViaMap consumes these records separately to recover the real
		// attacker IP for tunnelled sensors. They are transport metadata, not
		// honeypot observations, so never count or display them as a sensor.
		ev.skip = true
		return ev
	}

	// ---- anything else under /logs ----------------------------------------
	// Unknown JSON record: attribute it to its directory so new sensors show
	// up without a code change.
	if p := str(e["proto"]); p != "" && p != "-" {
		ev.proto = p
	}
	ev.detail = firstNonEmpty(str(e["event"]), str(e["event_type"]), str(e["message"]), str(e["msg"]), "event")
	return ev
}

// dicomEventLabels maps dicompot's raw DIMSE event names to a readable
// label; see dicompot/main.go for the exact set it emits.
var dicomEventLabels = map[string]string{
	"connect": "connect",
	"c_echo":  "C-ECHO",
	"c_find":  "C-FIND",
	"c_move":  "C-MOVE",
	"c_get":   "C-GET",
	"c_store": "C-STORE",
}

// dnsQTypeName maps the common DNS query type numbers to their record
// name, for dns-honeypot's logged qtype. Falls back to "" (omitted) for
// anything not in this short, deliberately incomplete list -- the raw
// number is still visible in the stored ES document either way.
func dnsQTypeName(qtype int) string {
	names := map[int]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
		16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
	}
	return names[qtype]
}

// opcodeName maps a DNS header OPCODE to its RFC name for dns-honeypot's
// logged opcode. 0 (QUERY) is deliberately absent -- it's virtually all
// real traffic and not worth flagging in the UI.
var opcodeName = map[int]string{
	1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE",
}

func personaForSensor(sensor string) (persona, site, asset, org string) {
	values := map[string][4]string{
		"conpot":          {"rheinwerk-water-s7-200", "rheinwerk-intake", "plc-intake-01", "Rheinwerk Municipal Water"},
		"conpot-s7-1200":  {"rheinwerk-water-s7-1200", "rheinwerk-treatment", "plc-filter-02", "Rheinwerk Municipal Water"},
		"conpot-s7-1500":  {"nordchem-s7-1500", "nordchem-reactor-4", "plc-reactor-04", "NordChem Process Industries"},
		"conpot-iec104":   {"elbegrid-iec104", "elbegrid-substation-17", "rtu-sub17-a", "ElbeGrid Distribution"},
		"conpot-guardian": {"northfuel-guardian", "northfuel-station-042", "tankmon-042", "NorthFuel Service GmbH"},
		"conpot-kamstrup": {"stadtwaerme-kamstrup", "stadtwaerme-loop-west", "heatmeter-west-0382", "Stadtwaerme Nord"},
	}
	v := values[sensor]
	return v[0], v[1], v[2], v[3]
}

// when extracts a timestamp from the record in whatever shape the sensor
// logged it (ISO string under several key names, or a unix epoch number).
//
// The display string is always formatted in UTC (#198), regardless of which
// Location the value happened to parse into. A Z-suffixed string parses as
// UTC; suricata's eve.json "...+0200" parses into a fixed +0200 Location;
// time.Unix's epoch branch returns the server process's local zone
// (Europe/Berlin here). time.Time comparisons (used everywhere else for
// age/sort) don't care about Location, so leaving t itself alone is fine --
// only t.Format printed the wrong wall-clock, silently disagreeing by
// exactly the CEST/UTC offset between sensors that happen to log in
// different formats.
func when(e map[string]any) (time.Time, string) {
	for _, k := range []string{"timestamp", "time", "@timestamp", "start_time", "ts"} {
		switch v := e[k].(type) {
		case string:
			if v == "" {
				continue
			}
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339,
				"2006-01-02T15:04:05.999999-0700", // suricata eve.json
				"2006-01-02T15:04:05.999999", "2006-01-02 15:04:05,999", "2006-01-02 15:04:05"} {
				if t, err := time.Parse(layout, v); err == nil {
					return t, t.UTC().Format("2006-01-02 15:04:05")
				}
			}
			return time.Time{}, v // unknown format — display raw, sorts last
		case float64:
			if v <= 0 {
				continue
			}
			t := time.Unix(int64(v), int64((v-float64(int64(v)))*1e9))
			return t, t.UTC().Format("2006-01-02 15:04:05")
		}
	}
	return time.Time{}, ""
}

// utcOrEmpty renders t as RFC3339 for client-side timezone conversion
// (#282), or "" for a zero time.Time -- when()'s "unknown format" branch
// returns time.Time{} alongside the raw display string, and formatting a
// zero value would hand the client "0001-01-01T00:00:00Z" to reformat into
// something that looks like a real, if wrong, date.
func utcOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ipOf hunts for a source address across the field names the sensors use.
func ipOf(e map[string]any) string {
	for _, k := range []string{"src_ip", "remote_ip", "peer_ip", "client_ip", "ip"} {
		if v := str(e[k]); v != "" {
			return v
		}
	}
	// conpot: "remote": ["1.2.3.4", 51234]
	if r, ok := e["remote"].([]any); ok && len(r) > 0 {
		return str(r[0])
	}
	return ""
}

// eventSrcPort returns the tunnel-side peer port used to correlate a sensor
// event with the VPS portbridge connection that carried it.
func eventSrcPort(e map[string]any) int {
	if p := int(numFloat(e["src_port"])); p != 0 {
		return p
	}
	if conn, ok := e["connection"].(map[string]any); ok {
		if p := int(numFloat(conn["remote_port"])); p != 0 {
			return p
		}
	}
	if data, ok := e["data"].(map[string]any); ok {
		if conn, ok := data["connection"].(map[string]any); ok {
			return int(numFloat(conn["remote_port"]))
		}
	}
	return 0
}

// tannerDetectionName digs response_msg.response.message.detection.name out
// of a tanner_report.json record -- tanner's own emulator-side
// classification of the request (a known scanner/exploit signature, or
// "index" for unmatched/benign traffic).
func tannerDetectionName(e map[string]any) string {
	respMsg, _ := e["response_msg"].(map[string]any)
	resp, _ := respMsg["response"].(map[string]any)
	msg, _ := resp["message"].(map[string]any)
	detection, _ := msg["detection"].(map[string]any)
	return str(detection["name"])
}

// headerMap coerces a JSON headers object into a plain string map.
func headerMap(v any) map[string]string {
	m := map[string]string{}
	if raw, ok := v.(map[string]any); ok {
		for k, val := range raw {
			m[strings.ToLower(k)] = str(val)
		}
	}
	return m
}

// headerVal reads a header case-insensitively (keys are already lowercased).
func headerVal(m map[string]string, key string) string { return m[strings.ToLower(key)] }

// hasForwardedIP reports whether a record carries a trusted forwarded client IP
// (Cloudflare / reverse-proxy headers) — used to avoid dropping a real request
// that merely arrived over loopback from a local proxy.
func hasForwardedIP(e map[string]any) bool {
	h := headerMap(e["headers"])
	return headerVal(h, "cf-connecting-ip") != "" ||
		headerVal(h, "x-forwarded-for") != "" ||
		headerVal(h, "x-real-ip") != ""
}

// firstHop returns the left-most address of an X-Forwarded-For chain.
func firstHop(xff string) string {
	if xff == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(xff, ",")[0])
}
