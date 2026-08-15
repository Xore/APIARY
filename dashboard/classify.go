package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
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
	ttyReplay   string // /tty/<shasum> download+replay link (cowrie.log.closed only, #612/#638)
	clientVer   string // ssh/telnet client banner (cowrie) — cheap fingerprint
	fingerprint string // user-agent/client identity reused across sensors
	fingerKind  string // HASSH / JA3 / JA4 / User-Agent / client banner
	category    string // suricata alert category / http probe class
	country     string // ISO country code, from a cf-ipcountry header when present
	severity    int    // suricata alert severity (1 = most severe)
	heldMs      int    // endlessh (#1294): tarpit hold duration, disconnect events only
	icsSeverity string // dnp3 (#1290): "critical"/"high" for control-function app_function codes, "" for read/status traffic
	// anomalyEvent/anomalyAppProto (#1279): suricata protocol-conformance
	// violation identity, category=="anomaly" events only -- separate
	// fields (not parsed back out of ev.detail) so the trend chart can
	// group by them directly.
	anomalyEvent    string
	anomalyAppProto string
	isLogin         bool
	skip            bool
	when            time.Time
	whenStr         string
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
// One query, one pass, two maps.
//
// #1103 Category 2: reads portbridge-v2-* exclusively now, not the local
// connlog -- portbridge-v2-* was added (#354) specifically so this join
// could move off disk, matching every other sensor's ES-only read (#1103
// Category 1). No local fallback: a query failure means the join simply
// can't run this cycle (both maps come back empty), the same "no data this
// cycle" behavior loadSensorEventsES already has for every other sensor.
//
// Sorted ascending (oldest first), the ES equivalent of the old
// portbridge.json.1-then-portbridge.json file-generation order: viaLookup
// takes the newest match, so processing oldest-to-newest makes plain
// append-order correct for the via_port lists, and last-write-wins correct
// for osByIP.
func (s *store) buildViaMap() (map[int][]viaEntry, map[string]string) {
	m := map[int][]viaEntry{}
	osByIP := map[string]string{}
	if s.es == nil {
		return m, osByIP
	}
	pitID, ok := s.es.openPointInTime("portbridge-v2-*", "1m")
	if !ok {
		return m, osByIP
	}
	defer s.es.closePointInTime(pitID)

	var searchAfter []any
	for page := 0; page < esEventsMaxPages; page++ {
		body := map[string]any{
			"size": esEventsPageSize,
			"pit":  map[string]any{"id": pitID, "keep_alive": "1m"},
			"sort": []map[string]any{
				{"@timestamp": "asc"},
				{"_shard_doc": "asc"},
			},
			"query": map[string]any{
				"bool": map[string]any{
					"filter": []map[string]any{
						{"range": map[string]any{"@timestamp": map[string]any{"gte": esOverviewWindow}}},
					},
				},
			},
		}
		if searchAfter != nil {
			body["search_after"] = searchAfter
		}
		reqBody, err := json.Marshal(body)
		if err != nil {
			break
		}
		b, err := s.es.searchBody("/_search", reqBody)
		if err != nil {
			break
		}
		var v struct {
			Hits struct {
				Hits []struct {
					Sort   []any `json:"sort"`
					Source struct {
						Portbridge map[string]any `json:"portbridge"`
					} `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if json.Unmarshal(b, &v) != nil || len(v.Hits.Hits) == 0 {
			break
		}
		for _, h := range v.Hits.Hits {
			e := h.Source.Portbridge
			if e == nil || str(e["sensor"]) != "portbridge" {
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
		if len(v.Hits.Hits) < esEventsPageSize {
			break
		}
		searchAfter = v.Hits.Hits[len(v.Hits.Hits)-1].Sort
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
		case eid == "cowrie.direct-tcpip.ja4":
			// JA4 fingerprint of TLS traffic the attacker tunneled through
			// a port-forward (cowrie's own ssh/forwarding.py computes this
			// from the ClientHello it observes) -- reached ES fine but had
			// no case here, so it only ever showed as free text in message.
			ev.fingerprint = str(e["ja4"])
			ev.fingerKind = "JA4"
			ev.detail = "JA4 (tunneled TLS to " + str(e["dst_ip"]) + ":" + num(e["dst_port"]) + "): " + ev.fingerprint
		case eid == "cowrie.direct-tcpip.ja4h":
			ev.fingerprint = str(e["ja4h"])
			ev.fingerKind = "JA4H"
			ev.detail = "JA4H (tunneled HTTP to " + str(e["dst_ip"]) + ":" + num(e["dst_port"]) + "): " + ev.fingerprint
		case eid == "cowrie.client.fingerprint":
			// Logged the moment a pubkey auth attempt is offered,
			// independent of whether it's ultimately accepted -- distinct
			// from cowrie.login.{success,failed}'s own fingerprint field,
			// which only fires for the auth outcome, not every offer.
			ev.user = str(e["username"])
			ev.fingerprint = str(e["fingerprint"])
			ev.fingerKind = "SSH pubkey"
			ev.detail = "pubkey offered (" + str(e["type"]) + "): " + shortHash(ev.fingerprint)
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
			ev.detail = "TTY session recorded"
			if ev.download != "" {
				ev.detail += ": " + ev.download
			}
			// #638/#1266: ev.ttyReplay is keyed by the TTY log's own hash --
			// the filename cowrie renames the recording to on session close
			// -- read directly from the raw event's "shasum" field rather
			// than through ev.shasum, deliberately NOT set here anymore.
			// cowrie reuses that same JSON key for a genuinely different
			// thing on cowrie.session.file_download/file_upload (a real
			// downloaded file's hash), but ev.shasum feeds every "this event
			// delivered a payload" signal downstream (the Shasum/VirusTotal
			// action links on every event row, aggregate.go's payload
			// leaderboard, and via canonical_shasum promotion,
			// attacker-identity-worker's entity.Payloads) -- setting it here
			// too silently counted every TTY session close as a payload
			// delivery. Confirmed live: ~20x more cowrie.log.closed events
			// than real file_download/file_upload events (57k vs 2.9k),
			// so this was the dominant source of "payload" noise in those
			// counts, not a rare edge case.
			if ttyHash := str(e["shasum"]); ttyHash != "" {
				ev.ttyReplay = "/tty/" + ttyHash
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
		if calledAE := str(e["called_ae"]); calledAE != "" {
			ev.detail += " called=" + calledAE
		}
		if callingAE := str(e["calling_ae"]); callingAE != "" {
			ev.detail += " calling=" + callingAE
		}
		if data := str(e["data"]); data != "" {
			ev.detail += " " + data
		}
		if b := num(e["bytes"]); b != "" {
			ev.detail += " (" + b + " bytes)"
		}
		return ev
	}

	// ---- dnp3-honeypot (#570) -----------------------------------------------
	// dnp3-honeypot/main.go emits function (link-layer function name),
	// frame_hex, and dnp3_source/dnp3_destination (link-layer addresses) on
	// every real protocol interaction, but had no dedicated case here --
	// every event fell through to the generic fallback below, which only
	// ever showed the bare event field ("frame"/"connect"/"malformed_frame")
	// with no indication of which link function was invoked or which RTU
	// address was targeted.
	if s, ok := e["sensor"].(string); ok && s == "dnp3" {
		ev.sensor = "dnp3"
		ev.proto = "dnp3"
		ev.port = num(e["port"])
		kind := str(e["event"])
		switch kind {
		case "frame":
			ev.detail = "link " + str(e["function"])
			// #610: app_function is only present when the frame carries a
			// full transport+application-layer segment past the link
			// header -- most scanners never send one, so this is absent
			// far more often than not.
			if app := str(e["app_function"]); app != "" {
				ev.detail += ", app " + app
				ev.icsSeverity = dnp3FunctionSeverity(app)
			}
			if src, dst := num(e["dnp3_source"]), num(e["dnp3_destination"]); src != "" || dst != "" {
				ev.detail += fmt.Sprintf(" (src %s -> dst %s)", src, dst)
			}
		case "malformed_frame":
			ev.detail = "malformed frame"
		default:
			ev.detail = kind
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
		// #571: dns-honeypot's own anti-amplification cap (dns.go's
		// ratioCap, at most 1.5x the request's byte size) can suppress a
		// response entirely when even a bare header would exceed it -- it
		// appends "_dropped" to the logged event ("query_dropped",
		// "malformed_query_dropped") when that happens. Previously
		// invisible here: a capped/suppressed response looked identical to
		// a normally-answered one.
		if strings.HasSuffix(kind, "_dropped") {
			ev.detail += " [response suppressed, amplification cap]"
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
		} else if kind == "post" {
			// #620: every POST body reaches ES fine (webvpn.go's servePOST
			// logs it unconditionally), but only the CVE-2018-0101-shaped
			// payload above ever populated ev.command -- a crafted
			// submission against the fake /+CSCOE+/logon.html login page
			// that isn't that specific CVE shape was captured end-to-end
			// and simply invisible in the dashboard. "body:" instead of
			// "payload:" keeps the two visually distinct at a glance.
			if body := str(e["data"]); body != "" {
				ev.command = body
				ev.detail += "  body: " + body
			}
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

	// ---- beelzebub (#1418) --------------------------------------------------
	// Reads the flat lowercase fields ip-enrichment-worker/beelzebub.go
	// promotes from upstream's own PascalCase Event (Protocol/User/Command/
	// RequestURI), not the raw field names -- see that file's doc comment
	// for why. No port: upstream's Event carries no listen-port field of its
	// own, a documented gap, not an oversight (same comment).
	if s, ok := e["sensor"].(string); ok && s == "beelzebub" {
		ev.sensor = "beelzebub"
		ev.proto = strings.ToLower(str(e["protocol"]))
		ev.user, ev.pass = str(e["username"]), str(e["password"])
		ev.isLogin = ev.user != "" || ev.pass != ""
		ev.command = str(e["command"])
		switch {
		case ev.command != "":
			ev.detail = "cmd: " + ev.command
		case ev.user != "" || ev.pass != "":
			ev.detail = "auth: " + ev.user + " / " + ev.pass
		case str(e["path"]) != "":
			ev.detail = "request: " + str(e["path"])
		default:
			ev.detail = str(e["Status"])
		}
		return ev
	}

	// ---- hellpot (#1419) -----------------------------------------------------
	// Reads the flat lowercase fields ip-enrichment-worker/hellpot.go
	// promotes from upstream's own field names (URL/USERAGENT), not the raw
	// ones -- see that file's doc comment for why. No port, same documented
	// gap as beelzebub above: hellpot logs no listen-port of its own.
	if s, ok := e["sensor"].(string); ok && s == "hellpot" {
		ev.sensor = "hellpot"
		ev.proto = "http"
		ev.path = str(e["path"])
		if ev.fingerprint = str(e["user_agent"]); ev.fingerprint != "" {
			ev.fingerKind = "User-Agent"
		}
		switch {
		// BYTES/DURATION are JSON numbers (num(), not str()) -- DURATION is
		// milliseconds (confirmed live: a ~2s held connection logged
		// DURATION:1998.9), not seconds.
		case str(e["message"]) == "FINISH":
			ev.detail = "tarpitted " + num(e["BYTES"]) + " bytes over " + num(e["DURATION"]) + "ms: " + ev.path
		case ev.path != "":
			ev.detail = "request: " + ev.path
		default:
			ev.detail = str(e["message"])
		}
		return ev
	}

	// ---- elasticpot (#1423) -------------------------------------------------
	// Genuinely flat native fields (eventid/message/url/request/payload) --
	// no ip-enrichment-worker promotion needed beyond the plain src_ip/
	// src_port join every other raw-port sensor gets from enrichLine, so
	// nothing here reads a promoted/renamed field the way beelzebub/
	// hellpot's blocks do.
	if s, ok := e["sensor"].(string); ok && s == "elasticpot" {
		ev.sensor = "elasticpot"
		ev.proto = "elasticsearch"
		ev.port = num(e["dst_port"])
		ev.path = str(e["url"])
		if ev.fingerprint = str(e["user_agent"]); ev.fingerprint != "" {
			ev.fingerKind = "User-Agent"
		}
		switch {
		case str(e["payload"]) != "":
			ev.detail = str(e["request"]) + " " + ev.path + "  payload: " + str(e["payload"])
		case ev.path != "":
			ev.detail = str(e["request"]) + " " + ev.path
		default:
			ev.detail = str(e["message"])
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
			ev.heldMs = ms
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
		// #1276: data.cve/data.name carry the actual exploit identity (e.g.
		// name "DoublePulsar connection attempt", cve
		// "CVE-2017-0144..CVE-2017-0148") on every exploit-attempt incident
		// -- previously unread, so an operator only ever saw the generic
		// Python module path (kind, e.g. "modules.python.smb.exploit")
		// where the real exploit name would tell them immediately what's
		// actually being tried.
		if name := str(data["name"]); name != "" {
			ev.detail = name
			if cve := str(data["cve"]); cve != "" {
				ev.detail += " (" + cve + ")"
			}
		}
		if ev.download != "" {
			ev.detail += " " + ev.download
		}
		if ev.shasum != "" && !strings.Contains(ev.detail, ev.shasum) {
			ev.detail += " [" + shortHash(ev.shasum) + "]"
		}
		// #624: smb.dcerpc.bind/request incidents carry which RPC service
		// interface (uuid) and, for a request, which operation (opnum) the
		// attacker targeted -- log_incident's generic handler already
		// stores both in `data`, this dashboard branch just never read
		// them before, so an operator had to open the raw ES document by
		// hand to see which interface/operation was actually probed.
		if uuid := str(data["uuid"]); uuid != "" {
			ev.detail += " uuid=" + uuid
			if opnum := num(data["opnum"]); opnum != "" {
				ev.detail += " opnum=" + opnum
			}
			if ts := str(data["transfersyntax"]); ts != "" {
				ev.detail += " transfersyntax=" + ts
			}
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
			// #575: for a classified attack, the actual payload (post_data --
			// exactly where a SQLi/XSS/cmd_exec/php_object_injection/etc.
			// payload one of tanner's 10 enabled emulators matched against
			// lands) and cookies (session-hijacking/injection payloads can
			// ride here too) were captured by tanner and stored in ES, but
			// never read here. http-honeypot's own POST handling already
			// captures its body separately via e["body"], so this is scoped
			// to tanner only.
			if ev.sensor == "tanner" {
				if postData, ok := e["post_data"].(map[string]any); ok && len(postData) > 0 {
					parts := make([]string, 0, len(postData))
					for k, v := range postData {
						parts = append(parts, k+"="+str(v))
					}
					sort.Strings(parts) // deterministic detail-line order
					ev.command = strings.Join(parts, "&")
					ev.detail += "  payload: " + ev.command
				}
				if cookies := stringMap(e["cookies"]); len(cookies) > 0 {
					parts := make([]string, 0, len(cookies))
					for k, v := range cookies {
						parts = append(parts, k+"="+v)
					}
					sort.Strings(parts)
					ev.detail += "  cookies: " + strings.Join(parts, "; ")
				}
				// #618: detection.payload.value is the actual emulator
				// execution result -- cmd_exec's real shell stdout, lfi's
				// real file-read content, the PHP-sandbox stdout for
				// php_code_injection/php_object_injection/xxe_injection, the
				// downloaded-and-executed RFI file's output. Reaches ES
				// unmodified (honeypot.response_msg.response.message.
				// detection.payload.value) but was never read here at all --
				// literally the richest field tanner produces, previously
				// invisible.
				if payload := tannerDetectionPayload(e); payload != "" {
					ev.detail += "  result: " + payload
				}
			}
		}
		return ev
	}

	// ---- suricata eve.json (VPS logs mounted at /logs/suricata) -----------
	if et := str(e["event_type"]); et != "" && dirSensor == "suricata" {
		// #616: anomaly (protocol-conformance violations/malformed traffic,
		// potentially IDS evasion) is a fundamentally different signal from
		// flow/dns/netflow/stats -- confirmed live it's genuinely low-volume
		// (50 anomaly events vs. 5700+ netflow in the same hour on the VPS),
		// so it doesn't "swamp the counts" the way those do and is worth
		// keeping alongside alert rather than filtered out with them.
		if et != "alert" && et != "anomaly" {
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
			if ev.severity > 0 {
				ev.detail += "  " + severityLabel(ev.severity)
			}
			// #615: alert.metadata.mitre_tactic_id/technique_id (present on
			// most ET/OISF rules that map to ATT&CK) reaches Elasticsearch
			// fine but was never read here -- confirmed live against
			// eve.json on the VPS, e.g. mitre_tactic_id ["TA0008"] +
			// mitre_tactic_name ["Lateral_Movement"]. Detail-line only, per
			// this issue's own scope note: not wired into Top
			// Commands/aggregate leaderboards, just extra context on the
			// alert an operator is already looking at.
			if am, ok := a["metadata"].(map[string]any); ok {
				if mitre := mitreSuffix(am); mitre != "" {
					ev.detail += "  " + mitre
				}
			}
		}
		if an, ok := e["anomaly"].(map[string]any); ok {
			// e.g. "REQUEST_HEADER_REPETITION [http] (layer: proto_parser)"
			ev.category = "anomaly"
			ev.anomalyEvent = str(an["event"])
			ev.anomalyAppProto = str(an["app_proto"])
			ev.detail = ev.anomalyEvent
			if ev.anomalyAppProto != "" {
				ev.detail += "  [" + ev.anomalyAppProto + "]"
			}
			if layer := str(an["layer"]); layer != "" {
				ev.detail += "  (layer: " + layer + ")"
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
	"connect":   "connect",
	"associate": "A-ASSOCIATE",
	"c_echo":    "C-ECHO",
	"c_find":    "C-FIND",
	"c_move":    "C-MOVE",
	"c_get":     "C-GET",
	"c_store":   "C-STORE",
}

// severityLabel renders suricata's numeric alert.severity (1 = most severe,
// per its own eve.json convention) as a short bracketed label -- distinct
// from ml_anomalies' unrelated low/medium/high/critical string band, which
// scores a different signal entirely.
func severityLabel(sev int) string {
	switch sev {
	case 1:
		return "[severity 1/critical]"
	case 2:
		return "[severity 2/major]"
	case 3:
		return "[severity 3/minor]"
	default:
		return fmt.Sprintf("[severity %d]", sev)
	}
}

// mitreSuffix renders alert.metadata's MITRE ATT&CK fields (present on most
// ET/OISF rules that map to ATT&CK -- confirmed live against eve.json,
// e.g. mitre_tactic_id ["TA0008"] + mitre_tactic_name ["Lateral_Movement"])
// as a short "ATT&CK: TA0008 Lateral_Movement / T1021 Remote_Services"
// suffix. Every metadata value in eve.json is a []any of strings even when
// only one is present, so this only ever reads the first.
func mitreSuffix(metadata map[string]any) string {
	tacticID := metaFirst(metadata, "mitre_tactic_id")
	tacticName := metaFirst(metadata, "mitre_tactic_name")
	techID := metaFirst(metadata, "mitre_technique_id")
	techName := metaFirst(metadata, "mitre_technique_name")
	if tacticID == "" && techID == "" {
		return ""
	}
	parts := []string{}
	if tacticID != "" {
		parts = append(parts, strings.TrimSpace(tacticID+" "+tacticName))
	}
	if techID != "" {
		parts = append(parts, strings.TrimSpace(techID+" "+techName))
	}
	return "ATT&CK: " + strings.Join(parts, " / ")
}

// metaFirst reads the first string out of an eve.json alert.metadata field,
// which suricata always encodes as a JSON array even for single values.
func metaFirst(metadata map[string]any, key string) string {
	vs, ok := metadata[key].([]any)
	if !ok || len(vs) == 0 {
		return ""
	}
	s, _ := vs[0].(string)
	return s
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

// tannerDetectionPayload digs response_msg.response.message.detection.
// payload.value out of a tanner event -- set by BaseHandler.
// get_emulation_result() (tanner/emulators/base.py) only when one of
// tanner's emulators actually matched and ran (confirmed live against
// cmd_exec.py: `dict(value=execute_result, page=True)`), so it's absent
// for benign/"index" traffic -- not an error, just nothing to show.
// Truncated for display; the full value is still in the ES _source
// regardless (subject to that field's own ignore_above:32000 for search,
// a separate ES-side property this doesn't need to fix).
func tannerDetectionPayload(e map[string]any) string {
	respMsg, _ := e["response_msg"].(map[string]any)
	resp, _ := respMsg["response"].(map[string]any)
	msg, _ := resp["message"].(map[string]any)
	detection, _ := msg["detection"].(map[string]any)
	payload, _ := detection["payload"].(map[string]any)
	v := str(payload["value"])
	if len(v) > 1000 {
		v = v[:1000] + "(...)"
	}
	return v
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

// stringMap coerces a JSON object into a plain string map, preserving key
// case -- unlike headerMap, which lowercases for HTTP headers' own
// case-insensitivity. Cookie names are case-sensitive, so #575's tanner
// cookie surfacing uses this instead of headerMap.
func stringMap(v any) map[string]string {
	m := map[string]string{}
	if raw, ok := v.(map[string]any); ok {
		for k, val := range raw {
			m[k] = str(val)
		}
	}
	return m
}

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
