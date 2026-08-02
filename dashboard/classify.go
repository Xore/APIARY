package main

import (
	"encoding/json"
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
		case strings.Contains(eid, "login"):
			ev.isLogin = true
			ev.detail = eid[len("cowrie."):] + ": " + ev.user + " / " + ev.pass
		case eid == "cowrie.command.input", eid == "cowrie.command.failed":
			ev.command = str(e["input"])
			ev.detail = "cmd: " + ev.command
		case eid == "cowrie.session.file_download", eid == "cowrie.session.file_upload":
			ev.shasum = str(e["shasum"])
			ev.download = firstNonEmpty(str(e["destfile"]), str(e["url"]), str(e["filename"]))
			ev.detail = "payload " + shortHash(ev.shasum)
			if ev.download != "" {
				ev.detail += " -> " + ev.download
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
		case eid == "cowrie.session.connect":
			ev.detail = "connect"
		case eid == "cowrie.session.closed":
			ev.detail = "closed"
			if d := num(e["duration"]); d != "" {
				ev.detail = "closed after " + d + "s"
			}
		default:
			ev.detail = eid[len("cowrie."):]
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
		ev.detail = strings.TrimSpace(ev.proto + " " + req)
		if ev.detail == "" {
			ev.detail = "probe"
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
