package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// mapPointRadius is the fixed SVG-fallback marker radius (viewBox units).
// #228: not scaled by event count -- see the comment where it's assigned.
const mapPointRadius = 6

func (s *store) rebuild() {
	var (
		total, logins, last24, previous24, downloads int
		unattributed                                 int
		srcIPs                                       = map[string]int{}
		sensors                                      = map[string]int{}
		protos                                       = map[string]int{}
		creds                                        = map[string]int{}
		commands                                     = map[string]int{}
		ports                                        = map[string]int{}
		paths                                        = map[string]int{}
		alerts                                       = map[string]int{}
		alertCats                                    = map[string]int{}
		countries                                    = map[string]int{}
		asns                                         = map[string]int{}
		providers                                    = map[string]int{}
		clients                                      = map[string]int{}
		fingerprints                                 = map[string]int{}
		// #228: keyed by city+country, not by source IP -- a marker is a
		// place, not an address, so every IP that geolocates to the same
		// city accumulates onto the one point instead of overplotting a
		// separate circle per IP. pointIPs tracks the distinct contributing
		// IPs per key for the marker's IPCount; it lives alongside points
		// rather than inside mapPoint because that struct is copied into
		// pointRows and serialized, and a per-point set has no JSON shape
		// worth keeping once IPCount is computed.
		points       = map[string]*mapPoint{}
		pointIPs     = map[string]map[string]struct{}{}
		payloads     = map[string]*payloadRow{}
		lastSeen     = map[string]time.Time{}
		sensorHourly = map[string]*[24]int{}
		evs          []storedEvent
		seen         = map[string]bool{}
	)
	now := time.Now()

	// Recover real attacker IPs for cowrie (which only sees the tunnel peer)
	// by joining on the tunnel ephemeral port recorded in the portbridge log.
	viaMap, p0fOS := s.buildViaMap()

	// #353: nextCache replaces s.logCache wholesale at the end of this
	// function rather than being mutated in place -- a file that rotated
	// out of logFiles()'s result this cycle (deleted, or renamed past
	// classify's own rotation-suffix matching) simply has no entry copied
	// forward, which is the prune: no separate sweep needed.
	nextCache := make(map[string]*logFileState, len(s.logCache))

	for _, fn := range logFiles(s.dir) {
		rel, _ := filepath.Rel(s.dir, fn)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		dirSensor := "logs"
		if len(parts) > 1 {
			dirSensor = parts[0]
		}
		cached, state := s.classifiedEventsFor(fn, dirSensor, s.logCache[fn], tailCap)
		if state != nil {
			nextCache[fn] = state
		}
		for _, entry := range cached {
			ev := entry.ev
			// cowrie / dionaea / conpot only see the tunnel peer (10.8.0.1)
			// because their ports aren't PROXY-wrapped. Recover the real attacker
			// IP by matching the connection's src_port to the via_port portbridge
			// dialed from — every event in one connection shares that port, so
			// the whole chain (and its geo lookup below) gets the real IP.
			//
			// When the join misses, the source is unknown, not 10.8.0.1: that
			// address is our own VPS tunnel end and is never an attacker.
			// Recording it as one puts our own infrastructure at the top of
			// /ips, inflates UniqueIPs, and feeds it to the geo lookup, the map,
			// campaign correlation, and eventually external abuse reporting.
			// Clearing the IP instead keeps the event — it is a real attack —
			// while every aggregate below, all of which already require a
			// non-empty IP, correctly declines to attribute it. The recovery gap
			// is reported as Unattributed rather than disguised as an attacker.
			//
			// What is left after issue #75 is the join window, not a missing
			// recovery path: UDP now carries a via_port like TCP, and the map
			// spans one log rotation. A miss means the connection that produced
			// this event has aged out of the portbridge log the dashboard can
			// still see. See issue #54 for why the peer is never substituted.
			//
			// #353: this join runs fresh every cycle even for an event whose
			// classification came from the cache -- see log_cache.go's own
			// header comment for why that matters (a line read before its
			// matching portbridge record landed must still get a chance to
			// join once that record shows up on a later cycle).
			lostSource := false
			if ev.ip == tunnelPeerIP {
				if real := viaLookup(viaMap, entry.srcPort, ev.port); real != "" {
					ev.ip = real
				} else {
					ev.ip = ""
					lostSource = true
				}
			}
			// #241: p0f OS guess, folded into the portbridge log at connection
			// time (vps/portbridge/p0f.go) — a fallback fingerprint for
			// connections that never produced a protocol-level one (HASSH/JA3/
			// User-Agent all require the attacker to complete a handshake with
			// a specific sensor; p0f only needs the initial SYN, so it covers
			// scanners and sensors those never fire against).
			if ev.fingerprint == "" && ev.ip != "" {
				if os, ok := p0fOS[ev.ip]; ok {
					ev.fingerprint, ev.fingerKind = os, "p0f OS"
				}
			}
			if key := dedupeKey(ev); key != "" {
				if seen[key] {
					continue
				}
				seen[key] = true
			}
			// Counted after the dedupe check so the figure matches the number of
			// events actually shown, not the number of raw log lines read.
			if lostSource {
				unattributed++
			}
			geo := geoInfo{Country: ev.country}
			if s.geo != nil && ev.ip != "" {
				geo = s.geo.lookup(ev.ip)
				if ev.country != "" {
					geo.Country = ev.country
				}
			}
			total++
			sensors[ev.sensor]++
			if ev.ip != "" {
				srcIPs[ev.ip]++
			}
			if ev.proto != "" {
				protos[ev.proto]++
			}
			if ev.isLogin {
				logins++
			}
			if ev.isLogin && validCredentialPair(ev.user, ev.pass) {
				creds[ev.user+" / "+ev.pass]++
			}
			if ev.command != "" {
				// Keep the sensor in the aggregate key so the command drill-down
				// can link to the exact source as well as the command text.
				commands[ev.sensor+"\x00"+ev.command]++
			}
			if ev.port != "" {
				ports[ev.port]++
			}
			// The HTTP OPTIONS asterisk-form is a request target, not a path.
			if strings.HasPrefix(ev.path, "/") {
				paths[ev.path]++
			}
			// Capture/decoder health warnings remain searchable in /events but
			// should not be presented as attacker detections on the overview.
			if ev.alert != "" && !isOperationalAlert(ev.alert) {
				alerts[ev.alert]++
			}
			if ev.category != "" && ev.sensor == "suricata" && !isOperationalAlert(ev.alert) {
				alertCats[ev.category]++
			}
			if ev.clientVer != "" {
				clients[ev.clientVer]++
			}
			if ev.fingerprint != "" {
				fingerprints[ev.fingerKind+"\x00"+ev.fingerprint]++
			}
			if geo.Country != "" {
				countries[geo.Country]++
			}
			if geo.ASN != 0 {
				asns[fmt.Sprintf("AS%d %s", geo.ASN, geo.Org)]++
			}
			provider := firstNonEmpty(geo.Intel, geo.Provider)
			if provider != "" {
				providers[provider]++
			}
			if geo.Lat != 0 || geo.Lon != 0 {
				// City empty means the GeoIP data only resolved to
				// country level; those IPs still cluster together onto one
				// per-country point rather than falling back to one point
				// per IP, consistent with how Country alone already reads
				// as a single dot rather than a jitter of siblings.
				key := geo.City + "\x00" + geo.Country
				p := points[key]
				if p == nil {
					p = &mapPoint{Country: geo.Country, City: geo.City, Lat: geo.Lat, Lon: geo.Lon}
					points[key] = p
					pointIPs[key] = map[string]struct{}{}
				}
				p.Count++
				pointIPs[key][ev.ip] = struct{}{}
			}
			if ev.shasum != "" {
				downloads++
				p := payloads[ev.shasum]
				if p == nil {
					p = &payloadRow{Shasum: ev.shasum, Download: ev.download}
					payloads[ev.shasum] = p
				}
				p.Count++
			}
			if ev.when.After(lastSeen[ev.sensor]) {
				lastSeen[ev.sensor] = ev.when
			}
			if !ev.when.IsZero() {
				if age := now.Sub(ev.when); age >= 0 && age < 24*time.Hour {
					hour := 23 - int(age.Hours())
					last24++
					if sensorHourly[ev.sensor] == nil {
						sensorHourly[ev.sensor] = &[24]int{}
					}
					sensorHourly[ev.sensor][hour]++
				} else if age >= 24*time.Hour && age < 48*time.Hour {
					previous24++
				}
			}
			evs = append(evs, storedEvent{
				when: ev.when,
				Time: ev.whenStr,
				// Empty, not a zero-value RFC3339 string, when ev.when never
				// parsed (when()'s "unknown format" branch) -- the client must
				// not reformat "0001-01-01" into something that looks like a
				// real, if wrong, date.
				UTC:           utcOrEmpty(ev.when),
				Sensor:        ev.sensor,
				Persona:       ev.persona,
				Site:          ev.site,
				Asset:         ev.asset,
				PersonaOrg:    ev.personaOrg,
				SrcIP:         ev.ip,
				Country:       geo.Country,
				City:          geo.City,
				Lat:           geo.Lat,
				Lon:           geo.Lon,
				ASN:           geo.ASN,
				Org:           geo.Org,
				Provider:      geo.Provider,
				Intel:         geo.Intel,
				Proto:         ev.proto,
				Port:          ev.port,
				User:          ev.user,
				Pass:          ev.pass,
				Command:       ev.command,
				Path:          ev.path,
				Alert:         ev.alert,
				Session:       ev.session,
				Shasum:        ev.shasum,
				Download:      ev.download,
				ClientVer:     ev.clientVer,
				Fingerprint:   ev.fingerprint,
				FingerKind:    ev.fingerKind,
				Category:      ev.category,
				Severity:      ev.severity,
				Detail:        ev.detail,
				IsLogin:       ev.isLogin,
				HasCredential: ev.isLogin && validCredentialPair(ev.user, ev.pass),
				Kibana:        investigationURL(investigationBase("kibana"), "kibana", ev.ip, ev.when),
				EveBox:        investigationURL(investigationBase("evebox"), "evebox", ev.ip, ev.when),
				Arkime:        investigationURL(investigationBase("arkime"), "arkime", ev.ip, ev.when),
			})
		}
	}

	// Newest first; /events pages retain the complete tail. The dashboard feed
	// caps each sensor so a noisy source (normally cowrie) cannot hide every
	// lower-volume sensor such as conpot or dionaea.
	sort.Slice(evs, func(i, j int) bool { return evs[i].when.After(evs[j].when) })
	recents := balancedRecent(evs, recentCap, recentPerSensorCap)
	campaigns := correlateCampaigns(evs, now.Add(-7*24*time.Hour))

	// Feed freshness rows, busiest first. Expected sensors remain visible with
	// zero events, making a missing mount/path obvious without Docker access.
	for _, name := range s.expected {
		if _, ok := sensors[name]; !ok {
			sensors[name] = 0
		}
	}
	var sensorRows []sensorRow
	for _, sensor := range topN(sensors, 30) {
		sensorRows = append(sensorRows, sensorRow{
			Name: sensor.Key, Count: sensor.Count, Ago: ago(lastSeen[sensor.Key]),
			State: feedState(lastSeen[sensor.Key], now),
			Link:  eventsURL(url.Values{"sensor": {sensor.Key}}),
		})
	}

	// Command rows: split the sensor back out of the map key for display + link.
	cmdRows := topN(commands, 15)
	for i, r := range cmdRows {
		sensor, cmd, _ := strings.Cut(r.Key, "\x00")
		cmdRows[i].Key = "[" + sensor + "] " + compactText(cmd, 68)
		cmdRows[i].Title = cmd
		cmdRows[i].Link = eventsURL(url.Values{"sensor": {sensor}, "cmd": {cmd}})
	}

	// Activity-by-sensor heatmap (#191/#193): replaced the single 24h bar
	// chart -- per-sensor breakdown is strictly more information for the
	// same space. Capped to the busiest sensorHeatmapRows sensors in the
	// window; more rows than that reads as noise, not signal, and a sensor
	// with zero events in the last 24h has nothing worth a row here.
	sensorHeatmap := buildSensorHeatmap(sensorHourly, now)

	// Payload rows sorted by frequency, with a VirusTotal link per hash.
	var payloadRows []payloadRow
	for _, p := range payloads {
		p.Link = eventsURL(url.Values{"shasum": {p.Shasum}})
		p.VT = "https://www.virustotal.com/gui/file/" + p.Shasum
		payloadRows = append(payloadRows, *p)
	}
	sort.Slice(payloadRows, func(i, j int) bool {
		if payloadRows[i].Count != payloadRows[j].Count {
			return payloadRows[i].Count > payloadRows[j].Count
		}
		return payloadRows[i].Shasum < payloadRows[j].Shasum
	})
	var pointRows []mapPoint
	for key, p := range points {
		p.X = (p.Lon + 180) / 360 * 1000
		p.Y = (90 - p.Lat) / 180 * 450
		// #228: fixed, not scaled by Count -- same reasoning as the Leaflet
		// map's circleMarker switch in hp-app.js. A count-scaled radius on
		// a high-traffic country-level point (no city resolved) could grow
		// large enough to visually cover a real city's own marker nearby.
		p.R = mapPointRadius
		p.IPCount = len(pointIPs[key])
		p.Link = mapPointEventsURL(p.City, p.Country)
		pointRows = append(pointRows, *p)
	}
	sort.Slice(pointRows, func(i, j int) bool { return pointRows[i].Count > pointRows[j].Count })
	if len(pointRows) > 500 {
		pointRows = pointRows[:500]
	}

	change, activity := "no prior baseline", "baseline unavailable"
	if previous24 > 0 {
		pct := (last24 - previous24) * 100 / previous24
		change = fmt.Sprintf("%+d%% vs previous 24h", pct)
		activity = "normal"
		if pct >= 100 {
			activity = "spike"
		} else if pct >= 35 {
			activity = "elevated"
		} else if pct <= -50 {
			activity = "low"
		}
	}
	snap := snapshot{
		Generated:      now,
		Total:          total,
		UniqueIPs:      len(srcIPs),
		Unattributed:   unattributed,
		Logins:         logins,
		Last24h:        last24,
		Previous24h:    previous24,
		Change24h:      change,
		ActivityState:  activity,
		Downloads:      downloads,
		GeoOn:          s.geo != nil,
		MapTileURL:     getenv("MAP_TILE_URL", "https://tile.openstreetmap.org/{z}/{x}/{y}.png"),
		MapAttribution: getenv("MAP_ATTRIBUTION", "© OpenStreetMap contributors"),
		Sensors:        sensorRows,
		Protocols:      linkRows(topN(protos, 12), "proto"),
		TopIPs:         linkRows(topN(srcIPs, 15), "ip"),
		TopPorts:       linkRows(topN(ports, 15), "port"),
		TopCreds:       credentialRows(topN(creds, 15)),
		TopCommands:    cmdRows,
		TopPaths:       linkRows(topN(paths, 15), "path"),
		Alerts:         linkRows(topN(alerts, 15), "sig"),
		AlertCats:      linkRows(topN(alertCats, 10), "cat"),
		Countries:      linkRows(topN(countries, 12), "country"),
		ASNs:           asnRows(topN(asns, 12)),
		Providers:      linkRows(topN(providers, 10), "provider"),
		Clients:        linkRows(topN(clients, 10), "client"),
		Fingerprints:   fingerprintRows(fingerprints, 12),
		MapPoints:      pointRows,
		Payloads:       payloadRows,
		Campaigns:      campaigns,
		SensorHeatmap:  sensorHeatmap,
		Recent:         recents,
		Runtime:        currentRuntime(),
		YARA:           yaraSummary(s.yaraFile),
	}
	if s.es != nil {
		snap.ES = s.es.get()
	}
	s.logCache = nextCache
	s.mu.Lock()
	s.snap = snap
	s.events = evs
	s.mu.Unlock()
	if s.intelligence != nil && s.intelligence.due() {
		s.intelligence.save(intelligenceSnapshot{Version: 1, Generated: now, Campaigns: campaigns, Clusters: s.clustersData(filter{}).Rows})
	}
	s.broadcast()
}

// sensorHeatmapRows caps the "Activity by sensor" heatmap to its busiest
// sensors in the current 24h window -- a row for every sensor that has ever
// logged anything would be mostly empty rows, not a signal.
const sensorHeatmapRows = 6

// buildSensorHeatmap turns the per-sensor, per-hour counts collected during
// rebuild into heatmapRow's, quantizing each cell's shade into five steps
// against the single busiest cell across every selected row -- a global
// scale, not per-row, so a quiet sensor's own peak hour never reads as
// visually "hot" as the noisiest sensor's.
func buildSensorHeatmap(sensorHourly map[string]*[24]int, now time.Time) []heatmapRow {
	type totaled struct {
		sensor string
		hours  *[24]int
		total  int
	}
	all := make([]totaled, 0, len(sensorHourly))
	for sensor, hours := range sensorHourly {
		total := 0
		for _, c := range hours {
			total += c
		}
		if total == 0 {
			continue
		}
		all = append(all, totaled{sensor: sensor, hours: hours, total: total})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].total != all[j].total {
			return all[i].total > all[j].total
		}
		return all[i].sensor < all[j].sensor
	})
	if len(all) > sensorHeatmapRows {
		all = all[:sensorHeatmapRows]
	}
	if len(all) == 0 {
		return nil
	}

	maxCell := 1
	for _, row := range all {
		for _, c := range row.hours {
			if c > maxCell {
				maxCell = c
			}
		}
	}
	quantize := func(count int) int {
		switch {
		case count <= 0:
			return 0
		case count*4 <= maxCell:
			return 25
		case count*4 <= maxCell*2:
			return 50
		case count*4 <= maxCell*3:
			return 75
		default:
			return 100
		}
	}

	rows := make([]heatmapRow, len(all))
	for r, row := range all {
		cells := make([]heatmapCell, len(row.hours))
		for i, c := range row.hours {
			t := now.Add(-time.Duration(len(row.hours)-1-i) * time.Hour)
			cells[i] = heatmapCell{Label: t.Format("15") + ":00", Count: c, Pct: quantize(c)}
		}
		rows[r] = heatmapRow{Sensor: row.sensor, Cells: cells}
	}
	return rows
}
