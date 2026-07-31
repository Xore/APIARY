package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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
		points                                       = map[string]*mapPoint{}
		payloads                                     = map[string]*payloadRow{}
		lastSeen                                     = map[string]time.Time{}
		hourly                                       [24]int
		evs                                          []storedEvent
		seen                                         = map[string]bool{}
	)
	now := time.Now()

	// Recover real attacker IPs for cowrie (which only sees the tunnel peer)
	// by joining on the tunnel ephemeral port recorded in the portbridge log.
	viaMap := s.buildViaMap()

	for _, fn := range logFiles(s.dir) {
		rel, _ := filepath.Rel(s.dir, fn)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		dirSensor := "logs"
		if len(parts) > 1 {
			dirSensor = parts[0]
		}
		for _, line := range strings.Split(string(readTail(fn)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var e map[string]any
			if json.Unmarshal([]byte(line), &e) != nil {
				continue
			}
			ev := classify(e, dirSensor)
			if ev.skip {
				continue
			}
			ev.proto = normalizeProtocol(ev.proto)
			// Commands containing inline shell/PowerShell/VBS/etc. programs are
			// retained as inert, hash-addressed artifacts. They are never run.
			s.captureScriptPayload(&ev)
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
			lostSource := false
			if ev.ip == tunnelPeerIP {
				if real := viaLookup(viaMap, eventSrcPort(e), ev.port); real != "" {
					ev.ip = real
				} else {
					ev.ip = ""
					lostSource = true
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
				p := points[ev.ip]
				if p == nil {
					p = &mapPoint{IP: ev.ip, Country: geo.Country, City: geo.City, Lat: geo.Lat, Lon: geo.Lon, ASN: geo.ASN, Org: geo.Org, Provider: geo.Provider, Intel: geo.Intel}
					points[ev.ip] = p
				}
				p.Count++
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
					hourly[23-int(age.Hours())]++
					last24++
				} else if age >= 24*time.Hour && age < 48*time.Hour {
					previous24++
				}
			}
			evs = append(evs, storedEvent{
				when:          ev.when,
				Time:          ev.whenStr,
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
				Kibana:        investigationURL(os.Getenv("KIBANA_PUBLIC_URL"), "kibana", ev.ip, ev.when),
				EveBox:        investigationURL(os.Getenv("EVEBOX_PUBLIC_URL"), "evebox", ev.ip, ev.when),
				Arkime:        investigationURL(os.Getenv("ARKIME_PUBLIC_URL"), "arkime", ev.ip, ev.when),
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

	// 24h chart: scale every bar against the busiest hour.
	maxHour := 1
	for _, c := range hourly {
		if c > maxHour {
			maxHour = c
		}
	}
	timeline := make([]bucket, len(hourly))
	for i, c := range hourly {
		t := now.Add(-time.Duration(len(hourly)-1-i) * time.Hour)
		timeline[i] = bucket{Label: t.Format("15"), Count: c, Pct: c * 100 / maxHour}
	}

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
	for _, p := range points {
		p.X = (p.Lon + 180) / 360 * 1000
		p.Y = (90 - p.Lat) / 180 * 450
		p.R = min(14, 3+int(math.Sqrt(float64(p.Count))))
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
		Timeline:       timeline,
		Recent:         recents,
		Runtime:        currentRuntime(),
		YARA:           yaraSummary(s.yaraFile),
	}
	if s.es != nil {
		snap.ES = s.es.get()
	}
	s.mu.Lock()
	s.snap = snap
	s.events = evs
	s.mu.Unlock()
	if s.intelligence != nil && s.intelligence.due() {
		s.intelligence.save(intelligenceSnapshot{Version: 1, Generated: now, Campaigns: campaigns, Clusters: s.clustersData().Rows})
	}
	s.broadcast()
}
