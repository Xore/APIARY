package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// mapPointRadius is the fixed SVG-fallback marker radius (viewBox units).
// #228: not scaled by event count -- see the comment where it's assigned.
const mapPointRadius = 6

func (s *store) rebuild() {
	var (
		logins, downloads int
		creds             = map[string]int{}
		commands          = map[string]int{}
		alerts            = map[string]int{}
		alertCats         = map[string]int{}
		providers         = map[string]int{}
		clients           = map[string]int{}
		fingerprints      = map[string]int{}
		payloads          = map[string]*payloadRow{}
		evs               []storedEvent
		seen              = map[string]bool{}
	)
	now := time.Now()
	// Captured before s.snap is overwritten at the end of this function --
	// the fallback source for every ES-native field below when this cycle's
	// query fails (see the #39 comment further down).
	prevSnap := s.get()

	// #39 (design decided under #37): sensor counts, protocol/port/country/
	// ASN/IP/path leaderboards, the activity heatmap, and the attack map all
	// come from a live Elasticsearch aggregation query now -- see
	// es_aggregate.go's own doc comment for exactly what moved here and why
	// the rest (creds/commands/alerts/providers/clients/fingerprints/
	// payloads/campaigns/clusters, all still below) didn't. esOverviewOK
	// false (an ES query failure, or Elasticsearch not configured at all)
	// falls back to whatever the previous successful rebuild produced for
	// these fields rather than blanking the overview page for one bad
	// cycle -- graceful degradation by omission, the same philosophy
	// esOnlySensors already uses in events_es.go.
	esOverviewResult, esOverviewOK := s.fetchESOverview(now)

	// Recover real attacker IPs for cowrie (which only sees the tunnel peer)
	// by joining on the tunnel ephemeral port recorded in the portbridge log.
	viaMap, p0fOS := s.buildViaMap()

	processEntry := func(entry cachedEvent) {
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
		if ev.ip == tunnelPeerIP {
			if real := viaLookup(viaMap, entry.srcPort, ev.port); real != "" {
				ev.ip = real
			} else {
				ev.ip = ""
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
				return
			}
			seen[key] = true
		}
		// The aggregate Unattributed count itself is now ES-native
		// (es_aggregate.go) -- ev.ip is still cleared above (not left as
		// the tunnel peer) so each individual event's own /events row shows
		// a correctly blank SrcIP, and the join above still runs fresh
		// every cycle so a line read before its matching portbridge record
		// landed gets a chance to join once that record shows up (see
		// log_cache.go's own header comment for why that retry property
		// matters).
		geo := geoInfo{Country: ev.country}
		if s.geo != nil && ev.ip != "" {
			geo = s.geo.lookup(ev.ip)
			if ev.country != "" {
				geo.Country = ev.country
			}
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
		provider := firstNonEmpty(geo.Intel, geo.Provider)
		if provider != "" {
			providers[provider]++
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
			TTYReplay:     ev.ttyReplay,
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

	// #34/#403/#1103: every sensor is ES-only now, but rebuild() still
	// discovers WHICH sensors to query by walking the local log directory
	// tree -- each sensor's own container still writes its raw log purely
	// for Filebeat to tail (see aggregate.go's own module doc / #1103's own
	// commit for why this discovery mechanism was kept as-is rather than
	// redesigned to be disk-independent), even though the dashboard itself
	// never reads that content anymore. sensorOrder is deduplicated names
	// only -- unlike before #1103, nothing here needs the actual file list
	// per sensor, since no sensor's local file content is ever read.
	var sensorOrder []string
	seenSensor := map[string]bool{}
	for _, fn := range logFiles(s.dir) {
		rel, _ := filepath.Rel(s.dir, fn)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		dirSensor := "logs"
		if len(parts) > 1 {
			dirSensor = parts[0]
		}
		// "enriched" is ip-enrichment-worker's own output directory (#38) --
		// Filebeat tails it so Elasticsearch gets an already-correct src_ip
		// for cowrie/dionaea/every conpot persona/dns-honeypot/
		// cisco-asa-honeypot, but it's the same underlying events those
		// sensors' own directories already carry, not a sixth sensor in its
		// own right. Reading it here too would just double the I/O this
		// loop already does for those five sensors' real directories.
		if dirSensor == "enriched" {
			continue
		}
		if slices.Contains(esOnlySensors, dirSensor) {
			continue
		}
		// portbridge is transport metadata, never a displayable sensor
		// (classify.go's portbridge branch always sets ev.skip) -- it needs
		// no event-listing read of any kind, ES or local. Its real job, the
		// via-map join, is buildViaMap's own direct ES query above, not
		// this per-sensor loop.
		if dirSensor == "portbridge" {
			continue
		}
		if seenSensor[dirSensor] {
			continue
		}
		seenSensor[dirSensor] = true
		sensorOrder = append(sensorOrder, dirSensor)
	}
	for _, dirSensor := range sensorOrder {
		if s.es == nil {
			continue
		}
		// suricata ships to its own index family (suricata-*, "logset"
		// values other than "sensors"; see analysis/filebeat.yml/
		// elasticsearch-setup.sh), never honeypot-v2-* under
		// event.sensor:"suricata" the way every other sensor here does --
		// loadSensorEventsES only ever queries honeypot-v2-*, so it needs
		// its own adapter (#1103 Category 2), not the generic one.
		if dirSensor == "suricata" {
			if cached, ok := s.loadSuricataEventsES(s.es); ok {
				for _, entry := range cached {
					processEntry(entry)
				}
			}
			continue
		}
		// ES-only (#1103): every sensor Filebeat ships to honeypot-v2-*
		// under event.sensor:<dirSensor> is read from there exclusively --
		// an ES query failure means "no data this cycle," the same as
		// esOnlySensors below, not a reason to fall back to this dashboard
		// instance's own local log mount.
		if cached, ok := s.loadSensorEventsES(s.es, dirSensor); ok {
			for _, entry := range cached {
				processEntry(entry)
			}
		}
	}

	for _, sensor := range esOnlySensors {
		cached, ok := s.loadSensorEventsES(s.es, sensor)
		if !ok {
			continue
		}
		for _, entry := range cached {
			processEntry(entry)
		}
	}

	// Newest first; /events pages retain the complete tail. The dashboard feed
	// caps each sensor so a noisy source (normally cowrie) cannot hide every
	// lower-volume sensor such as conpot or dionaea.
	sort.Slice(evs, func(i, j int) bool { return evs[i].when.After(evs[j].when) })
	recents := balancedRecent(evs, recentCap, recentPerSensorCap)
	campaigns := correlateCampaigns(evs, now.Add(-7*24*time.Hour))

	// Command rows: split the sensor back out of the map key for display + link.
	cmdRows := topN(commands, 15)
	for i, r := range cmdRows {
		sensor, cmd, _ := strings.Cut(r.Key, "\x00")
		cmdRows[i].Key = "[" + sensor + "] " + compactText(cmd, 68)
		cmdRows[i].Title = cmd
		cmdRows[i].Link = eventsURL(url.Values{"sensor": {sensor}, "cmd": {cmd}})
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

	// #39: everything below this point that used to be accumulated above
	// (sensor counts/freshness, protocol/port/country/ASN/IP/path
	// leaderboards, the activity heatmap, the attack map, and the
	// Total/UniqueIPs/Unattributed/Last24h/Previous24h/Change24h/
	// ActivityState scalars) now comes from one live Elasticsearch
	// aggregation query -- see es_aggregate.go. On a query failure this
	// cycle keeps showing prevSnap's numbers rather than blanking the
	// overview page for one bad tick.
	snap := prevSnap
	snap.Sensors, snap.Protocols, snap.TopIPs, snap.TopPorts, snap.TopPaths,
		snap.Countries, snap.ASNs, snap.MapPoints, snap.SensorHeatmap = nil, nil, nil, nil, nil, nil, nil, nil, nil
	if esOverviewOK {
		for _, name := range s.expected {
			if _, ok := esOverviewResult.SensorCounts[name]; !ok {
				esOverviewResult.SensorCounts[name] = 0
			}
		}
		// #539: every configured (s.expected, zero-filled above) and every
		// ES-observed sensor, not a top-30 cut -- a low-volume or newly added
		// sensor was previously only reachable through the heatmap's sensor
		// filter (backed by /api/filter-values, which ranks the full set
		// before applying its own cap), never visible on this card at all.
		// The card itself scrolls (theme.css's .sensor-card) instead of
		// growing the page, so there's no longer a size reason to cap it.
		for _, sensor := range topN(esOverviewResult.SensorCounts, len(esOverviewResult.SensorCounts)) {
			snap.Sensors = append(snap.Sensors, sensorRow{
				Name: sensor.Key, Count: sensor.Count,
				Ago:   ago(esOverviewResult.SensorLastSeen[sensor.Key]),
				State: feedState(esOverviewResult.SensorLastSeen[sensor.Key], now),
				// classify() (below, the "tanner_report.json + http-honeypot"
				// block) deliberately renames every http-honeypot event's own
				// .sensor to "http" -- EXPECTED_SENSORS agrees ("http", not
				// "http-honeypot"). event.sensor in Elasticsearch carries the
				// raw, un-renamed value from the ingest pipeline though, so a
				// card built straight from ES buckets links to the name
				// classify() never actually produces -- confirmed live
				// (2026-08-09): filtering by the literal ES bucket key
				// "http-honeypot" always found zero events, filtering by
				// "http" found the real ones. Match the link to what
				// classify() actually names these events, not the raw
				// ingest-side field.
				Link: eventsURL(url.Values{"sensor": {eventsSensorName(sensor.Key)}}),
			})
		}
		snap.Protocols = linkRows(esOverviewResult.Protocols, "proto")
		snap.TopIPs = linkRows(esOverviewResult.TopIPs, "ip")
		snap.TopPorts = linkRows(esOverviewResult.Ports, "port")
		snap.TopPaths = linkRows(esOverviewResult.Paths, "path")
		snap.Countries = linkRows(esOverviewResult.Countries, "country")
		snap.ASNs = asnRows(esOverviewResult.ASNs)
		snap.SensorHeatmap = esOverviewResult.SensorHeatmap
		for _, p := range esOverviewResult.MapPoints {
			p.X = (p.Lon + 180) / 360 * 1000
			p.Y = (90 - p.Lat) / 180 * 450
			// #228: fixed, not scaled by Count -- same reasoning as the
			// Leaflet map's circleMarker switch in hp-app.js. A
			// count-scaled radius on a high-traffic country-level point
			// (no city resolved) could grow large enough to visually cover
			// a real city's own marker nearby.
			p.R = mapPointRadius
			p.Link = mapPointEventsURL(p.City, p.Country)
			snap.MapPoints = append(snap.MapPoints, p)
		}
		sort.Slice(snap.MapPoints, func(i, j int) bool {
			if snap.MapPoints[i].Count != snap.MapPoints[j].Count {
				return snap.MapPoints[i].Count > snap.MapPoints[j].Count
			}
			// #40: City+Country ties are common (many single-event markers),
			// and a Count-only comparator gives sort.Slice no way to settle
			// them consistently across independently-running instances.
			if snap.MapPoints[i].Country != snap.MapPoints[j].Country {
				return snap.MapPoints[i].Country < snap.MapPoints[j].Country
			}
			return snap.MapPoints[i].City < snap.MapPoints[j].City
		})
		if len(snap.MapPoints) > 500 {
			snap.MapPoints = snap.MapPoints[:500]
		}

		snap.Total, snap.UniqueIPs, snap.Unattributed = esOverviewResult.Total, esOverviewResult.UniqueIPs, esOverviewResult.Unattributed
		snap.Last24h, snap.Previous24h = esOverviewResult.Last24h, esOverviewResult.Previous24h
		snap.Change24h, snap.ActivityState = "no prior baseline", "baseline unavailable"
		// #469: the previous-24h window (now-48h..now-24h) only means
		// something once the store/sensor has actually been collecting
		// since before it started -- otherwise a young store's "previous"
		// window is empty or partially empty for reasons that have nothing
		// to do with traffic, and any real events in the last 24h read as
		// an enormous, misleading spike. Require two full 24h windows of
		// real history (data reaching back past esOverviewWindow) before
		// the percentage badge is trusted at all.
		haveFullBaseline := !esOverviewResult.EarliestSeen.IsZero() &&
			esOverviewResult.EarliestSeen.Before(now.Add(-esOverviewWindowDuration))
		if !haveFullBaseline {
			snap.Change24h = "insufficient baseline"
			snap.ActivityState = "insufficient baseline"
			if !esOverviewResult.EarliestSeen.IsZero() {
				snap.Change24h = fmt.Sprintf("insufficient baseline (collecting since %s)", ago(esOverviewResult.EarliestSeen))
			}
		} else if esOverviewResult.Previous24h > 0 {
			pct := (esOverviewResult.Last24h - esOverviewResult.Previous24h) * 100 / esOverviewResult.Previous24h
			snap.Change24h = fmt.Sprintf("%+d%% vs previous 24h", pct)
			snap.ActivityState = "normal"
			if pct >= 100 {
				snap.ActivityState = "spike"
			} else if pct >= 35 {
				snap.ActivityState = "elevated"
			} else if pct <= -50 {
				snap.ActivityState = "low"
			}
		}
	}

	snap.Generated = now
	snap.Logins = logins
	snap.Downloads = downloads
	// #470: read from the same disk-scan cache /payloads itself uses
	// (payloads_data.go's scanPayloads/refreshPayloadCacheAsync), not
	// Downloads above -- Downloads counts per-event observations in the log
	// tail window, a much smaller and differently-scoped number than the
	// distinct binaries /payloads reports.
	s.refreshPayloadCacheAsync()
	s.payloadMu.Lock()
	snap.UniquePayloads = s.payloadCache.UniqueTotal
	s.payloadMu.Unlock()
	snap.GeoOn = s.geo != nil
	snap.MapTileURL = getenv("MAP_TILE_URL", "https://tile.openstreetmap.org/{z}/{x}/{y}.png")
	snap.MapAttribution = getenv("MAP_ATTRIBUTION", "© OpenStreetMap contributors")
	snap.TopCreds = credentialRows(topN(creds, 15))
	snap.TopCommands = cmdRows
	snap.Alerts = linkRows(topN(alerts, 15), "sig")
	snap.AlertCats = linkRows(topN(alertCats, 10), "cat")
	snap.Providers = linkRows(topN(providers, 10), "provider")
	snap.Clients = linkRows(topN(clients, 10), "client")
	snap.Fingerprints = fingerprintRows(fingerprints, 12)
	snap.Payloads = payloadRows
	snap.Campaigns = campaigns
	snap.Recent = recents
	snap.Runtime = currentRuntime()
	snap.YARA = yaraSummary(s.yaraFile)
	if s.es != nil {
		snap.ES = s.es.get()
	}
	s.mu.Lock()
	s.snap = snap
	s.events = evs
	s.mu.Unlock()
	if s.intelligence != nil && s.intelligence.due() {
		s.intelligence.save(intelligenceSnapshot{Version: 1, Generated: now, Campaigns: campaigns, Clusters: s.clustersData(filter{}).Rows})
	}
	s.broadcast()
}
