package main

import (
	"encoding/json"
)

// esOnlySensors lists dirSensor values (the same names logFiles()'s
// directory-derived dirSensor already produces) whose events are sourced
// from Elasticsearch instead of a local log file (#403, prerequisite for
// #238). rebuild() skips these directories in its file walk entirely and
// calls loadSensorEventsES for each instead, merging the result into the
// exact same per-entry pipeline (portbridge join, geo lookup, dedup,
// aggregation) file-sourced sensors go through -- an ES-sourced sensor is
// indistinguishable from a file-sourced one anywhere downstream of
// rebuild()'s two source loops.
//
// multipot moved here as part of adding RDP/ADB/POP3/IMAP/SOCKS5/HL7 (#238):
// rather than splitting multipot's already-existing protocols (file-based)
// from its new ones (ES-based) within the same log file/sensor identity --
// which would need a second log file and a second Filebeat input just to
// keep them apart -- the whole sensor moved to ES-sourced at once. Every
// other sensor is unaffected and stays file-based.
//
// dicompot (#413), dns-honeypot (#415), citrix-honeypot,
// cisco-asa-honeypot (#414) and rdp-honeypot (#412) are ES-only from the
// day each was added, per #238's broader data-flow requirement that every
// new sensor added under that issue reads through Elasticsearch, never a
// local log directory -- none needed a migration the way multipot did,
// since there was no pre-existing file-based dashboard code path to move
// away from for any of them.
var esOnlySensors = []string{"multipot", "dicompot", "dns-honeypot", "citrix-honeypot", "cisco-asa-honeypot", "rdp-honeypot"}

// loadSensorEventsES fetches dirSensor's events from the honeypot-v2-*
// Filebeat index (see analysis/filebeat.yml, analysis/elasticsearch-setup.sh)
// instead of a local file. es.request already timing out/erroring is the
// only failure mode -- there is deliberately no local-file fallback here,
// unlike loadGhidraResults/loadSandboxResults/loadGitHubAnalysisResults: an
// ES-only sensor has no log file for the dashboard to fall back to reading
// by design (#238's data-flow requirement), so a query failure just means
// this sensor contributes nothing to this rebuild cycle, exactly as if a
// file-based sensor's log directory briefly vanished.
//
// event.sensor (not the root "sensor" field -- see analysis/
// elasticsearch-setup.sh's geoip-honeypot ingest pipeline, which only ever
// populates the nested event.sensor from each line's own honeypot.sensor
// value) is set to "multipot" for every multipot protocol uniformly
// (multipot/main.go's e.Sensor = "multipot"), so this one query already
// covers every existing and future multipot protocol -- no per-protocol
// wiring needed here when #238's new handlers are added.
//
// The extracted honeypot.* field is the exact same raw JSON object
// classifyLines (log_cache.go) parses out of a log line -- Filebeat's ndjson
// parser nests it there unmodified (target: "honeypot" in filebeat.yml) --
// so it feeds classify() identically regardless of source.
// esEventsPageSize is Elasticsearch's own default index.max_result_window
// ceiling for a single _search request -- not an arbitrary app-level choice,
// the actual limit a plain query can return without search_after/scroll/PIT.
const esEventsPageSize = 10000

// esEventsMaxPages bounds loadSensorEventsES's search_after loop (#583): a
// hard cap on how many pages one rebuild cycle will fetch per sensor, so a
// pathological burst can't make a single rebuild run unboundedly long. 10
// pages * esEventsPageSize is 100,000 events for one sensor in one rebuild
// cycle -- far beyond any real burst this stack has seen live; if that cap
// is ever actually hit, the remaining events are picked up on the *next*
// rebuild cycle exactly as the pre-#583 code silently did for everything
// past 10,000, just an order of magnitude later.
const esEventsMaxPages = 10

func (s *store) loadSensorEventsES(es *esClient, dirSensor string) ([]cachedEvent, bool) {
	if es == nil {
		return nil, false
	}

	// #1097: _id can no longer be used as a search_after tie-breaker --
	// confirmed live against this deployment's Elasticsearch version
	// (2026-08-09): "Fielddata access on the _id field is disallowed",
	// and unlike the older deprecated-but-functional id_field_data.enabled
	// escape hatch, this version has removed that setting outright ("unknown
	// setting... check the breaking changes documentation for removed
	// settings"). This was silently failing loadSensorEventsES for every
	// sensor on every rebuild cycle: the esOnlySensors six (no local-file
	// fallback, so they went completely blank) and every other sensor too
	// (silently falling back to a local-file read that happened to mask the
	// failure for most of them). _shard_doc is Elasticsearch's own
	// documented modern replacement, but it requires a point-in-time
	// context to use at all ("[_shard_doc] sort field cannot be used
	// without [point in time]") -- open one for this call, scoped to the
	// same honeypot-v2-* pattern the plain index-pattern search this
	// replaces used, and always close it before returning.
	pitID, ok := es.openPointInTime("honeypot-v2-*", "1m")
	if !ok {
		return nil, false
	}
	defer es.closePointInTime(pitID)

	var events []cachedEvent
	var searchAfter []any
	for page := 0; page < esEventsMaxPages; page++ {
		// #583: a plain size=10000 GET query silently dropped every event
		// past the first 10,000 in one rebuild cycle during a burst --
		// Elasticsearch's own max_result_window ceiling for a single
		// request, not something raising `size` further can fix. Paginates
		// via search_after instead, which needs a real query body (not the
		// simple ?q= query-string form) and a fully stable sort -- see the
		// PIT/_shard_doc comment above for why the tie-breaker is what it is.
		//
		// #880: this query had no time bound at all, so a sensor with more
		// than esEventsPageSize sightings within the 30-day honeypot-30d ILM
		// retention window re-fetched its *entire* retained history on every
		// single 15s rebuild tick, forever, with cost scaling with attacker
		// traffic volume. esOverviewWindow (es_aggregate.go) is already the
		// documented, deliberate bound for what "Total" honestly means for
		// an ES-backed sensor -- reusing it here instead of inventing a
		// second window keeps that meaning consistent across the dashboard.
		body := map[string]any{
			"size": esEventsPageSize,
			"pit":  map[string]any{"id": pitID, "keep_alive": "1m"},
			"sort": []map[string]any{
				{"@timestamp": "desc"},
				{"_shard_doc": "desc"},
			},
			"query": map[string]any{
				"bool": map[string]any{
					"filter": []map[string]any{
						{"term": map[string]any{"event.sensor": dirSensor}},
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
			return nil, false
		}
		// A PIT search takes no index in the path -- the PIT itself already
		// pins which index/indices it was opened against.
		b, err := es.searchBody("/_search", reqBody)
		if err != nil {
			if page == 0 {
				return nil, false
			}
			break // later page failed -- keep what earlier pages already returned
		}
		var v struct {
			Hits struct {
				Hits []struct {
					Sort   []any `json:"sort"`
					Source struct {
						Honeypot map[string]any `json:"honeypot"`
					} `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if json.Unmarshal(b, &v) != nil {
			if page == 0 {
				return nil, false
			}
			break
		}
		if len(v.Hits.Hits) == 0 {
			break
		}
		for _, h := range v.Hits.Hits {
			e := h.Source.Honeypot
			if e == nil {
				continue
			}
			ev := classify(e, dirSensor)
			if ev.skip {
				continue
			}
			ev.proto = normalizeProtocol(ev.proto)
			s.captureScriptPayload(&ev)
			events = append(events, cachedEvent{ev: ev, srcPort: eventSrcPort(e)})
		}
		if len(v.Hits.Hits) < esEventsPageSize {
			break // last page
		}
		searchAfter = v.Hits.Hits[len(v.Hits.Hits)-1].Sort
	}
	return events, true
}
