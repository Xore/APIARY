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

	var events []cachedEvent
	var searchAfter []any
	for page := 0; page < esEventsMaxPages; page++ {
		// #583: a plain size=10000 GET query silently dropped every event
		// past the first 10,000 in one rebuild cycle during a burst --
		// Elasticsearch's own max_result_window ceiling for a single
		// request, not something raising `size` further can fix. Paginates
		// via search_after instead, which needs a real query body (not the
		// simple ?q= query-string form) and a fully stable sort:
		// @timestamp alone can collide at this volume, so _id is added as
		// a tie-breaker -- without one, search_after can silently skip or
		// duplicate hits that share a timestamp across page boundaries.
		body := map[string]any{
			"size": esEventsPageSize,
			"sort": []map[string]any{
				{"@timestamp": "desc"},
				{"_id": "desc"},
			},
			"query": map[string]any{
				"term": map[string]any{"event.sensor": dirSensor},
			},
		}
		if searchAfter != nil {
			body["search_after"] = searchAfter
		}
		reqBody, err := json.Marshal(body)
		if err != nil {
			return nil, false
		}
		b, err := es.searchBody("/honeypot-v2-*/_search", reqBody)
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
