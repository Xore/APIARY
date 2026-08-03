package main

import (
	"encoding/json"
	"fmt"
	"net/url"
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
// dicompot (#413) and dns-honeypot (#415) are ES-only from the day each was
// added, per #238's broader data-flow requirement that every new sensor
// added under that issue reads through Elasticsearch, never a local log
// directory -- neither needed a migration the way multipot did, since
// there was no pre-existing file-based dashboard code path to move away
// from for either.
var esOnlySensors = []string{"multipot", "dicompot", "dns-honeypot"}

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
func (s *store) loadSensorEventsES(es *esClient, dirSensor string) ([]cachedEvent, bool) {
	if es == nil {
		return nil, false
	}
	q := url.QueryEscape(fmt.Sprintf(`event.sensor:%q`, dirSensor))
	path := fmt.Sprintf("/honeypot-v2-*/_search?size=10000&sort=%%40timestamp%%3Adesc&q=%s", q)
	b, err := es.request(path)
	if err != nil {
		return nil, false
	}
	var v struct {
		Hits struct {
			Hits []struct {
				Source struct {
					Honeypot map[string]any `json:"honeypot"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil, false
	}
	events := make([]cachedEvent, 0, len(v.Hits.Hits))
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
	return events, true
}
