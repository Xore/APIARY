package main

// fetch.go -- reads recent events from honeypot-v2-*, same PIT +
// search_after pattern and the same canonical_*-field scope as
// correlator-worker/fetch.go (both descend from the former Go dashboard's
// events_es.go pagination, removed with that dashboard in #1659; the
// idiom's live home now is backend-service/src/es.rs's paged PIT search --
// not shared as a package here either, see that file's own doc comment
// for the full reasoning, including why the window is much shorter than
// the old 7-day dashboard default). identity.go turns these
// into per-IP signal sets; unlike correlator-worker, this worker's own
// output (attackers-v1) is durable and accumulates across cycles even
// though each cycle's own event fetch only covers a short recent window --
// an attacker's identity, once established, persists in attackers-v1
// regardless of whether that IP reappears in every subsequent window.

import (
	"encoding/json"
	"log"
	"strings"
	"time"
)

const (
	honeypotIndexPattern = "honeypot-v2-*"
	esPageSize           = 10000
	esMaxPages           = 50
)

// tunnelPeerIP matches every other worker's own constant of the same name
// -- an event still carrying it means the via_port join hasn't resolved
// this connection yet (#1198/#1206); never a real attacker.
const tunnelPeerIP = "10.8.0.1"

type corrEvent struct {
	When        time.Time
	SrcIP       string
	Sensor      string
	User, Pass  string
	Shasum      string
	Fingerprint string
	// Techniques (#1260) is ip-enrichment-worker's canonical_attck_techniques
	// (#1261) -- a per-event ATT&CK technique-ID array promoted from the
	// same canonical_user/pass/shasum/fingerprint/command fields this
	// worker already reads, ported from the former Go dashboard's
	// kill_chain.go techniquesForEvent (now backend-service/src/kill_chain.rs).
	// identity.go folds these into each entity's own
	// durable Techniques field so an entity's technique coverage persists
	// once observed instead of only ever existing as a per-request,
	// per-dashboard-instance computation (see identity.go's own comment
	// on entityTechniqueSet for the rest of this).
	Techniques []string
}

func fetchRecentEvents(es *esClient, since time.Time) ([]corrEvent, bool) {
	pitID, ok := es.openPointInTime(honeypotIndexPattern, "2m")
	if !ok {
		return nil, false
	}
	defer es.closePointInTime(pitID)

	var out []corrEvent
	var searchAfter []any
	for page := 0; page < esMaxPages; page++ {
		body := map[string]any{
			"size": esPageSize,
			"pit":  map[string]any{"id": pitID, "keep_alive": "2m"},
			"sort": []map[string]any{
				{"@timestamp": "asc"},
				{"_shard_doc": "asc"},
			},
			"query": map[string]any{
				"bool": map[string]any{
					"filter": []map[string]any{
						{"range": map[string]any{"@timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
						{"exists": map[string]any{"field": "source.ip"}},
					},
				},
			},
			"_source": []string{
				"@timestamp", "source.ip", "event.sensor",
				"honeypot.canonical_user", "honeypot.canonical_pass", "honeypot.canonical_shasum",
				"honeypot.canonical_fingerprint", "honeypot.canonical_attck_techniques",
			},
		}
		if searchAfter != nil {
			body["search_after"] = searchAfter
		}
		reqBody, err := json.Marshal(body)
		if err != nil {
			break
		}
		b, err := es.searchBody("/_search", reqBody)
		if err != nil {
			return out, false
		}
		var v struct {
			Hits struct {
				Hits []struct {
					Sort   []any `json:"sort"`
					Source struct {
						Timestamp string `json:"@timestamp"`
						Source    struct {
							IP string `json:"ip"`
						} `json:"source"`
						Event struct {
							Sensor string `json:"sensor"`
						} `json:"event"`
						Honeypot struct {
							CanonicalUser            string   `json:"canonical_user"`
							CanonicalPass            string   `json:"canonical_pass"`
							CanonicalShasum          string   `json:"canonical_shasum"`
							CanonicalFingerprint     string   `json:"canonical_fingerprint"`
							CanonicalAttckTechniques []string `json:"canonical_attck_techniques"`
						} `json:"honeypot"`
					} `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		// An unmarshal error means this page's response is unparseable --
		// not "no more results". Treating the two the same silently
		// discards every hit already decoded on this page and abandons any
		// subsequent pages, while still returning (out, true): runCycle
		// then logs a normal-looking "cycle complete" with an artificially
		// small event count and no indication anything went wrong.
		if err := json.Unmarshal(b, &v); err != nil {
			log.Printf("attacker-identity-worker: fetchRecentEvents: unmarshal search response: %v", err)
			return out, false
		}
		if len(v.Hits.Hits) == 0 {
			break
		}
		for _, h := range v.Hits.Hits {
			when, _ := time.Parse(time.RFC3339, h.Source.Timestamp)
			ip := h.Source.Source.IP
			if ip == "" || ip == tunnelPeerIP {
				continue
			}
			out = append(out, corrEvent{
				When: when, SrcIP: ip, Sensor: h.Source.Event.Sensor,
				User: h.Source.Honeypot.CanonicalUser, Pass: h.Source.Honeypot.CanonicalPass,
				Shasum: h.Source.Honeypot.CanonicalShasum, Fingerprint: h.Source.Honeypot.CanonicalFingerprint,
				Techniques: h.Source.Honeypot.CanonicalAttckTechniques,
			})
		}
		if len(v.Hits.Hits) < esPageSize {
			break
		}
		searchAfter = v.Hits.Hits[len(v.Hits.Hits)-1].Sort
		if page == esMaxPages-1 {
			log.Printf("attacker-identity-worker: hit the %d-page cap (%d events) before exhausting the window since %s -- see correlator-worker/fetch.go's own comment for the same scale trade-off",
				esMaxPages, esMaxPages*esPageSize, since.UTC().Format(time.RFC3339))
		}
	}
	return out, true
}

// validCredentialPair -- ported verbatim from dashboard/links.go, same
// copy correlator-worker's own correlate.go already carries. Gates which
// canonical_user/canonical_pass pairs count as a real credential signal
// for entity merging, matching TopCreds' exact semantics elsewhere in
// this codebase.
func validCredentialPair(user, pass string) bool {
	if user == "" && pass == "" || len(user) > 128 || len(pass) > 512 {
		return false
	}
	for _, value := range []string{user, pass} {
		lower := strings.ToLower(value)
		if strings.ContainsAny(value, "\x00\r\n") || strings.Contains(lower, "\\x00") || strings.Contains(lower, "\\u0000") {
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
